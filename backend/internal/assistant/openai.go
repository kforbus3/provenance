package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kforbus3/provenance/backend/internal/ssrf"
)

// openaiClient speaks the OpenAI chat-completions API: /v1/models and
// /v1/chat/completions. It is what llama.cpp, vLLM and LocalAI serve.
//
// It adapts to this package's Ollama-shaped types rather than the reverse, so the
// tool loop, fast paths and direct answers stay written against one representation.
// Three differences have to be translated, and each one is a silent failure if it
// is not:
//
//  1. Tool-call arguments are a JSON *string* here and a JSON *object* in Ollama.
//  2. Every tool call carries an id, and the tool result MUST quote it back in
//     tool_call_id. Ollama has no such requirement and ignores the field.
//  3. Sampling options are top-level request fields, not a nested "options" map —
//     and num_ctx has no equivalent at all, because the context window is fixed
//     when the server starts. See modelContextLength.
type openaiClient struct {
	url    string
	apiKey string
	http   *http.Client
	// validate guards against SSRF before every request. A field rather than a
	// direct call so tests can point the client at an httptest server on loopback,
	// which the real validator refuses — correctly, in production.
	validate func(string) error
}

func newOpenAI(url, apiKey string) *openaiClient {
	u := strings.TrimRight(strings.TrimSpace(url), "/")
	// Accept a URL with or without the /v1 suffix. Operators copy these from
	// wherever the server documented itself, and both spellings are common enough
	// that rejecting one produces a 404 that reads like the server being down.
	u = strings.TrimSuffix(u, "/v1")
	return &openaiClient{
		url:      u,
		apiKey:   strings.TrimSpace(apiKey),
		http:     ssrf.SafeClient(5 * time.Minute),
		validate: ssrf.ValidateURL,
	}
}

func (c *openaiClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	if c.validate != nil {
		if err := c.validate(c.url); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Sent only when configured. A local llama.cpp needs no key; a hosted endpoint
	// rejects the request without one.
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	return c.http.Do(req)
}

// modelsResponse is the subset of /v1/models this needs.
//
// `meta` is not part of the OpenAI specification — llama.cpp adds it, and it
// carries the two numbers that matter: n_ctx, the window the server will actually
// give this model, and n_ctx_train, what the model was trained for. A server that
// does not send them leaves the values at zero, which callers already treat as
// "unknown" rather than "zero-length".
type modelsResponse struct {
	Data []struct {
		ID   string `json:"id"`
		Meta struct {
			NCtx      int `json:"n_ctx"`
			NCtxTrain int `json:"n_ctx_train"`
		} `json:"meta"`
	} `json:"data"`
}

func (c *openaiClient) models(ctx context.Context) (modelsResponse, error) {
	var out modelsResponse
	resp, err := c.do(ctx, http.MethodGet, "/v1/models", nil)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("models: HTTP %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

func (c *openaiClient) listModels(ctx context.Context) ([]string, error) {
	body, err := c.models(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(body.Data))
	for _, m := range body.Data {
		names = append(names, m.ID)
	}
	return names, nil
}

// modelContextLength returns the window the server will give this model.
//
// Unlike Ollama, this is NOT the model's trained length: an OpenAI-compatible
// server fixes the window when it starts (llama.cpp's --ctx-size), and no request
// can ask for more. So the number that matters to the caller is the served one,
// and a model the server has not loaded yet reports nothing at all — hence 0, the
// existing "unknown" value.
func (c *openaiClient) modelContextLength(ctx context.Context, model string) int {
	body, err := c.models(ctx)
	if err != nil {
		return 0
	}
	for _, m := range body.Data {
		if m.ID == model {
			return m.Meta.NCtx
		}
	}
	return 0
}

// --- wire types -------------------------------------------------------------

type openaiToolCall struct {
	ID       string `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	Function struct {
		Name string `json:"name"`
		// A JSON-encoded STRING here, unlike Ollama's object.
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type openaiMessage struct {
	Role       string           `json:"role"`
	Content    string           `json:"content"`
	ToolCalls  []openaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
	// Reasoning models put their chain of thought here and leave Content empty.
	// Read only so the caller can be told what happened; never fed back.
	ReasoningContent string `json:"reasoning_content,omitempty"`
}

type openaiRequest struct {
	Model       string          `json:"model"`
	Messages    []openaiMessage `json:"messages"`
	Tools       []toolDef       `json:"tools,omitempty"`
	Stream      bool            `json:"stream"`
	Temperature *float64        `json:"temperature,omitempty"`
	TopP        *float64        `json:"top_p,omitempty"`
	Seed        *int            `json:"seed,omitempty"`
}

type openaiResponse struct {
	Choices []struct {
		Message      openaiMessage `json:"message"`
		FinishReason string        `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// --- translation ------------------------------------------------------------

// toOpenAIMessages converts this package's messages to the wire form.
func toOpenAIMessages(in []chatMessage) []openaiMessage {
	out := make([]openaiMessage, 0, len(in))
	for _, m := range in {
		om := openaiMessage{Role: m.Role, Content: m.Content, ToolCallID: m.ToolCallID}
		for _, tc := range m.ToolCalls {
			var otc openaiToolCall
			otc.ID = tc.ID
			otc.Type = "function"
			otc.Function.Name = tc.Function.Name
			// Object -> string. An absent object becomes "{}" rather than "", because
			// a tool call whose arguments are the empty string is rejected by servers
			// that parse it strictly.
			args := strings.TrimSpace(string(tc.Function.Arguments))
			if args == "" {
				args = "{}"
			}
			otc.Function.Arguments = args
			om.ToolCalls = append(om.ToolCalls, otc)
		}
		out = append(out, om)
	}
	return out
}

// fromOpenAIMessage converts a wire message back, turning the arguments string
// back into the raw JSON object the tool runners unmarshal.
func fromOpenAIMessage(m openaiMessage) chatMessage {
	out := chatMessage{Role: m.Role, Content: m.Content}
	for _, tc := range m.ToolCalls {
		var c toolCall
		c.ID = tc.ID
		c.Function.Name = tc.Function.Name
		args := strings.TrimSpace(tc.Function.Arguments)
		if args == "" {
			args = "{}"
		}
		c.Function.Arguments = json.RawMessage(args)
		out.ToolCalls = append(out.ToolCalls, c)
	}
	return out
}

// sampling maps the Ollama options map onto the top-level request fields.
//
// num_ctx is deliberately dropped: the window is fixed when the server starts and
// cannot be requested per call. Silently sending it would be worse than dropping
// it — the caller would believe it had asked for a window it never got.
func (r *openaiRequest) sampling(opts map[string]any) {
	if v, ok := numeric(opts["temperature"]); ok {
		r.Temperature = &v
	}
	if v, ok := numeric(opts["top_p"]); ok {
		r.TopP = &v
	}
	if v, ok := numeric(opts["seed"]); ok {
		n := int(v)
		r.Seed = &n
	}
}

func numeric(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// chat performs one non-streaming chat completion.
func (c *openaiClient) chat(ctx context.Context, req chatRequest) (chatResponse, error) {
	oreq := openaiRequest{
		Model:    req.Model,
		Messages: toOpenAIMessages(req.Messages),
		Tools:    req.Tools,
		Stream:   false,
	}
	oreq.sampling(req.Options)

	b, err := json.Marshal(oreq)
	if err != nil {
		return chatResponse{}, err
	}
	resp, err := c.do(ctx, http.MethodPost, "/v1/chat/completions", bytes.NewReader(b))
	if err != nil {
		return chatResponse{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		// Surface the server's own message. "model 'x' not found" and "context
		// exceeded" are the two most common failures and both are actionable, while
		// a bare status code sends the operator looking at the network.
		var oe openaiResponse
		if json.Unmarshal(body, &oe) == nil && oe.Error != nil && oe.Error.Message != "" {
			return chatResponse{}, fmt.Errorf("chat: HTTP %d: %s", resp.StatusCode, oe.Error.Message)
		}
		return chatResponse{}, fmt.Errorf("chat: HTTP %d", resp.StatusCode)
	}
	var or openaiResponse
	if err := json.Unmarshal(body, &or); err != nil {
		return chatResponse{}, err
	}
	if len(or.Choices) == 0 {
		return chatResponse{}, fmt.Errorf("chat: server returned no choices")
	}
	choice := or.Choices[0]

	// A reasoning model spends its budget thinking and returns empty content with
	// finish_reason "length". That is indistinguishable from a broken model unless
	// it is named: the answer is blank, nothing errors, and the log says nothing.
	// Report it as the configuration problem it is.
	if strings.TrimSpace(choice.Message.Content) == "" &&
		len(choice.Message.ToolCalls) == 0 &&
		choice.FinishReason == "length" {
		hint := "the model hit its token limit before producing an answer"
		if strings.TrimSpace(choice.Message.ReasoningContent) != "" {
			hint = "the model spent its entire token budget on reasoning and returned no answer; " +
				"serve it with reasoning disabled, or use a non-reasoning model"
		}
		return chatResponse{}, fmt.Errorf("chat: %s", hint)
	}
	return chatResponse{Message: fromOpenAIMessage(choice.Message), Done: true}, nil
}
