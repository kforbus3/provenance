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

	"github.com/fleet-terminal/backend/internal/ssrf"
)

// ollamaClient is a minimal client for a local Ollama instance (/api/tags and
// /api/chat with tool-calling).
type ollamaClient struct {
	url  string
	http *http.Client
}

func newOllama(url string) *ollamaClient {
	return &ollamaClient{
		url:  strings.TrimRight(url, "/"),
		http: ssrf.SafeClient(5 * time.Minute),
	}
}

// listModels returns the names of models available on the Ollama instance.
func (c *ollamaClient) listModels(ctx context.Context) ([]string, error) {
	if err := ssrf.ValidateURL(c.url); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/api/tags", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama tags: HTTP %d", resp.StatusCode)
	}
	body, err := decodeTags(resp.Body)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(body.Models))
	for _, m := range body.Models {
		names = append(names, m.Name)
	}
	return names, nil
}

// tagsResponse is the subset of /api/tags we read. ContextLength is the model's
// trained window; it bounds how much of our prompt can actually be attended to.
type tagsResponse struct {
	Models []struct {
		Name    string `json:"name"`
		Details struct {
			ContextLength int `json:"context_length"`
		} `json:"details"`
	} `json:"models"`
}

func decodeTags(r io.Reader) (tagsResponse, error) {
	var body tagsResponse
	err := json.NewDecoder(r).Decode(&body)
	return body, err
}

// modelContextLength returns the trained context length Ollama reports for a model,
// or 0 when it is unknown (older Ollama builds omit it). Used to warn the operator
// when the configured window exceeds what the model was trained for.
func (c *ollamaClient) modelContextLength(ctx context.Context, model string) int {
	if err := ssrf.ValidateURL(c.url); err != nil {
		return 0
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/api/tags", nil)
	if err != nil {
		return 0
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0
	}
	body, err := decodeTags(resp.Body)
	if err != nil {
		return 0
	}
	for _, m := range body.Models {
		if m.Name == model {
			return m.Details.ContextLength
		}
	}
	return 0
}

type chatMessage struct {
	Role      string     `json:"role"` // system|user|assistant|tool
	Content   string     `json:"content"`
	ToolCalls []toolCall `json:"tool_calls,omitempty"`
}

type toolCall struct {
	Function struct {
		Name string `json:"name"`
		// Ollama returns arguments as a JSON object (not a string).
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type toolDef struct {
	Type     string       `json:"type"` // "function"
	Function toolFunction `json:"function"`
}

type toolFunction struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Parameters  any    `json:"parameters"` // JSON Schema
}

type chatRequest struct {
	Model    string         `json:"model"`
	Messages []chatMessage  `json:"messages"`
	Tools    []toolDef      `json:"tools,omitempty"`
	Stream   bool           `json:"stream"`
	Options  map[string]any `json:"options,omitempty"` // Ollama sampling options (see deterministicOptions)
}

const (
	// defaultNumCtx is the context window requested from Ollama when the operator
	// has not set one. It MUST be large enough to hold the system prompt + every
	// tool schema (~9k tokens on its own) plus the conversation and the tool
	// results, or Ollama silently drops the front of the prompt — see numCtx.
	defaultNumCtx = 32768
	// minNumCtx is the floor an operator-supplied value is raised to. Below this the
	// system prompt cannot survive alongside the tool schemas.
	minNumCtx = 16384
)

// numCtx resolves the context window to request. This is not a tuning knob — it is
// a correctness fix. Ollama defaults num_ctx to 4096 and, when the rendered prompt
// exceeds it, silently discards the OLDEST tokens: the system prompt goes first.
// The assistant's system prompt plus its tool schemas are ~9k tokens before a single
// row of data, so on the default window the model was answering with NO tool-choice
// guidance, no answer-scope rules, and no follow-up rules at all — the cause of
// "security scan" routing to CVEs, "active right now" routing to session history, and
// the chatty "I'd be happy to help… which hostname?" preamble the rules forbid.
func numCtx(configured int) int {
	if configured <= 0 {
		return defaultNumCtx
	}
	if configured < minNumCtx {
		return minNumCtx
	}
	return configured
}

// deterministicOptions makes the assistant behave like a precise sysadmin tool rather
// than a chatbot: a low temperature + low top_p keep tool selection and answers STABLE
// (the same or a reworded question routes to the same tool and yields the same answer),
// and curb the creative expansion that adds facts the user didn't ask for. A fixed seed
// makes a given request reproducible. Ollama's default (temp 0.8) is tuned for open-ended
// chat and is the main cause of phrasing-dependent, over-eager answers. Not exactly 0:
// some local models degrade into repetition at 0, so a small epsilon is safer.
// ctx is the resolved context window (see numCtx); it is sent on EVERY call, because a
// single request made without it loses the whole system prompt.
func deterministicOptions(ctx int) map[string]any {
	return map[string]any{
		"temperature": 0.1,
		"top_p":       0.9,
		"seed":        42,
		"num_ctx":     numCtx(ctx),
	}
}

type chatResponse struct {
	Message chatMessage `json:"message"`
	Done    bool        `json:"done"`
}

// chat performs one non-streaming chat completion.
func (c *ollamaClient) chat(ctx context.Context, req chatRequest) (chatResponse, error) {
	req.Stream = false
	b, err := json.Marshal(req)
	if err != nil {
		return chatResponse{}, err
	}
	if err := ssrf.ValidateURL(c.url); err != nil {
		return chatResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/api/chat", bytes.NewReader(b))
	if err != nil {
		return chatResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return chatResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return chatResponse{}, fmt.Errorf("ollama chat: HTTP %d", resp.StatusCode)
	}
	var cr chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return chatResponse{}, err
	}
	return cr, nil
}
