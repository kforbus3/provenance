package assistant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Tool-call arguments are a JSON object in Ollama's protocol and a JSON string in
// OpenAI's. Every tool runner in this package unmarshals the object form, so the
// client has to translate both ways — and a failure here is silent: the model
// appears to call the tool and the runner sees empty arguments.
func TestToolCallArgumentsCrossTheObjectStringBoundary(t *testing.T) {
	out := toOpenAIMessages([]chatMessage{{
		Role: "assistant",
		ToolCalls: []toolCall{func() toolCall {
			var c toolCall
			c.ID = "call_1"
			c.Function.Name = "query_hosts"
			c.Function.Arguments = json.RawMessage(`{"status":"offline"}`)
			return c
		}()},
	}})
	if len(out) != 1 || len(out[0].ToolCalls) != 1 {
		t.Fatalf("expected one tool call, got %+v", out)
	}
	got := out[0].ToolCalls[0]
	if got.Function.Arguments != `{"status":"offline"}` {
		t.Errorf("arguments went out as %q, want the JSON string form", got.Function.Arguments)
	}
	if got.Type != "function" {
		t.Errorf("tool call type = %q, want \"function\"", got.Type)
	}
	if got.ID != "call_1" {
		t.Errorf("tool call id = %q, want it preserved", got.ID)
	}

	// ...and back, as the object the runners unmarshal.
	back := fromOpenAIMessage(openaiMessage{Role: "assistant", ToolCalls: []openaiToolCall{got}})
	var args struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(back.ToolCalls[0].Function.Arguments, &args); err != nil {
		t.Fatalf("arguments did not come back as a JSON object: %v", err)
	}
	if args.Status != "offline" {
		t.Errorf("status = %q, want offline", args.Status)
	}
}

// Empty arguments must become "{}", not "". A tool call whose arguments are the
// empty string is rejected by servers that parse it strictly, and the model then
// looks like it failed to call the tool.
func TestEmptyToolArgumentsBecomeAnEmptyObject(t *testing.T) {
	out := toOpenAIMessages([]chatMessage{{Role: "assistant", ToolCalls: []toolCall{{}}}})
	if got := out[0].ToolCalls[0].Function.Arguments; got != "{}" {
		t.Errorf("empty arguments went out as %q, want %q", got, "{}")
	}
	back := fromOpenAIMessage(openaiMessage{ToolCalls: []openaiToolCall{{}}})
	if got := string(back.ToolCalls[0].Function.Arguments); got != "{}" {
		t.Errorf("empty arguments came back as %q, want %q", got, "{}")
	}
}

// The OpenAI protocol matches a tool result to its call by tool_call_id. Dropping
// it leaves the server unable to pair them.
func TestToolResultCarriesItsCallID(t *testing.T) {
	out := toOpenAIMessages([]chatMessage{{Role: "tool", Content: "{}", ToolCallID: "call_7"}})
	if out[0].ToolCallID != "call_7" {
		t.Fatalf("tool_call_id = %q, want it preserved", out[0].ToolCallID)
	}
}

// num_ctx has no per-request equivalent: the window is fixed when the server
// starts. It must be dropped rather than sent, and the sampling options that DO
// map must survive — losing them costs the determinism the whole feature relies on.
func TestSamplingMapsAndNumCtxIsDropped(t *testing.T) {
	var r openaiRequest
	r.sampling(deterministicOptions(32768))
	if r.Temperature == nil || *r.Temperature != 0.1 {
		t.Errorf("temperature = %v, want 0.1", r.Temperature)
	}
	if r.TopP == nil || *r.TopP != 0.9 {
		t.Errorf("top_p = %v, want 0.9", r.TopP)
	}
	if r.Seed == nil || *r.Seed != 42 {
		t.Errorf("seed = %v, want 42", r.Seed)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "num_ctx") {
		t.Error("num_ctx was sent; the server fixes the window at startup and cannot honour it")
	}
}

// A reasoning model spends its budget thinking and returns empty content with
// finish_reason "length". Returning that as a successful empty answer is
// indistinguishable from a broken model: nothing errors and the log says nothing.
func TestReasoningModelExhaustionIsReportedNotReturnedBlank(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"length",
			"message":{"role":"assistant","content":"","reasoning_content":"thinking..."}}]}`))
	}))
	defer srv.Close()

	_, err := testOpenAI(srv.URL, "").chat(context.Background(), chatRequest{Model: "m"})
	if err == nil {
		t.Fatal("an exhausted reasoning model returned no error")
	}
	if !strings.Contains(err.Error(), "reasoning") {
		t.Errorf("error %q does not name reasoning as the cause", err)
	}
}

// The server's own error message is the actionable part — "model 'x' not found"
// and a context overflow both arrive as a 400, and a bare status code sends the
// operator to look at the network instead.
func TestServerErrorMessageIsSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"model 'gpt-4o-mini' not found"}}`))
	}))
	defer srv.Close()

	_, err := testOpenAI(srv.URL, "").chat(context.Background(), chatRequest{Model: "gpt-4o-mini"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error = %v, want the server's own message", err)
	}
}

// Operators paste the base URL from wherever the server documented itself, and
// both spellings are common. Rejecting one produces a 404 that reads like the
// server being down.
func TestBaseURLAcceptsAnOptionalV1Suffix(t *testing.T) {
	for _, in := range []string{"http://ai:8080", "http://ai:8080/", "http://ai:8080/v1", "http://ai:8080/v1/"} {
		if got := newOpenAI(in, "").url; got != "http://ai:8080" {
			t.Errorf("newOpenAI(%q).url = %q, want http://ai:8080", in, got)
		}
	}
}

// The API key is a bearer token and must only be sent when configured: a local
// llama.cpp needs none.
func TestAPIKeyIsSentOnlyWhenSet(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	_, _ = testOpenAI(srv.URL, "").listModels(context.Background())
	if seen != "" {
		t.Errorf("sent Authorization %q with no key configured", seen)
	}
	_, _ = testOpenAI(srv.URL, "sk-test").listModels(context.Background())
	if seen != "Bearer sk-test" {
		t.Errorf("Authorization = %q, want a bearer token", seen)
	}
}

// llama.cpp reports the window it will actually serve in meta.n_ctx, which is the
// number that matters — not the model's trained length, which no request can reach.
func TestModelContextLengthReadsTheServedWindow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[
			{"id":"gemma4-26b","meta":{"n_ctx":8192,"n_ctx_train":262144}},
			{"id":"unloaded"}]}`))
	}))
	defer srv.Close()
	c := testOpenAI(srv.URL, "")

	if got := c.modelContextLength(context.Background(), "gemma4-26b"); got != 8192 {
		t.Errorf("served window = %d, want 8192 (not the trained 262144)", got)
	}
	// A model the server has not loaded reports nothing; 0 is the existing
	// "unknown" value, not a claim that the window is zero.
	if got := c.modelContextLength(context.Background(), "unloaded"); got != 0 {
		t.Errorf("unloaded model window = %d, want 0 (unknown)", got)
	}
	if got := c.modelContextLength(context.Background(), "absent"); got != 0 {
		t.Errorf("absent model window = %d, want 0", got)
	}
}

// testOpenAI points a client at an httptest server. Only the two SSRF guards are
// relaxed — the validator and the dialer both refuse loopback, which is exactly
// right in production and exactly wrong for a test server. Everything above them,
// including all of the translation this file is testing, is the production client.
func testOpenAI(url, key string) *openaiClient {
	c := newOpenAI(url, key)
	c.validate = func(string) error { return nil }
	c.http = &http.Client{}
	return c
}
