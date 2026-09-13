package assistant

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Exercises the real client against a real OpenAI-compatible server: list models,
// read the served window, and run a full tool round trip through the translation.
// Skipped unless PROV_LIVE_OPENAI is set, so it never runs in the normal gate.
func TestLiveOpenAIRoundTrip(t *testing.T) {
	url := os.Getenv("PROV_LIVE_OPENAI")
	if url == "" {
		t.Skip("set PROV_LIVE_OPENAI to run")
	}
	model := os.Getenv("PROV_LIVE_MODEL")
	c := newOpenAI(url, "")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	models, err := c.listModels(ctx)
	if err != nil {
		t.Fatalf("listModels: %v", err)
	}
	t.Logf("models: %v", models)
	t.Logf("served window for %s: %d (prompt floor %d)", model, c.modelContextLength(ctx, model), promptFloorTokens())

	var args json.RawMessage = []byte(`{"status":"offline"}`)
	tc := toolCall{}
	tc.ID = "call_1"
	tc.Function.Name = "query_hosts"
	tc.Function.Arguments = args

	resp, err := c.chat(ctx, chatRequest{
		Model: model,
		Messages: []chatMessage{
			{Role: "system", Content: "You are a fleet assistant. Answer only from tool results. Be terse."},
			{Role: "user", Content: "How many hosts are offline?"},
			{Role: "assistant", ToolCalls: []toolCall{tc}},
			{Role: "tool", ToolCallID: "call_1", Content: `{"count":2,"hosts":["alpha","beta"]}`},
		},
		Options: deterministicOptions(0),
	})
	if err != nil {
		t.Fatalf("chat: %v", err)
	}
	t.Logf("answer: %q", resp.Message.Content)
	if resp.Message.Content == "" {
		t.Error("empty answer from a tool round trip")
	}
}

// The model must actually emit a tool call through our translation, not just
// answer from its own knowledge.
func TestLiveOpenAIEmitsToolCalls(t *testing.T) {
	url := os.Getenv("PROV_LIVE_OPENAI")
	if url == "" {
		t.Skip("set PROV_LIVE_OPENAI to run")
	}
	c := newOpenAI(url, "")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	resp, err := c.chat(ctx, chatRequest{
		Model: os.Getenv("PROV_LIVE_MODEL"),
		Messages: []chatMessage{
			{Role: "system", Content: "You are a fleet assistant. Use the tools provided."},
			{Role: "user", Content: "How many hosts are offline?"},
		},
		Tools:   []toolDef{{Type: "function", Function: toolFunction{Name: "query_hosts", Description: "Query hosts by status", Parameters: map[string]any{"type": "object", "properties": map[string]any{"status": map[string]any{"type": "string"}}}}}},
		Options: deterministicOptions(0),
	})
	if err != nil {
		t.Fatalf("chat: %v", err)
	}
	if len(resp.Message.ToolCalls) == 0 {
		t.Fatalf("no tool calls; content=%q", resp.Message.Content)
	}
	got := resp.Message.ToolCalls[0]
	t.Logf("tool=%s id=%s args=%s", got.Function.Name, got.ID, string(got.Function.Arguments))
	var parsed map[string]any
	if err := json.Unmarshal(got.Function.Arguments, &parsed); err != nil {
		t.Fatalf("arguments did not arrive as a JSON object: %v", err)
	}
	if got.ID == "" {
		t.Error("tool call id was lost; the tool result cannot be paired back")
	}
}
