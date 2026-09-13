package assistant

import (
	"context"
	"fmt"
	"strings"
)

// The assistant talks to a local model server. Two wire protocols are supported,
// because they are not interchangeable:
//
//   - Ollama's native API (/api/tags, /api/chat), which this feature was built on.
//   - The OpenAI chat-completions API (/v1/models, /v1/chat/completions), which is
//     what llama.cpp, vLLM, LocalAI and others serve. llama.cpp serves NO /api/*
//     routes at all, so a deployment that moves to it cannot be repointed by
//     changing a URL — the client has to change with it.
//
// Everything above this interface is written against Ollama's shapes, because that
// is what the tool loop, the fast paths and the direct answers were built and tuned
// against. The OpenAI client adapts to those shapes rather than the reverse, so
// there is exactly one representation of a conversation in this package.
type llmClient interface {
	// listModels returns the model names the server can serve.
	listModels(ctx context.Context) ([]string, error)
	// modelContextLength returns the context window the server will actually give
	// this model, or 0 when that cannot be determined. This is a correctness input,
	// not a statistic: the system prompt plus the tool schemas alone are over ten
	// thousand tokens, and a server whose window is smaller than that silently
	// discards the instructions instead of erroring.
	modelContextLength(ctx context.Context, model string) int
	// chat performs one non-streaming completion.
	chat(ctx context.Context, req chatRequest) (chatResponse, error)
}

// Provider names as stored in the `assistant` setting.
const (
	ProviderOllama = "ollama"
	ProviderOpenAI = "openai"
)

// resolveProvider decides which protocol to speak, and is deliberately explicit
// rather than clever.
//
// An absent `provider` means the setting predates this field — it is not a choice
// the operator made — so it resolves to Ollama, which is what such a deployment was
// necessarily talking to. It is never inferred from the port or the URL shape: an
// OpenAI-compatible server on :11434 is perfectly legal, and guessing wrong fails
// as a connection error that names the wrong cause.
//
// The resolved value is reported in Status so the UI shows which protocol is in
// use rather than leaving the operator to infer it.
func resolveProvider(cfg Settings) string {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case ProviderOpenAI:
		return ProviderOpenAI
	case ProviderOllama:
		return ProviderOllama
	default:
		return ProviderOllama
	}
}

// resolveBaseURL returns the server URL for the resolved provider.
//
// BaseURL is the field going forward; OllamaURL is kept because it is what every
// existing deployment has stored, and a rename that silently emptied it would
// disable the assistant on upgrade. BaseURL wins when both are set.
func resolveBaseURL(cfg Settings) string {
	if u := strings.TrimSpace(cfg.BaseURL); u != "" {
		return u
	}
	return strings.TrimSpace(cfg.OllamaURL)
}

// newLLMClient builds the client for the configured provider.
func newLLMClient(cfg Settings) (llmClient, error) {
	url := resolveBaseURL(cfg)
	if url == "" {
		return nil, fmt.Errorf("no model server URL configured")
	}
	switch resolveProvider(cfg) {
	case ProviderOpenAI:
		return newOpenAI(url, cfg.APIKey), nil
	default:
		return newOllama(url), nil
	}
}
