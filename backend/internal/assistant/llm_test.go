package assistant

import (
	"strings"
	"testing"
)

// A setting stored before `provider` existed has no opinion about the protocol —
// that is not the operator choosing OpenAI. It must resolve to Ollama, which is
// necessarily what such a deployment was talking to, or every existing install
// breaks the moment it upgrades.
func TestAnAbsentProviderIsNotAChoice(t *testing.T) {
	legacy := Settings{Enabled: true, OllamaURL: "http://ai:11434", Model: "qwen2.5:14b"}
	if got := resolveProvider(legacy); got != ProviderOllama {
		t.Errorf("resolveProvider(legacy) = %q, want %q", got, ProviderOllama)
	}
	if got := resolveBaseURL(legacy); got != "http://ai:11434" {
		t.Errorf("resolveBaseURL(legacy) = %q, want the stored ollamaUrl", got)
	}
	c, err := newLLMClient(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.(*ollamaClient); !ok {
		t.Errorf("legacy settings built a %T, want the Ollama client", c)
	}
}

// The protocol is never inferred from the URL or the port. An OpenAI-compatible
// server on :11434 is legal, and guessing wrong fails as a connection error that
// names the wrong cause.
func TestProviderIsNeverGuessedFromTheURL(t *testing.T) {
	openaiOn11434 := Settings{Provider: ProviderOpenAI, BaseURL: "http://ai:11434/v1"}
	if got := resolveProvider(openaiOn11434); got != ProviderOpenAI {
		t.Errorf("an explicit openai provider was overridden to %q", got)
	}
	ollamaOn8080 := Settings{Provider: ProviderOllama, BaseURL: "http://ai:8080"}
	if got := resolveProvider(ollamaOn8080); got != ProviderOllama {
		t.Errorf("an explicit ollama provider was overridden to %q", got)
	}
}

func TestOpenAIProviderBuildsTheOpenAIClient(t *testing.T) {
	c, err := newLLMClient(Settings{Provider: ProviderOpenAI, BaseURL: "http://ai:8080", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	oc, ok := c.(*openaiClient)
	if !ok {
		t.Fatalf("built a %T, want the OpenAI client", c)
	}
	if oc.apiKey != "k" {
		t.Errorf("api key = %q, want it carried through", oc.apiKey)
	}
}

// baseUrl is the field going forward, but ollamaUrl is what every existing
// deployment has stored. Both are read; the new one wins.
func TestBaseURLWinsOverTheLegacyField(t *testing.T) {
	both := Settings{BaseURL: "http://new:8080", OllamaURL: "http://old:11434"}
	if got := resolveBaseURL(both); got != "http://new:8080" {
		t.Errorf("resolveBaseURL = %q, want the newer baseUrl", got)
	}
	// Whitespace-only is not a value. Treating it as one would point a deployment
	// at an empty URL and report it as unreachable rather than unconfigured.
	blank := Settings{BaseURL: "   ", OllamaURL: "http://old:11434"}
	if got := resolveBaseURL(blank); got != "http://old:11434" {
		t.Errorf("resolveBaseURL = %q, want it to fall through to ollamaUrl", got)
	}
}

// Provider names are matched case-insensitively: operators type them by hand in
// the settings screen and "OpenAI" is the natural spelling.
func TestProviderMatchingIsCaseInsensitive(t *testing.T) {
	for _, in := range []string{"openai", "OpenAI", "OPENAI", " openai "} {
		if got := resolveProvider(Settings{Provider: in}); got != ProviderOpenAI {
			t.Errorf("resolveProvider(%q) = %q, want %q", in, got, ProviderOpenAI)
		}
	}
}

// No URL at all is a configuration error, not a client that fails later with a
// confusing connection message.
func TestNoURLIsRefusedUpFront(t *testing.T) {
	if _, err := newLLMClient(Settings{Provider: ProviderOpenAI}); err == nil {
		t.Fatal("expected an error when no server URL is configured")
	}
}

// On an OpenAI-compatible server the window is fixed at startup and no request can
// raise it, so the number to compare against is the PROMPT FLOOR — the system prompt
// plus every tool schema, before a single row of data. Below it the assistant cannot
// work at all, and the operator needs to be told which knob to turn, on which side.
//
// This is the case the fleet actually hit: gemma4-26b served at 8192 against a floor
// of ~10,157.
func TestContextWarningNamesTheServerSideFixForOpenAI(t *testing.T) {
	floor := promptFloorTokens()
	if floor < 8192 {
		t.Skipf("prompt floor %d no longer exceeds a typical 8192 window; rewrite this test", floor)
	}
	msg := openAIContextWarning("gemma4-26b", 8192, numCtx(0), floor)
	if msg == "" {
		t.Fatal("a served window below the prompt floor produced no warning")
	}
	for _, want := range []string{"8192", "ctx-size"} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning does not mention %q: %s", want, msg)
		}
	}
	// Above the floor but below what this deployment configured is a mismatch worth
	// saying, but not the same failure — the assistant works, it just cannot have the
	// window it asked for.
	mismatch := openAIContextWarning("m", floor+1000, 32768, floor)
	if mismatch == "" || strings.Contains(mismatch, "ctx-size") {
		t.Errorf("a window above the floor should report a mismatch, not the floor failure: %q", mismatch)
	}
	// A window that satisfies both says nothing.
	if got := openAIContextWarning("m", 32768, 32768, floor); got != "" {
		t.Errorf("a sufficient window still warned: %q", got)
	}
	// Unknown (a model the server has not loaded) is not a complaint.
	if got := openAIContextWarning("m", 0, 32768, floor); got != "" {
		t.Errorf("an unknown window warned: %q", got)
	}
}
