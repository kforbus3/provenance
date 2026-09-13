package assistant

import "testing"

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
