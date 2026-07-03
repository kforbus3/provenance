package assistant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	var body struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(body.Models))
	for _, m := range body.Models {
		names = append(names, m.Name)
	}
	return names, nil
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
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Tools    []toolDef     `json:"tools,omitempty"`
	Stream   bool          `json:"stream"`
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
