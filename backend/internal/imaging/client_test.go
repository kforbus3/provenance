package imaging

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The client is the seam between two products, and the failures worth testing
// are the ones that would otherwise be reported as the wrong thing: a rejected
// token reading as an outage, Flipside's own explanation of a bad rollout being
// swallowed, or the operator token following a redirect somewhere else.

func fake(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "flt_test", 5*time.Second)
}

func TestUnconfiguredIsItsOwnAnswer(t *testing.T) {
	c := NewClient("", "", 0)
	if c.Configured() {
		t.Fatal("a client with no URL reports itself configured")
	}
	// A distinct error, because "you have not set this up" and "this is broken"
	// need completely different messages and different people.
	if _, err := c.Images(context.Background()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestTokenIsSentAsBearer(t *testing.T) {
	var got string
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"images":[]}`))
	})
	if _, err := c.Images(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer flt_test" {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestRejectedTokenIsDistinguishable(t *testing.T) {
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":"Invalid or expired token"}`))
	})
	_, err := c.Images(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want an APIError", err)
	}
	// Told apart from an outage on purpose: one is fixed by re-issuing a token,
	// the other by looking at a server.
	if !apiErr.Unauthorized() {
		t.Fatalf("401 did not report itself as an authorization failure: %+v", apiErr)
	}
	if !strings.Contains(apiErr.Error(), "Invalid or expired token") {
		t.Fatalf("Flipside's own message was lost: %v", apiErr)
	}
}

func TestFlipsideRefusalIsPassedThroughVerbatim(t *testing.T) {
	// Flipside validates a rollout and says exactly what is wrong with one
	// ("that target matches no machines", "no version recorded in its
	// sidecar"). Rewording that here would only lose the detail that makes it
	// actionable.
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"that target matches no machines"}`))
	})
	_, err := c.CreateRollout(context.Background(), map[string]any{"bundle": "x"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 400 {
		t.Fatalf("err = %v, want a 400 APIError", err)
	}
	if apiErr.Detail != "that target matches no machines" {
		t.Fatalf("detail = %q", apiErr.Detail)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	// The token is an operator credential for the imaging server. Flipside is
	// named by configuration and answers on its own address; a redirect is
	// either a misconfiguration or something answering in its place, and
	// following one would hand the token to wherever it pointed.
	var elsewhere bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			elsewhere = true
		}
		_, _ = w.Write([]byte(`{"images":[]}`))
	}))
	defer other.Close()

	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/images", http.StatusFound)
	})
	if _, err := c.Images(context.Background()); err == nil {
		t.Fatal("a redirect was followed and reported as success")
	}
	if elsewhere {
		t.Fatal("the operator token was sent to the redirect target")
	}
}

func TestAnErrorBodyThatIsNotJSONStillReadsAsSomething(t *testing.T) {
	// A proxy in front of Flipside answers with HTML. The message must be a
	// bounded, recognisable fragment rather than a page of markup in a log.
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html><body>" + strings.Repeat("nginx ", 500) + "</body></html>"))
	})
	_, err := c.Images(context.Background())
	if err == nil {
		t.Fatal("a 502 of HTML was treated as success")
	}
	if len(err.Error()) > 500 {
		t.Fatalf("error message is %d bytes; it should be bounded", len(err.Error()))
	}
	if !strings.Contains(err.Error(), "nginx") {
		t.Fatalf("nothing identifiable survived: %v", err)
	}
}

func TestUnreachableSaysWhereItTried(t *testing.T) {
	// "connection refused" on its own sends people to the wrong server. The
	// address is the useful half of the message.
	c := NewClient("http://127.0.0.1:1", "t", time.Second)
	_, err := c.Fleet(context.Background())
	if err == nil {
		t.Fatal("expected a failure")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("error does not name the address it tried: %v", err)
	}
}

func TestFleetAndRolloutsDecode(t *testing.T) {
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fleet":
			_, _ = w.Write([]byte(`{"machines":[{"id":"aa:bb","hostname":"web01",
				"version":"2.0","presence":"online","health":"ok","groups":["prod"]}],
				"counts":{"online":1},"versions":{"2.0":1},"interval":300,
				"control_url":"https://flipside.example.com"}`))
		case "/api/rollouts":
			_, _ = w.Write([]byte(`{"rollouts":[{"id":"r-1","bundle":"b.raucb","version":"2.0",
				"state":"running","total":3,"done":1,"counts":{"verified":1,"pending":2},
				"machines":{"aa:bb":{"state":"verified"},"cc:dd":{"state":"pending"}},
				"strategy":{"canary":1,"batch_size":10,"soak_seconds":900,"max_failures":2}}]}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	view, err := c.Fleet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Machines) != 1 || view.Machines[0].Presence != "online" ||
		view.ControlURL != "https://flipside.example.com" {
		t.Fatalf("fleet decoded wrong: %+v", view)
	}
	rollouts, err := c.Rollouts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rollouts) != 1 || rollouts[0].Machines["cc:dd"].State != "pending" ||
		rollouts[0].Strategy.Canary != 1 {
		t.Fatalf("rollout decoded wrong: %+v", rollouts)
	}
}

func TestSteerRolloutEscapesItsArguments(t *testing.T) {
	// The id reaches a URL path. It comes from Flipside rather than a browser,
	// but "it came from a trusted system" is the reasoning behind most path
	// injections.
	var path string
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.EscapedPath()
	})
	_ = c.SteerRollout(context.Background(), "r-1/../../admin", "pause")
	if strings.Contains(path, "/../") {
		t.Fatalf("path traversal survived escaping: %s", path)
	}
}
