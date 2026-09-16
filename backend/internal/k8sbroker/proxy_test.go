package k8sbroker

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kforbus3/provenance/backend/internal/store"
)

func upstreamProxy(t *testing.T, upstream *httptest.Server, rest string) *httptest.Server {
	t.Helper()
	base, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	cl := &store.K8sCluster{Name: "test", APIServer: upstream.URL, InsecureTLS: true}
	rp := newClusterProxy(cl, "the-cluster-token", base, rest, func(int, error) {})
	return httptest.NewServer(rp)
}

// A watch is one long-lived response that trickles events. The OLD implementation
// (client.Do + io.Copy straight into the ResponseWriter) left them in the http
// server's bufio buffer until it filled, so a UI built on watches showed nothing
// and then showed everything at once.
//
// Note what this test does and does not prove. It proves the proxy streams. It
// does NOT guard the FlushInterval field: Go flushes immediately whenever the
// upstream ContentLength is -1, which is every watch and every log follow, so
// setting FlushInterval to 0 does not reproduce the bug. FlushInterval -1 is kept
// because it also covers the responses Go would otherwise batch -- ones that
// arrive with a known length.
func TestAStreamingResponseArrivesIncrementally(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"type\":\"ADDED\"}\n"))
		w.(http.Flusher).Flush()
		<-release // hold the response open, as a watch does
		_, _ = w.Write([]byte("{\"type\":\"DELETED\"}\n"))
	}))
	defer upstream.Close()

	p := upstreamProxy(t, upstream, "/api/v1/pods?watch=1")
	defer p.Close()
	defer close(release)

	resp, err := http.Get(p.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// The first event must be readable while the response is still open.
	done := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(resp.Body).ReadString('\n')
		done <- line
	}()
	select {
	case line := <-done:
		if !strings.Contains(line, "ADDED") {
			t.Errorf("first chunk = %q, want the ADDED event", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no chunk arrived while the response was still open — the proxy is buffering, " +
			"which makes every watch and every log follow useless")
	}
}

// exec, attach and port-forward are not ordinary HTTP: the client sends Upgrade
// and then speaks SPDY or WebSocket over the raw connection. There is no body to
// copy, so a proxy that copies bodies cannot carry a shell at all.
func TestAnUpgradeIsHandedThrough(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Connection"), "Upgrade") {
			t.Errorf("upstream saw Connection=%q, want Upgrade", r.Header.Get("Connection"))
		}
		if got := r.Header.Get("X-Stream-Protocol-Version"); got != "v4.channel.k8s.io" {
			t.Errorf("stream protocol header = %q; k8s selects the exec protocol from it", got)
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("upstream could not hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
			"Connection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\nshell-bytes")
		_ = buf.Flush()
	}))
	defer upstream.Close()

	p := upstreamProxy(t, upstream, "/api/v1/namespaces/default/pods/x/exec")
	defer p.Close()

	req, _ := http.NewRequest(http.MethodGet, p.URL, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "SPDY/3.1")
	req.Header.Set("X-Stream-Protocol-Version", "v4.channel.k8s.io")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("upgrade request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101 — the proxy did not hand over the connection", resp.StatusCode)
	}
}

// The caller authenticated to Provenance. That credential must not reach the
// cluster, and the cluster's must not reach the caller.
func TestTheCallersCredentialIsSwappedNotForwarded(t *testing.T) {
	var seenAuth, seenCookie string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		seenCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := upstreamProxy(t, upstream, "/api/v1/nodes")
	defer p.Close()

	req, _ := http.NewRequest(http.MethodGet, p.URL, nil)
	req.Header.Set("Authorization", "Bearer provenance-session-token")
	req.Header.Set("Cookie", "prov_refresh=secret")
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if seenAuth != "Bearer the-cluster-token" {
		t.Errorf("upstream Authorization = %q, want the CLUSTER token", seenAuth)
	}
	if strings.Contains(seenAuth, "provenance-session-token") || seenCookie != "" {
		t.Errorf("the caller's own credential reached the cluster: auth=%q cookie=%q", seenAuth, seenCookie)
	}
}

func TestClusterTLSHonoursTheVerificationChoice(t *testing.T) {
	if got := clusterTLS(&store.K8sCluster{InsecureTLS: true}); !got.InsecureSkipVerify {
		t.Error("insecureTls must disable verification")
	}
	secure := clusterTLS(&store.K8sCluster{})
	if secure.InsecureSkipVerify {
		t.Error("verification must be on by default")
	}
	if secure.MinVersion != 0x0303 {
		t.Errorf("MinVersion = %x, want TLS 1.2", secure.MinVersion)
	}
}
