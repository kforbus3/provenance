// Command fleet-enroll-agent enrolls a managed host into Fleet Terminal using
// the SSH agent on the OPERATOR'S machine. The agent's private key never leaves
// this machine: the backend performs the SSH handshake and asks this bridge to
// sign challenges, which it forwards to the local agent ($SSH_AUTH_SOCK).
//
// Usage:
//
//	fleet-enroll-agent -url https://fleet.example.com -host web-01 \
//	    -token "$FLEET_TOKEN" -bootstrap-user opsadmin [-via-jump] \
//	    [-wg-endpoint vpn.example.com:51820] [-sudo-password ...]
//
// Get a token from the web UI (it is your normal access token), or pass
// -user/-password for a non-MFA account.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		base      = flag.String("url", "", "backend base URL, e.g. https://fleet.example.com")
		host      = flag.String("host", "", "host id (UUID) or hostname to enroll")
		token     = flag.String("token", os.Getenv("FLEET_TOKEN"), "access token (or set FLEET_TOKEN)")
		user      = flag.String("user", "", "username (alternative to -token; non-MFA accounts only)")
		pass      = flag.String("password", "", "password (with -user)")
		buser     = flag.String("bootstrap-user", "", "SSH user whose agent key is authorized on the host")
		viaJump   = flag.Bool("via-jump", false, "reach the host through the jump host")
		wgEnd     = flag.String("wg-endpoint", "", "jump host WireGuard endpoint (host:port) the managed host dials")
		sudoPass  = flag.String("sudo-password", "", "sudo password, if the bootstrap user's sudo needs one")
		insecure  = flag.Bool("insecure", false, "skip TLS certificate verification (dev only)")
		agentSock = flag.String("agent", os.Getenv("SSH_AUTH_SOCK"), "SSH agent socket (default $SSH_AUTH_SOCK)")
	)
	flag.Parse()

	if *base == "" || *host == "" {
		return fmt.Errorf("-url and -host are required")
	}
	if *agentSock == "" {
		return fmt.Errorf("no SSH agent: set SSH_AUTH_SOCK or -agent (run `ssh-add` first)")
	}

	// FIPS mode forbids skipping peer-certificate verification. Fail closed rather
	// than silently downgrade the operator's connection to the backend.
	if *insecure && fipsEnabled() {
		return fmt.Errorf("-insecure is not allowed in FIPS mode (FLEET_FIPS_MODE): peer certificates must be verified")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if *insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
	}

	tok := *token
	if tok == "" {
		if *user == "" || *pass == "" {
			return fmt.Errorf("provide -token, or -user and -password")
		}
		var err error
		tok, err = login(client, *base, *user, *pass)
		if err != nil {
			return err
		}
	}

	hostID, err := resolveHostID(client, *base, tok, *host)
	if err != nil {
		return err
	}

	// Connect to the local SSH agent.
	agentConn, err := net.Dial("unix", *agentSock)
	if err != nil {
		return fmt.Errorf("connect SSH agent at %s: %w", *agentSock, err)
	}
	defer agentConn.Close()

	// Open the enrollment WebSocket.
	wsURL, err := wsEndpoint(*base, hostID, tok)
	if err != nil {
		return err
	}
	dialer := *websocket.DefaultDialer
	if *insecure {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	}
	ws, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("connect enrollment websocket (%s): %w", resp.Status, err)
		}
		return fmt.Errorf("connect enrollment websocket: %w", err)
	}
	defer ws.Close()

	// First frame: enrollment parameters.
	params, _ := json.Marshal(map[string]any{
		"bootstrapUser": *buser, "sudoPassword": *sudoPass,
		"wgEndpoint": *wgEnd, "viaJump": *viaJump,
	})
	if err := ws.WriteMessage(websocket.TextMessage, params); err != nil {
		return fmt.Errorf("send parameters: %w", err)
	}
	fmt.Printf("Enrolling %s using your SSH agent (key stays local)…\n", *host)

	// Pipe agent -> websocket (binary frames). The agent only produces bytes in
	// response to requests, so this drives the forwarded signing.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := agentConn.Read(buf)
			if n > 0 {
				if werr := ws.WriteMessage(websocket.BinaryMessage, append([]byte(nil), buf[:n]...)); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	// Pipe websocket -> agent (binary) and surface the final result (text).
	for {
		mt, data, rerr := ws.ReadMessage()
		if rerr != nil {
			return fmt.Errorf("connection closed before result: %w", rerr)
		}
		switch mt {
		case websocket.BinaryMessage:
			if _, werr := agentConn.Write(data); werr != nil {
				return fmt.Errorf("write to agent: %w", werr)
			}
		case websocket.TextMessage:
			return printResult(data)
		}
	}
}

func printResult(data []byte) error {
	var res struct {
		Error     string `json:"error"`
		WGAddress string `json:"wgAddress"`
		Job       struct {
			Status string `json:"status"`
			Steps  []struct {
				Name, Status, Detail string
			} `json:"steps"`
		} `json:"job"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return fmt.Errorf("decode result: %w", err)
	}
	for _, s := range res.Job.Steps {
		mark := map[string]string{"ok": "✓", "failed": "✗", "warning": "⚠"}[s.Status]
		if mark == "" {
			mark = "•"
		}
		fmt.Printf("  %s %s: %s\n", mark, s.Name, s.Detail)
	}
	if res.Error != "" {
		return fmt.Errorf("enrollment failed: %s", res.Error)
	}
	fmt.Printf("Enrolled. Overlay address %s.\n", res.WGAddress)
	return nil
}

func login(client *http.Client, base, user, pass string) (string, error) {
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	resp, err := client.Post(strings.TrimRight(base, "/")+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var lr struct {
		AccessToken           string `json:"accessToken"`
		MFARequired           bool   `json:"mfaRequired"`
		MFAEnrollmentRequired bool   `json:"mfaEnrollmentRequired"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&lr)
	if lr.MFARequired || lr.MFAEnrollmentRequired {
		return "", fmt.Errorf("account requires MFA; sign in via the web UI and pass its access token with -token")
	}
	if lr.AccessToken == "" {
		return "", fmt.Errorf("login failed (status %d)", resp.StatusCode)
	}
	return lr.AccessToken, nil
}

func resolveHostID(client *http.Client, base, token, host string) (string, error) {
	if looksLikeUUID(host) {
		return host, nil
	}
	req, _ := http.NewRequest("GET", strings.TrimRight(base, "/")+"/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var hr struct {
		Hosts []struct {
			ID       string `json:"id"`
			Hostname string `json:"hostname"`
		} `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		return "", err
	}
	for _, h := range hr.Hosts {
		if h.Hostname == host {
			return h.ID, nil
		}
	}
	return "", fmt.Errorf("host %q not found (register it first)", host)
}

func wsEndpoint(base, hostID, token string) (string, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("unsupported url scheme %q", u.Scheme)
	}
	u.Path = fmt.Sprintf("/api/v1/hosts/%s/enroll/agent", hostID)
	u.RawQuery = "token=" + url.QueryEscape(token)
	return u.String(), nil
}

// fipsEnabled reports whether FLEET_FIPS_MODE is set to a truthy value, mirroring
// the backend's config parsing (strconv.ParseBool) so the agent enforces the same
// TLS posture the backend runs under.
func fipsEnabled() bool {
	if v, ok := os.LookupEnv("FLEET_FIPS_MODE"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return false
}

func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
