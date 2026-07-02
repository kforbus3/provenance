package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/fleet-terminal/backend/internal/secretbox"
	"github.com/fleet-terminal/backend/internal/ssrf"
)

// emailPassword decrypts the stored SMTP password (empty if none/unset).
func (s *Service) emailPassword(cfg *Config) string {
	if cfg.Email.PasswordEnc == "" {
		return ""
	}
	pw, err := secretbox.Open(s.cfg.CAKeyPassphrase, cfg.Email.PasswordEnc)
	if err != nil {
		s.log.Warn("notify: decrypt smtp password", "err", err)
		return ""
	}
	return string(pw)
}

// sendEmail delivers ev over SMTP. toOverride, when non-empty, replaces the
// configured admin distribution list (used to email a single direct recipient).
func (s *Service) sendEmail(_ context.Context, cfg *Config, ev Event, toOverride string) error {
	e := cfg.Email
	to := e.To
	if toOverride != "" {
		to = toOverride
	}
	if e.Host == "" || e.From == "" || to == "" {
		return fmt.Errorf("email channel is incompletely configured")
	}
	port := e.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(e.Host, fmt.Sprintf("%d", port))

	recipients := splitList(to)
	subject := fmt.Sprintf("[Fleet] %s", ev.Title)
	msg := buildMessage(e.From, to, subject, ev.Body)

	var auth smtp.Auth
	if e.Username != "" {
		auth = smtp.PlainAuth("", e.Username, s.emailPassword(cfg), e.Host)
	}

	switch strings.ToLower(e.Security) {
	case "tls": // implicit TLS (usually port 465)
		return sendImplicitTLS(addr, e.Host, auth, e.From, recipients, msg)
	default: // "starttls" (587) or "none" (25) — SendMail upgrades if offered
		return smtp.SendMail(addr, auth, e.From, recipients, msg)
	}
}

// sendImplicitTLS handles SMTPS (TLS from the first byte).
func sendImplicitTLS(addr, host string, auth smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// hdrSafe strips CR/LF so a value carried into a header (e.g. a hostname in the
// Subject) can't inject extra headers or a forged body.
func hdrSafe(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func buildMessage(from, to, subject, body string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", hdrSafe(from))
	fmt.Fprintf(&b, "To: %s\r\n", hdrSafe(to))
	fmt.Fprintf(&b, "Subject: %s\r\n", hdrSafe(subject))
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=UTF-8\r\n")
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.Bytes()
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Service) sendWebhook(ctx context.Context, cfg *Config, ev Event) error {
	w := cfg.Webhook
	if w.URL == "" {
		return fmt.Errorf("webhook URL is not set")
	}
	text := fmt.Sprintf("*%s*\n%s", ev.Title, ev.Body)

	var payload any
	switch strings.ToLower(w.Format) {
	case "slack", "mattermost":
		payload = map[string]string{"text": text}
	case "discord":
		payload = map[string]string{"content": text}
	default: // generic json
		payload = map[string]string{
			"type": ev.Type, "severity": string(ev.Severity),
			"title": ev.Title, "body": ev.Body,
		}
	}
	body, _ := json.Marshal(payload)

	if err := ssrf.ValidateURL(w.URL); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
