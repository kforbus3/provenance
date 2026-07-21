package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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
	msg := buildMessage(e.From, to, subject, ev.Body, ev.Attachments)

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
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", addr,
		&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
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

func buildMessage(from, to, subject, body string, attachments []Attachment) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", hdrSafe(from))
	fmt.Fprintf(&b, "To: %s\r\n", hdrSafe(to))
	fmt.Fprintf(&b, "Subject: %s\r\n", hdrSafe(subject))
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))

	if len(attachments) == 0 {
		fmt.Fprintf(&b, "Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(body)
		return b.Bytes()
	}

	// multipart/mixed: a text body part followed by one part per attachment.
	// A fixed boundary keeps this deterministic (no randomness needed here).
	const boundary = "fleet-mixed-boundary-8f3a1c"
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", boundary)
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(body)
	b.WriteString("\r\n")
	for _, a := range attachments {
		ct := a.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		fmt.Fprintf(&b, "Content-Type: %s\r\n", ct)
		fmt.Fprintf(&b, "Content-Transfer-Encoding: base64\r\n")
		fmt.Fprintf(&b, "Content-Disposition: attachment; filename=%q\r\n\r\n", a.Filename)
		writeBase64Wrapped(&b, a.Data)
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes()
}

// writeBase64Wrapped writes data as base64 in 76-char lines (RFC 2045).
func writeBase64Wrapped(b *bytes.Buffer, data []byte) {
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	b.WriteString("\r\n")
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
	case "teams":
		// Microsoft Teams incoming-webhook MessageCard.
		payload = map[string]any{
			"@type": "MessageCard", "@context": "http://schema.org/extensions",
			"summary": ev.Title, "themeColor": severityColor(ev.Severity),
			"title": ev.Title, "text": ev.Body,
		}
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
	client := ssrf.SafeClient(15 * time.Second)
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

// decryptSecret opens a secretbox-sealed value (empty if unset).
func (s *Service) decryptSecret(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	b, err := secretbox.Open(s.cfg.CAKeyPassphrase, enc)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// severityColor maps a severity to a hex accent used by rich-card receivers.
func severityColor(sev Severity) string {
	switch sev {
	case SeverityError:
		return "D93F0B"
	case SeverityWarning:
		return "FBCA04"
	default:
		return "1F6FEB"
	}
}

// sendPagerDuty triggers an incident via the Events API v2. The endpoint is a
// fixed PagerDuty host, so no SSRF validation is needed (unlike the user-supplied
// webhook URL).
func (s *Service) sendPagerDuty(ctx context.Context, cfg *Config, ev Event) error {
	key, err := s.decryptSecret(cfg.PagerDuty.RoutingKeyEnc)
	if err != nil || key == "" {
		return fmt.Errorf("pagerduty routing key is not set")
	}
	payload := map[string]any{
		"routing_key":  key,
		"event_action": "trigger",
		"payload": map[string]any{
			"summary":  truncate(ev.Title, 1024),
			"source":   "fleet-terminal",
			"severity": pagerdutySeverity(ev.Severity),
			"custom_details": map[string]string{
				"type": ev.Type, "body": ev.Body,
			},
		},
	}
	if ev.DedupeKey != "" {
		payload["dedup_key"] = ev.Type + ":" + ev.DedupeKey
	}
	return postJSON(ctx, "https://events.pagerduty.com/v2/enqueue", nil, payload)
}

func pagerdutySeverity(sev Severity) string {
	switch sev {
	case SeverityError:
		return "critical"
	case SeverityWarning:
		return "warning"
	default:
		return "info"
	}
}

// sendOpsgenie raises an alert via the Opsgenie Alerts API (US or EU host).
func (s *Service) sendOpsgenie(ctx context.Context, cfg *Config, ev Event) error {
	key, err := s.decryptSecret(cfg.Opsgenie.APIKeyEnc)
	if err != nil || key == "" {
		return fmt.Errorf("opsgenie api key is not set")
	}
	host := "api.opsgenie.com"
	if strings.EqualFold(cfg.Opsgenie.Region, "eu") {
		host = "api.eu.opsgenie.com"
	}
	payload := map[string]any{
		"message":     truncate(ev.Title, 130),
		"description": ev.Body,
		"priority":    opsgeniePriority(ev.Severity),
	}
	if ev.DedupeKey != "" {
		payload["alias"] = ev.Type + ":" + ev.DedupeKey
	}
	return postJSON(ctx, "https://"+host+"/v2/alerts",
		map[string]string{"Authorization": "GenieKey " + key}, payload)
}

func opsgeniePriority(sev Severity) string {
	switch sev {
	case SeverityError:
		return "P1"
	case SeverityWarning:
		return "P3"
	default:
		return "P5"
	}
}

// postJSON POSTs a JSON body to a fixed (non-user-supplied) URL with optional
// headers, treating any 2xx as success.
func postJSON(ctx context.Context, url string, headers map[string]string, payload any) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %d", url, resp.StatusCode)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
