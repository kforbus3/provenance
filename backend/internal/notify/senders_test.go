package notify

import (
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

func TestBuildMessagePlainNoAttachments(t *testing.T) {
	msg := buildMessage("from@x.com", "to@y.com", "[Fleet] Hi", "hello", nil)
	m, err := mail.ReadMessage(strings.NewReader(string(msg)))
	if err != nil {
		t.Fatal(err)
	}
	if ct := m.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("expected text/plain, got %q", ct)
	}
	body, _ := io.ReadAll(m.Body)
	if strings.TrimSpace(string(body)) != "hello" {
		t.Fatalf("body = %q", body)
	}
}

func TestBuildMessageWithAttachmentIsValidMIME(t *testing.T) {
	csv := []byte("user,host\nalice,web-01\n")
	msg := buildMessage("from@x.com", "to@y.com", "[Fleet] Report", "See attached.", []Attachment{
		{Filename: "access.csv", ContentType: "text/csv", Data: csv},
	})
	m, err := mail.ReadMessage(strings.NewReader(string(msg)))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("expected multipart, got %q err=%v", mediaType, err)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	var sawBody, sawCSV bool
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(part)
		ct := part.Header.Get("Content-Type")
		switch {
		case strings.HasPrefix(ct, "text/plain"):
			sawBody = true
		case strings.HasPrefix(ct, "text/csv"):
			sawCSV = true
			if fn := part.FileName(); fn != "access.csv" {
				t.Fatalf("attachment filename = %q", fn)
			}
			// The part carries the CSV base64-encoded (mail clients decode this).
			if part.Header.Get("Content-Transfer-Encoding") != "base64" {
				t.Fatal("attachment is not base64-encoded")
			}
			dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(string(data)), "\r\n", ""))
			if err != nil {
				t.Fatalf("attachment is not valid base64: %v", err)
			}
			if string(dec) != string(csv) {
				t.Fatalf("attachment content mismatch: %q vs %q", dec, csv)
			}
		}
	}
	if !sawBody || !sawCSV {
		t.Fatalf("missing parts: body=%v csv=%v", sawBody, sawCSV)
	}
}
