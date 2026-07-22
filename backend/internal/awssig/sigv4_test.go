package awssig

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSignV4GetVanilla checks SigV4 against AWS's published "get-vanilla" test vector.
func TestSignV4GetVanilla(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	creds := Creds{AccessKey: "AKIDEXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	SignV4(req, nil, "us-east-1", "service", creds, time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))

	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestSignV4IncludesSessionToken(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://secretsmanager.us-east-1.amazonaws.com/", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	SignV4(req, []byte("{}"), "us-east-1", "secretsmanager", Creds{AccessKey: "AK", SecretKey: "SK", SessionToken: "TOKEN123"}, time.Unix(0, 0))

	if req.Header.Get("X-Amz-Security-Token") != "TOKEN123" {
		t.Error("session token header not set")
	}
	auth := req.Header.Get("Authorization")
	for _, h := range []string{"content-type", "x-amz-security-token", "x-amz-target", "host", "x-amz-date"} {
		if !strings.Contains(auth, h) {
			t.Errorf("expected %q in SignedHeaders: %s", h, auth)
		}
	}
}
