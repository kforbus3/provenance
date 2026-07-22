package kms

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

// awsCreds holds the AWS credentials used to sign a request.
type awsCreds struct {
	accessKey    string
	secretKey    string
	sessionToken string // optional (STS)
}

// signV4 signs an HTTP request with AWS Signature Version 4 and sets the
// X-Amz-Date, Authorization (and, when present, X-Amz-Security-Token) headers on it.
// Implemented against the documented algorithm with no AWS SDK. The signing time is
// passed in so the process is deterministic and unit-testable against AWS's published
// test vectors.
func signV4(req *http.Request, body []byte, region, service string, creds awsCreds, t time.Time) {
	t = t.UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if creds.sessionToken != "" {
		// The session token must be present before we compute the signed-header set so
		// it is covered by the signature.
		req.Header.Set("X-Amz-Security-Token", creds.sessionToken)
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	// Canonical headers: host plus every X-Amz-* / Content-Type header on the request,
	// lower-cased and sorted, each "name:trimmed-value\n".
	type hdr struct{ name, value string }
	headers := []hdr{{"host", host}}
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		if lk == "content-type" || strings.HasPrefix(lk, "x-amz-") {
			headers = append(headers, hdr{lk, strings.TrimSpace(strings.Join(vs, ","))})
		}
	}
	sort.Slice(headers, func(i, j int) bool { return headers[i].name < headers[j].name })

	var canonHeaders strings.Builder
	names := make([]string, 0, len(headers))
	for _, h := range headers {
		canonHeaders.WriteString(h.name)
		canonHeaders.WriteByte(':')
		canonHeaders.WriteString(h.value)
		canonHeaders.WriteByte('\n')
		names = append(names, h.name)
	}
	signedHeaders := strings.Join(names, ";")

	payloadHash := hexSHA256(body)

	canonURI := req.URL.EscapedPath()
	if canonURI == "" {
		canonURI = "/"
	}
	canonQuery := canonicalQuery(req.URL.RawQuery)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonURI,
		canonQuery,
		canonHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+creds.secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	auth := "AWS4-HMAC-SHA256 " +
		"Credential=" + creds.accessKey + "/" + scope + ", " +
		"SignedHeaders=" + signedHeaders + ", " +
		"Signature=" + signature
	req.Header.Set("Authorization", auth)
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func hexSHA256(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// canonicalQuery sorts and re-encodes a raw query string per SigV4 rules. Fleet's
// KMS calls carry no query, but this keeps the signer correct and self-contained.
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	sort.Strings(parts)
	return strings.Join(parts, "&")
}
