package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fleet-terminal/backend/internal/awssig"
)

// awsKMSPrefix tags a wrapped blob produced by the AWS KMS backend so it is
// self-describing on disk and Unwrap can reject a mismatched token.
const awsKMSPrefix = "awskms:v1:"

// awsKMS wraps/unwraps via AWS KMS Encrypt/Decrypt. Implemented against the KMS
// JSON API with a hand-rolled SigV4 signer (see sigv4.go) so Fleet takes no
// dependency on the AWS SDK. An endpoint override supports KMS-compatible emulators
// (e.g. LocalStack) for testing.
type awsKMS struct {
	endpoint string // full base URL, no trailing slash
	region   string
	keyID    string
	creds    awssig.Creds
	client   *http.Client
	now      func() time.Time // injectable for tests
}

func newAWSKMS(cfg Config) (Provider, error) {
	region := strings.TrimSpace(cfg.AWSRegion)
	if region == "" {
		return nil, fmt.Errorf("kms(aws-kms): FLEET_KMS_AWS_REGION is required")
	}
	if strings.TrimSpace(cfg.KeyID) == "" {
		return nil, fmt.Errorf("kms(aws-kms): FLEET_KMS_KEY_ID (key id / ARN / alias) is required")
	}
	if strings.TrimSpace(cfg.AWSAccessKey) == "" || strings.TrimSpace(cfg.AWSSecretKey) == "" {
		return nil, fmt.Errorf("kms(aws-kms): FLEET_KMS_AWS_ACCESS_KEY_ID and FLEET_KMS_AWS_SECRET_ACCESS_KEY are required")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.AWSEndpoint), "/")
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://kms.%s.amazonaws.com", region)
	}
	return &awsKMS{
		endpoint: endpoint,
		region:   region,
		keyID:    cfg.KeyID,
		creds: awssig.Creds{
			AccessKey:    cfg.AWSAccessKey,
			SecretKey:    cfg.AWSSecretKey,
			SessionToken: cfg.AWSSessionToken,
		},
		client: &http.Client{Timeout: 15 * time.Second},
		now:    time.Now,
	}, nil
}

func (a *awsKMS) Name() string { return "aws-kms" }

func (a *awsKMS) Wrap(ctx context.Context, plaintext []byte) (string, error) {
	req := map[string]string{
		"KeyId":     a.keyID,
		"Plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}
	var out struct {
		CiphertextBlob string `json:"CiphertextBlob"`
	}
	if err := a.call(ctx, "TrentService.Encrypt", req, &out); err != nil {
		return "", err
	}
	if out.CiphertextBlob == "" {
		return "", fmt.Errorf("kms(aws-kms): empty ciphertext from KMS")
	}
	// KMS already returns base64; keep it and add a self-describing prefix.
	return awsKMSPrefix + out.CiphertextBlob, nil
}

func (a *awsKMS) Unwrap(ctx context.Context, token string) ([]byte, error) {
	if !strings.HasPrefix(token, awsKMSPrefix) {
		return nil, fmt.Errorf("kms(aws-kms): token is not an AWS KMS ciphertext")
	}
	req := map[string]string{
		"KeyId":          a.keyID, // scopes the decrypt to the expected key
		"CiphertextBlob": strings.TrimPrefix(token, awsKMSPrefix),
	}
	var out struct {
		Plaintext string `json:"Plaintext"`
	}
	if err := a.call(ctx, "TrentService.Decrypt", req, &out); err != nil {
		return nil, err
	}
	pt, err := base64.StdEncoding.DecodeString(out.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("kms(aws-kms): decode plaintext: %w", err)
	}
	return pt, nil
}

func (a *awsKMS) Health(ctx context.Context) error {
	req := map[string]string{"KeyId": a.keyID}
	var out struct {
		KeyMetadata struct {
			KeyID string `json:"KeyId"`
		} `json:"KeyMetadata"`
	}
	if err := a.call(ctx, "TrentService.DescribeKey", req, &out); err != nil {
		return err
	}
	return nil
}

// call invokes a KMS action (X-Amz-Target) with a JSON body, signing the request
// with SigV4, and decodes the JSON response into out.
func (a *awsKMS) call(ctx context.Context, target string, body any, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	awssig.SignV4(req, buf, a.region, "kms", a.creds, a.now())

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("kms(aws-kms): request failed: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kms(aws-kms): %s -> HTTP %d: %s", target, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("kms(aws-kms): decode response: %w", err)
	}
	return nil
}
