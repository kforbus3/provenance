package extsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kforbus3/provenance/backend/internal/awssig"
)

// awsSecrets reads secrets from AWS Secrets Manager (GetSecretValue). A reference is a
// secret name or ARN, optionally with "#field" to extract one key when the secret's
// value is a JSON object (e.g. "prod/db#password"). Implemented against the JSON API
// with the shared SigV4 signer — no AWS SDK. An endpoint override supports emulators
// (LocalStack).
type awsSecrets struct {
	endpoint string
	region   string
	creds    awssig.Creds
	client   *http.Client
	now      func() time.Time
}

func newAWSSecrets(cfg Config) (Provider, error) {
	region := strings.TrimSpace(cfg.AWSRegion)
	if region == "" {
		return nil, fmt.Errorf("extsecret(aws-secrets): PROV_EXTSECRET_AWS_REGION is required")
	}
	if strings.TrimSpace(cfg.AWSAccessKey) == "" || strings.TrimSpace(cfg.AWSSecretKey) == "" {
		return nil, fmt.Errorf("extsecret(aws-secrets): PROV_EXTSECRET_AWS_ACCESS_KEY_ID and PROV_EXTSECRET_AWS_SECRET_ACCESS_KEY are required")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.AWSEndpoint), "/")
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://secretsmanager.%s.amazonaws.com", region)
	}
	return &awsSecrets{
		endpoint: endpoint,
		region:   region,
		creds:    awssig.Creds{AccessKey: cfg.AWSAccessKey, SecretKey: cfg.AWSSecretKey, SessionToken: cfg.AWSSessionToken},
		client:   &http.Client{Timeout: 15 * time.Second},
		now:      time.Now,
	}, nil
}

func (a *awsSecrets) Name() string { return ProviderAWSSecrets }

func (a *awsSecrets) Fetch(ctx context.Context, ref string) (string, error) {
	secretID, field := splitRef(ref)
	if secretID == "" {
		return "", fmt.Errorf("extsecret(aws-secrets): empty secret reference")
	}
	var out struct {
		SecretString string `json:"SecretString"`
	}
	if err := a.call(ctx, "secretsmanager.GetSecretValue", map[string]string{"SecretId": secretID}, &out); err != nil {
		return "", err
	}
	if field == "" {
		return out.SecretString, nil
	}
	// Extract one field from a JSON-valued secret.
	var m map[string]any
	if err := json.Unmarshal([]byte(out.SecretString), &m); err != nil {
		return "", fmt.Errorf("extsecret(aws-secrets): secret is not JSON but a #field was requested")
	}
	v, ok := m[field]
	if !ok {
		return "", fmt.Errorf("extsecret(aws-secrets): field %q not found in secret", field)
	}
	return toString(v), nil
}

func (a *awsSecrets) Health(ctx context.Context) error {
	// ListSecrets with MaxResults=1 verifies credentials and reachability.
	return a.call(ctx, "secretsmanager.ListSecrets", map[string]int{"MaxResults": 1}, nil)
}

func (a *awsSecrets) call(ctx context.Context, target string, body any, out any) error {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	awssig.SignV4(req, buf, a.region, "secretsmanager", a.creds, a.now())

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("extsecret(aws-secrets): request failed: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("extsecret(aws-secrets): %s -> HTTP %d: %s", target, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("extsecret(aws-secrets): decode response: %w", err)
		}
	}
	return nil
}

// Store creates a secret with CreateSecret, which fails if the name already
// exists rather than adding a version to it.
//
// CreateSecret and not PutSecretValue on purpose: PutSecretValue would append a
// new version to whatever is already there, and the thing already there would be
// another image's LUKS recovery passphrase. A new version does not destroy the
// old one in Secrets Manager, but it does change what a plain read returns — so
// the recovery key for machines in the field would silently stop being the one
// this path hands back.
//
// The fields are stored as a JSON object in SecretString, matching how Fetch
// reads them back ("secret-id#field").
func (a *awsSecrets) Store(ctx context.Context, ref string, fields map[string]string) error {
	secretID, _ := splitRef(ref)
	if strings.TrimSpace(secretID) == "" {
		return fmt.Errorf("extsecret(aws-secrets): a secret id is required")
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	var out struct {
		ARN string `json:"ARN"`
	}
	body := map[string]string{"Name": secretID, "SecretString": string(payload)}
	if err := a.call(ctx, "secretsmanager.CreateSecret", body, &out); err != nil {
		// The API's own name for "it is already there"; surfaced as the same
		// refusal the Vault path gives so the caller can treat them alike.
		if strings.Contains(err.Error(), "ResourceExistsException") {
			return fmt.Errorf("extsecret(aws-secrets): %s already exists; refusing to overwrite it", secretID)
		}
		return err
	}
	return nil
}
