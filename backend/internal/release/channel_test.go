package release

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// serveChannel returns a test server serving a signed index at /channel.json (raw
// signature at /channel.json.sig — decodeSig accepts the raw 64 bytes).
func serveChannel(t *testing.T, idx ChannelIndex, priv ed25519.PrivateKey) *httptest.Server {
	t.Helper()
	body, _ := json.Marshal(idx)
	sig := Sign(body, priv)
	mux := http.NewServeMux()
	mux.HandleFunc("/channel.json", func(w http.ResponseWriter, r *http.Request) { w.Write(body) })
	// Serve the base64 form the `fleetctl release channel` builder writes (EncodeSig),
	// exercising decodeSig's base64 branch end-to-end.
	mux.HandleFunc("/channel.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(EncodeSig(sig))) })
	return httptest.NewServer(mux)
}

func TestFetchChannelAndPick(t *testing.T) {
	pub, priv, _ := GenerateKey()
	idx := ChannelIndex{
		SchemaVersion: ChannelSchema, Latest: "v0.62.0",
		Releases: []ChannelRelease{
			{Version: "v0.60.0", MinFromVersion: "v0.50.0", BundleURL: "http://x/60.fleetup", MigrationCompatibility: "additive"},
			{Version: "v0.62.0", MinFromVersion: "v0.55.0", BundleURL: "http://x/62.fleetup", MigrationCompatibility: "additive"},
			{Version: "v0.61.0", MinFromVersion: "v0.55.0", BundleURL: "http://x/61.fleetup", MigrationCompatibility: "breaking"},
		},
	}
	srv := serveChannel(t, idx, priv)
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	got, err := FetchChannel(context.Background(), client, srv.URL+"/channel.json", []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatalf("FetchChannel: %v", err)
	}
	if up := got.PickUpdate("v0.60.0"); up == nil || up.Version != "v0.62.0" {
		t.Fatalf("PickUpdate(v0.60.0) = %v, want v0.62.0", up)
	}
	if got.PickUpdate("v0.62.0") != nil {
		t.Fatal("PickUpdate(v0.62.0) should be nil (already latest)")
	}
	// Below minFromVersion for the newer releases -> only v0.60.0 qualifies.
	if up := got.PickUpdate("v0.52.0"); up == nil || up.Version != "v0.60.0" {
		t.Fatalf("PickUpdate(v0.52.0) = %v, want v0.60.0 (min gate)", up)
	}
}

func TestFetchChannelRejectsWrongKey(t *testing.T) {
	_, priv, _ := GenerateKey()
	otherPub, _, _ := GenerateKey()
	srv := serveChannel(t, ChannelIndex{SchemaVersion: ChannelSchema, Latest: "v1.0.0"}, priv)
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	if _, err := FetchChannel(context.Background(), client, srv.URL+"/channel.json", []ed25519.PublicKey{otherPub}); err == nil {
		t.Fatal("expected FetchChannel to reject a channel signed by a different key")
	}
}
