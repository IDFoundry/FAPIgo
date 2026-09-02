package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
)

// writeTestJWKSFile generates an EC P-256 key, writes it as a JWK Set
// JSON file (mirroring gen-rp-pkjwt-mtls.go's own output shape) into
// t.TempDir, and returns the file path plus the private key it holds,
// so a test can compare loadClientAuthenticationSigner's result
// against ground truth.
func writeTestJWKSFile(t *testing.T, kid string, includePrivate bool) (path string, priv *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk := map[string]string{
		"kty": "EC", "crv": "P-256", "kid": kid,
		"x": base64.RawURLEncoding.EncodeToString(priv.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(priv.Y.Bytes()),
	}
	if includePrivate {
		jwk["d"] = base64.RawURLEncoding.EncodeToString(priv.D.Bytes())
	}
	set := map[string]any{"keys": []map[string]string{jwk}}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	path = filepath.Join(t.TempDir(), "client.jwks")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write jwks file: %v", err)
	}
	return path, priv
}

func TestLoadClientAuthenticationSignerRoundTrip(t *testing.T) {
	path, want := writeTestJWKSFile(t, "test-key-1", true)

	got, kid, err := loadClientAuthenticationSigner(path)
	if err != nil {
		t.Fatalf("loadClientAuthenticationSigner() error = %v", err)
	}
	if kid != "test-key-1" {
		t.Errorf("kid = %q, want %q", kid, "test-key-1")
	}
	if got.X.Cmp(want.X) != 0 || got.Y.Cmp(want.Y) != 0 || got.D.Cmp(want.D) != 0 {
		t.Errorf("loaded key does not match the key the file was generated from")
	}
}

func TestLoadClientAuthenticationSignerRejectsPublicOnlyKey(t *testing.T) {
	path, _ := writeTestJWKSFile(t, "test-key-1", false)

	_, _, err := loadClientAuthenticationSigner(path)
	if err == nil {
		t.Fatal("loadClientAuthenticationSigner() = nil error, want error for a public-only key")
	}
	if !strings.Contains(err.Error(), "private component") {
		t.Errorf("error %q does not explain the public-only-key problem", err.Error())
	}
}

func TestLoadClientAuthenticationSignerNoECKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.jwks")
	if err := os.WriteFile(path, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatalf("write jwks file: %v", err)
	}
	if _, _, err := loadClientAuthenticationSigner(path); err == nil {
		t.Fatal("loadClientAuthenticationSigner() = nil error, want error for an empty key set")
	}
}

func TestBuildFixedClientKeyManagerRequiresClientAuthenticationPurpose(t *testing.T) {
	path, _ := writeTestJWKSFile(t, "test-key-1", true)
	purposes := map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.DPoPProofSigning: fapi.ES256}

	if _, err := buildFixedClientKeyManager(path, purposes); err == nil {
		t.Fatal("buildFixedClientKeyManager() = nil error, want error (no ClientAuthentication purpose)")
	}
}

func TestBuildFixedClientKeyManagerUsesFixedKeyAndEphemeralOthers(t *testing.T) {
	path, want := writeTestJWKSFile(t, "test-key-1", true)
	purposes := map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.ClientAuthentication: fapi.ES256,
		keys.DPoPProofSigning:     fapi.ES256,
	}

	mgr, err := buildFixedClientKeyManager(path, purposes)
	if err != nil {
		t.Fatalf("buildFixedClientKeyManager() error = %v", err)
	}

	ctx := context.Background()
	clientAuthInfo, err := mgr.PublicKey(ctx, keys.ClientAuthentication, fapi.ES256)
	if err != nil {
		t.Fatalf("PublicKey(ClientAuthentication) error = %v", err)
	}
	pub, ok := clientAuthInfo.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("ClientAuthentication public key = %T, want *ecdsa.PublicKey", clientAuthInfo.PublicKey)
	}
	if pub.X.Cmp(want.X) != 0 || pub.Y.Cmp(want.Y) != 0 {
		t.Fatal("ClientAuthentication signer is not the fixed key loaded from the jwks file")
	}

	digest := sha256.Sum256([]byte("dpop-proof-signing-input"))
	sig, err := mgr.Sign(ctx, keys.SigningRequest{Purpose: keys.DPoPProofSigning, Algorithm: fapi.ES256, Digest: digest[:]})
	if err != nil {
		t.Fatalf("Sign(DPoPProofSigning) error = %v — ephemeral key for the non-fixed purpose was not built correctly", err)
	}
	if len(sig.Value) == 0 {
		t.Fatal("Sign(DPoPProofSigning) returned an empty signature")
	}
}
