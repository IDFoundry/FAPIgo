package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
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
// so a test can compare loadFixedClientSigner's result
// against ground truth.
func writeTestJWKSFile(t *testing.T, kid string, includePrivate bool) (path string, priv *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk := map[string]string{
		"kty": "EC", "crv": "P-256", "kid": kid,
		"x": base64.RawURLEncoding.EncodeToString(priv.X.FillBytes(make([]byte, 32))),
		"y": base64.RawURLEncoding.EncodeToString(priv.Y.FillBytes(make([]byte, 32))),
	}
	if includePrivate {
		jwk["d"] = base64.RawURLEncoding.EncodeToString(priv.D.FillBytes(make([]byte, 32)))
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

func TestLoadFixedClientSignerRoundTrip(t *testing.T) {
	path, want := writeTestJWKSFile(t, "test-key-1", true)

	got, kid, err := loadFixedClientSigner(path)
	if err != nil {
		t.Fatalf("loadFixedClientSigner() error = %v", err)
	}
	if kid != "test-key-1" {
		t.Errorf("kid = %q, want %q", kid, "test-key-1")
	}
	if got.X.Cmp(want.X) != 0 || got.Y.Cmp(want.Y) != 0 || got.D.Cmp(want.D) != 0 {
		t.Errorf("loaded key does not match the key the file was generated from")
	}
}

func TestLoadFixedClientSignerRejectsPublicOnlyKey(t *testing.T) {
	path, _ := writeTestJWKSFile(t, "test-key-1", false)

	_, _, err := loadFixedClientSigner(path)
	if err == nil {
		t.Fatal("loadFixedClientSigner() = nil error, want error for a public-only key")
	}
	if !strings.Contains(err.Error(), "private component") {
		t.Errorf("error %q does not explain the public-only-key problem", err.Error())
	}
}

func TestLoadFixedClientSignerNoECKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.jwks")
	if err := os.WriteFile(path, []byte(`{"keys":[]}`), 0o600); err != nil {
		t.Fatalf("write jwks file: %v", err)
	}
	if _, _, err := loadFixedClientSigner(path); err == nil {
		t.Fatal("loadFixedClientSigner() = nil error, want error for an empty key set")
	}
}

func TestBuildFixedClientKeyManagerRequiresAFixedKeyPurpose(t *testing.T) {
	path, _ := writeTestJWKSFile(t, "test-key-1", true)
	purposes := map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.DPoPProofSigning: fapi.ES256}

	if _, err := buildFixedClientKeyManager(path, purposes); err == nil {
		t.Fatal("buildFixedClientKeyManager() = nil error, want error (neither ClientAuthentication nor RequestObjectSigning is active)")
	}
}

// TestBuildFixedClientKeyManagerBindsRequestObjectSigningAlone covers
// client_auth_type=mtls combined with a signed request object (JAR) —
// no ClientAuthentication purpose is ever active there (RFC 8705 §2:
// the certificate itself is the credential), so the fixed key must
// still bind to RequestObjectSigning alone, not just ClientAuthentication.
func TestBuildFixedClientKeyManagerBindsRequestObjectSigningAlone(t *testing.T) {
	path, want := writeTestJWKSFile(t, "test-key-1", true)
	purposes := map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.RequestObjectSigning: fapi.ES256,
		keys.DPoPProofSigning:     fapi.ES256,
	}

	mgr, err := buildFixedClientKeyManager(path, purposes)
	if err != nil {
		t.Fatalf("buildFixedClientKeyManager() error = %v", err)
	}

	ctx := context.Background()
	info, err := mgr.PublicKey(ctx, keys.RequestObjectSigning, fapi.ES256)
	if err != nil {
		t.Fatalf("PublicKey(RequestObjectSigning) error = %v", err)
	}
	pub, ok := info.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("RequestObjectSigning public key = %T, want *ecdsa.PublicKey", info.PublicKey)
	}
	if pub.X.Cmp(want.X) != 0 || pub.Y.Cmp(want.Y) != 0 {
		t.Fatal("RequestObjectSigning signer is not the fixed key loaded from the jwks file")
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

// TestLoadFixedClientSignerRefusesMalformedKeys: the private JWK is read
// as strictly as the library reads a public one. A coordinate or scalar
// that isn't 32 octets, a d outside P-256's range, or an x and y that
// aren't d's public key is refused with an error naming the key.
func TestLoadFixedClientSignerRefusesMalformedKeys(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	full := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32))) }
	octets := func(n int, b byte) string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{b}, n)) }
	good := map[string]string{"kty": "EC", "crv": "P-256", "kid": "k", "x": full(priv.X), "y": full(priv.Y), "d": full(priv.D)}
	for _, tc := range []struct {
		name, member, value, wantErr string
	}{
		{"short x", "x", octets(31, 1), "x is 31 octets"},
		{"long y", "y", octets(33, 1), "y is 33 octets"},
		{"short d", "d", octets(31, 1), "d is 31 octets"},
		{"d of zero", "d", octets(32, 0), "d:"},
		{"d above the curve order", "d", octets(32, 0xff), "d:"},
		{"another key's x", "x", full(other.X), "not the public key of d"},
		{"another key's y", "y", full(other.Y), "not the public key of d"},
		{"x not base64url", "x", "!!", "decode x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jwk := map[string]string{}
			for k, v := range good {
				jwk[k] = v
			}
			jwk[tc.member] = tc.value
			body, err := json.Marshal(map[string]any{"keys": []map[string]string{jwk}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "client.jwks")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err = loadFixedClientSigner(path)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), `key "k"`) {
				t.Fatalf("loadFixedClientSigner = %v, want an error naming key \"k\" and containing %q", err, tc.wantErr)
			}
		})
	}
}
