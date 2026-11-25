package federation_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/internal/rendertest"
)

// ed25519Issuers is one of each issuer, signing with a fresh
// ed25519.PrivateKey, and that key's seed.
func ed25519Issuers(t *testing.T) (map[string]any, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "x": base64.RawURLEncoding.EncodeToString(pub)}}})
	if err != nil {
		t.Fatal(err)
	}
	const id = "https://entity.example"
	clock := federation.SystemClock{}
	issuers := map[string]any{}
	add := func(name string, v any, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("New%s: %v", name, err)
		}
		issuers[name] = v
	}
	h, err := federation.NewHistoricalKeysIssuer(federation.HistoricalKeysIssueConfig{EntityID: id},
		federation.HistoricalKeysIssueDependencies{Signer: key, Algorithm: fapi.EdDSA, KeyID: "k1", Clock: clock})
	add("HistoricalKeysIssuer", h, err)
	r, err := federation.NewResolveIssuer(federation.ResolveIssueConfig{EntityID: id},
		federation.ResolveIssueDependencies{Signer: key, Algorithm: fapi.EdDSA, KeyID: "k1", Clock: clock})
	add("ResolveIssuer", r, err)
	s, err := federation.NewSelfIssuer(federation.SelfIssueConfig{EntityID: id, Lifetime: time.Hour},
		federation.SelfIssueDependencies{Signer: key, Algorithm: fapi.EdDSA, KeyID: "k1", JWKS: jwks, Clock: clock})
	add("SelfIssuer", s, err)
	sub, err := federation.NewSubordinateIssuer(federation.SubordinateIssueConfig{EntityID: id, Lifetime: time.Hour},
		federation.SubordinateIssueDependencies{Signer: key, Algorithm: fapi.EdDSA, KeyID: "k1", Clock: clock})
	add("SubordinateIssuer", sub, err)
	tm, err := federation.NewTrustMarkIssuer(federation.TrustMarkIssueConfig{EntityID: id},
		federation.TrustMarkIssueDependencies{Signer: key, Algorithm: fapi.EdDSA, KeyID: "k1", Clock: clock})
	add("TrustMarkIssuer", tm, err)
	return issuers, string(key.Seed())
}

// TestIssuersPrintNoKey: each issuer, signing with an
// ed25519.PrivateKey, a byte slice fmt would print whole, prints and
// logs its config and dependencies with [REDACTED] for the Signer,
// under every rendering the matrix makes, fmt's reflection fallback
// included.
func TestIssuersPrintNoKey(t *testing.T) {
	issuers, seed := ed25519Issuers(t)
	for name, issuer := range issuers {
		rendertest.Check(t, issuer, []string{seed}, rendertest.Quick())
		out := fmt.Sprintf("%+v", issuer)
		if !strings.Contains(out, "Dependencies:{Signer:[REDACTED] Algorithm:EdDSA KeyID:k1") || !strings.Contains(out, "Config:{EntityID:https://entity.example") {
			t.Errorf("%s: %%+v = %q, want its config and redacted dependencies", name, out)
		}
		if got := fmt.Sprintf("%#v", issuer); !strings.HasPrefix(got, "federation."+name+"{") {
			t.Errorf("%s: %%#v = %q, want the real type's name", name, got)
		}
		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("issuer", "v", issuer)
		if got := buf.String(); !strings.Contains(got, `"Dependencies":{"Signer":"[REDACTED]","Algorithm":"EdDSA","KeyID":"k1"`) {
			t.Errorf("%s: slog JSON logged %s, want its redacted dependencies", name, got)
		}
	}
}
