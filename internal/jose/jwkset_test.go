package jose

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// rawKeySetJSON marshals jwk (via its own MarshalJSON, which never
// includes "alg" — see JWK.MarshalJSON's own doc comment) and applies
// edits to the resulting member map before re-marshaling, then wraps it
// in a one-entry `{"keys": [...]}` JWK Set body. edits == nil leaves
// the marshaled JWK untouched.
func rawKeySetEntry(t *testing.T, jwk JWK, edits map[string]any) json.RawMessage {
	t.Helper()
	data, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if len(edits) == 0 {
		return data
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal for edit: %v", err)
	}
	for k, v := range edits {
		if v == nil {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	return out
}

func jwkSetBody(t *testing.T, entries ...json.RawMessage) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		t.Fatalf("marshal jwks body: %v", err)
	}
	return body
}

// TestParseJWKSetInfersAlgorithmFromKtyAndCrv covers the common case:
// this package's own MarshalJSON never emits "alg" (see its own doc
// comment), so a JWK Set built from this library's own PublicJWKS
// output always relies on ParseJWKSet's kty/crv-based inference, not
// an explicit hint.
func TestParseJWKSetInfersAlgorithmFromKtyAndCrv(t *testing.T) {
	ecPriv := generateEC(t)
	ecJWK, err := NewJWK(&ecPriv.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK (EC): %v", err)
	}
	ecEntry := rawKeySetEntry(t, ecJWK.WithKeyID("ec-kid"), nil)

	rsaPriv := generateRSA(t)
	rsaJWK, err := NewJWK(&rsaPriv.PublicKey, fapi.PS256)
	if err != nil {
		t.Fatalf("NewJWK (RSA): %v", err)
	}
	rsaEntry := rawKeySetEntry(t, rsaJWK.WithKeyID("rsa-kid"), nil)

	parsed, err := ParseJWKSet(jwkSetBody(t, ecEntry, rsaEntry))
	if err != nil {
		t.Fatalf("ParseJWKSet: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("len(parsed) = %d, want 2", len(parsed))
	}
	if parsed[0].KeyID != "ec-kid" || parsed[0].Algorithm != fapi.ES256 {
		t.Fatalf("parsed[0] = %+v, want kid=ec-kid alg=ES256", parsed[0])
	}
	if _, ok := parsed[0].PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("parsed[0].PublicKey type = %T, want *ecdsa.PublicKey", parsed[0].PublicKey)
	}
	if parsed[1].KeyID != "rsa-kid" || parsed[1].Algorithm != fapi.PS256 {
		t.Fatalf("parsed[1] = %+v, want kid=rsa-kid alg=PS256", parsed[1])
	}
	if _, ok := parsed[1].PublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("parsed[1].PublicKey type = %T, want *rsa.PublicKey", parsed[1].PublicKey)
	}
}

// TestParseJWKSetUsesExplicitAlgorithmHint covers the other server's
// JWKS case: a document that does carry "alg" (common for
// interoperability with issuers other than this library).
func TestParseJWKSetUsesExplicitAlgorithmHint(t *testing.T) {
	priv := generateEC(t)
	jwk, err := NewJWK(&priv.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	entry := rawKeySetEntry(t, jwk.WithKeyID("explicit-alg"), map[string]any{"alg": "ES256"})

	parsed, err := ParseJWKSet(jwkSetBody(t, entry))
	if err != nil {
		t.Fatalf("ParseJWKSet: %v", err)
	}
	if len(parsed) != 1 || parsed[0].KeyID != "explicit-alg" || parsed[0].Algorithm != fapi.ES256 {
		t.Fatalf("parsed = %+v, want one entry kid=explicit-alg alg=ES256", parsed)
	}
}

// TestParseJWKSetSkipsMalformedAndUnsupportedEntries covers
// ParseJWKSet's core contract (see its own doc comment): one bad entry
// must not invalidate an otherwise usable set. Mixes a valid key with
// three ways an entry can go wrong, and confirms only the valid one
// survives.
func TestParseJWKSetSkipsMalformedAndUnsupportedEntries(t *testing.T) {
	priv := generateEC(t)
	jwk, err := NewJWK(&priv.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	validEntry := rawKeySetEntry(t, jwk.WithKeyID("valid"), nil)

	unrecognizedKty := json.RawMessage(`{"kty":"oct","k":"c2VjcmV0"}`) // symmetric key: no ParseJWKSet path accepts this kty
	unrecognizedAlg := json.RawMessage(`{"kty":"EC","crv":"P-256","alg":"not-a-real-alg","x":"AA","y":"AA"}`)
	notJSON := json.RawMessage(`"just a string, not a key object"`)

	parsed, err := ParseJWKSet(jwkSetBody(t, unrecognizedKty, unrecognizedAlg, notJSON, validEntry))
	if err != nil {
		t.Fatalf("ParseJWKSet: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("len(parsed) = %d, want 1 (only the valid entry); got %+v", len(parsed), parsed)
	}
	if parsed[0].KeyID != "valid" {
		t.Fatalf("parsed[0].KeyID = %q, want %q", parsed[0].KeyID, "valid")
	}
}

// TestParseJWKSetRejectsMalformedTopLevelJSON covers the one error
// ParseJWKSet itself returns, as opposed to silently skipping — the
// top-level body isn't a JWK Set at all.
func TestParseJWKSetRejectsMalformedTopLevelJSON(t *testing.T) {
	if _, err := ParseJWKSet([]byte(`not json`)); err == nil {
		t.Fatalf("ParseJWKSet(not json) = nil error, want error")
	}
}
