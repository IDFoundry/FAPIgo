package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func generateEC(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	return key
}

func generateRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return key
}

func TestJWKMarshalJSONOmitsKidByDefault(t *testing.T) {
	priv := generateEC(t)
	jwk, err := NewJWK(&priv.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	data, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["kid"]; ok {
		t.Fatalf("MarshalJSON output contains \"kid\" without WithKeyID: %s", data)
	}
}

func TestJWKWithKeyIDIncludesKid(t *testing.T) {
	priv := generateEC(t)
	jwk, err := NewJWK(&priv.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	data, err := jwk.WithKeyID("key-1").MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["kid"] != "key-1" {
		t.Fatalf("kid = %v, want %q", m["kid"], "key-1")
	}
}

func TestJWKWithKeyIDDoesNotMutateOriginal(t *testing.T) {
	priv := generateEC(t)
	jwk, err := NewJWK(&priv.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	_ = jwk.WithKeyID("key-1")

	data, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["kid"]; ok {
		t.Fatalf("original JWK was mutated by WithKeyID: %s", data)
	}
}

func TestJWKRoundTripEC(t *testing.T) {
	priv := generateEC(t)
	jwk, err := NewJWK(&priv.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	data, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	parsed, err := ParseJWK(data, fapi.ES256)
	if err != nil {
		t.Fatalf("ParseJWK: %v", err)
	}
	pub, ok := parsed.PublicKey().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey() type = %T, want *ecdsa.PublicKey", parsed.PublicKey())
	}
	if !pub.Equal(&priv.PublicKey) {
		t.Fatalf("round-tripped key does not equal original")
	}

	tp1, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	tp2, err := parsed.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint (parsed): %v", err)
	}
	if !tp1.Equal(tp2) {
		t.Fatalf("thumbprints differ after round trip: %s vs %s", tp1, tp2)
	}
}

func TestJWKRoundTripRSA(t *testing.T) {
	priv := generateRSA(t)
	jwk, err := NewJWK(&priv.PublicKey, fapi.PS256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	data, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	parsed, err := ParseJWK(data, fapi.PS256)
	if err != nil {
		t.Fatalf("ParseJWK: %v", err)
	}
	pub, ok := parsed.PublicKey().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey() type = %T, want *rsa.PublicKey", parsed.PublicKey())
	}
	if !pub.Equal(&priv.PublicKey) {
		t.Fatalf("round-tripped key does not equal original")
	}
}

// TestJWKRoundTripOKP checks the exact wire shape RFC 8037 §2 requires
// for an Ed25519 public key — kty="OKP", crv="Ed25519", "x" only, no
// "y"/"n"/"e" the way EC/RSA JWKs carry — not just that MarshalJSON and
// ParseJWK happen to agree with each other, which a bug in both
// wouldn't catch.
func TestJWKRoundTripOKP(t *testing.T) {
	pub, _ := generateEd25519Key(t)
	jwk, err := NewJWK(pub, fapi.EdDSA)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	data, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["kty"] != "OKP" {
		t.Fatalf(`m["kty"] = %v, want "OKP"`, m["kty"])
	}
	if m["crv"] != "Ed25519" {
		t.Fatalf(`m["crv"] = %v, want "Ed25519"`, m["crv"])
	}
	if m["x"] != base64.RawURLEncoding.EncodeToString(pub) {
		t.Fatalf(`m["x"] = %v, want %q`, m["x"], base64.RawURLEncoding.EncodeToString(pub))
	}
	for _, member := range []string{"y", "n", "e"} {
		if _, ok := m[member]; ok {
			t.Fatalf("MarshalJSON output unexpectedly contains %q: %s", member, data)
		}
	}

	parsed, err := ParseJWK(data, fapi.EdDSA)
	if err != nil {
		t.Fatalf("ParseJWK: %v", err)
	}
	parsedPub, ok := parsed.PublicKey().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("PublicKey() type = %T, want ed25519.PublicKey", parsed.PublicKey())
	}
	if !parsedPub.Equal(pub) {
		t.Fatalf("round-tripped key does not equal original")
	}

	tp1, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	tp2, err := parsed.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint (parsed): %v", err)
	}
	if !tp1.Equal(tp2) {
		t.Fatalf("thumbprints differ before/after round trip: %s vs %s", tp1, tp2)
	}
}

func TestParseJWKRejectsMalformedOKPCoordinates(t *testing.T) {
	cases := map[string]string{
		"wrong curve": `{"kty":"OKP","crv":"X25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		"missing x":   `{"kty":"OKP","crv":"Ed25519"}`,
		"empty x":     `{"kty":"OKP","crv":"Ed25519","x":""}`,
		"short x":     `{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`,
		"invalid b64": `{"kty":"OKP","crv":"Ed25519","x":"not-valid-base64url!!"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseJWK([]byte(raw), fapi.EdDSA); err == nil {
				t.Fatalf("ParseJWK(%s) = nil error, want error", name)
			}
		})
	}
}

func TestJWKRejectsWrongAlgorithm(t *testing.T) {
	ecKey := generateEC(t)
	if _, err := NewJWK(&ecKey.PublicKey, fapi.PS256); err == nil {
		t.Fatalf("NewJWK(ec key, PS256) = nil error, want error")
	}

	rsaKey := generateRSA(t)
	if _, err := NewJWK(&rsaKey.PublicKey, fapi.ES256); err == nil {
		t.Fatalf("NewJWK(rsa key, ES256) = nil error, want error")
	}

	edPub, _ := generateEd25519Key(t)
	if _, err := NewJWK(edPub, fapi.ES256); err == nil {
		t.Fatalf("NewJWK(ed25519 key, ES256) = nil error, want error")
	}
	if _, err := NewJWK(&ecKey.PublicKey, fapi.EdDSA); err == nil {
		t.Fatalf("NewJWK(ec key, EdDSA) = nil error, want error")
	}
}

func TestJWKRejectsSmallRSAKey(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate small rsa key: %v", err)
	}
	if _, err := NewJWK(&small.PublicKey, fapi.PS256); err == nil {
		t.Fatalf("NewJWK(1024-bit rsa key, PS256) = nil error, want error")
	}
}

func TestParseJWKRejectsDegenerateRSAExponent(t *testing.T) {
	rsaKey := generateRSA(t)
	n := base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes())

	cases := map[string]string{
		"e = 1 (AQ)": "AQ",
		"e = 2 (Ag)": "Ag",
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			raw := fmt.Sprintf(`{"kty":"RSA","n":%q,"e":%q}`, n, e)
			if _, err := ParseJWK([]byte(raw), fapi.PS256); err == nil {
				t.Fatalf("ParseJWK(e=%s) = nil error, want error", e)
			}
		})
	}

	// e = 65537 (0x10001), the typical RSA public exponent, must still
	// be accepted.
	raw := fmt.Sprintf(`{"kty":"RSA","n":%q,"e":"AQAB"}`, n)
	if _, err := ParseJWK([]byte(raw), fapi.PS256); err != nil {
		t.Fatalf("ParseJWK(e=65537): %v", err)
	}
}

func TestJWKRejectsPrivateKeyMaterial(t *testing.T) {
	priv := generateEC(t)
	jwk, err := NewJWK(&priv.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	data, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["d"] = "sensitive-private-value"
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := ParseJWK(tampered, fapi.ES256); err == nil {
		t.Fatalf("ParseJWK with injected \"d\" member = nil error, want ErrPrivateKeyMaterial")
	}
}

func TestJWKRejectsCertificateChain(t *testing.T) {
	priv := generateEC(t)
	jwk, err := NewJWK(&priv.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	data, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["x5c"] = []string{"deadbeef"}
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := ParseJWK(tampered, fapi.ES256); err == nil {
		t.Fatalf("ParseJWK with injected \"x5c\" member = nil error, want ErrCertificateChain")
	}
}

func TestJWKRejectsUnknownMember(t *testing.T) {
	priv := generateEC(t)
	jwk, err := NewJWK(&priv.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	data, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["unexpected_extension"] = "value"
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := ParseJWK(tampered, fapi.ES256); err == nil {
		t.Fatalf("ParseJWK with unknown member = nil error, want error")
	}
}

// TestJWKThumbprintRSAKnownAnswer checks the RSA thumbprint canonical
// form against the worked example from RFC 7638 Appendix A.1.
func TestJWKThumbprintRSAKnownAnswer(t *testing.T) {
	const rsaJWK = `{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`
	const wantThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	jwk, err := ParseJWK([]byte(rsaJWK), fapi.PS256)
	if err != nil {
		t.Fatalf("ParseJWK: %v", err)
	}
	tp, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if got := tp.String(); got != wantThumbprint {
		t.Fatalf("Thumbprint = %q, want %q", got, wantThumbprint)
	}
}
