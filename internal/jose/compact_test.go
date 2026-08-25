package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func TestSignVerifyRoundTripES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	header := Header{Algorithm: fapi.ES256, Type: "test+jwt"}
	payload := []byte(`{"hello":"world"}`)

	token, err := Sign(priv, header, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	compact, err := ParseCompact(token)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if compact.Header.Type != "test+jwt" {
		t.Fatalf("Header.Type = %q, want %q", compact.Header.Type, "test+jwt")
	}
	if string(compact.Payload) != string(payload) {
		t.Fatalf("Payload = %q, want %q", compact.Payload, payload)
	}
	if err := compact.Verify(&priv.PublicKey, fapi.ES256); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSignVerifyRoundTripPS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	header := Header{Algorithm: fapi.PS256, Type: "test+jwt"}
	payload := []byte(`{"hello":"world"}`)

	token, err := Sign(priv, header, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	compact, err := ParseCompact(token)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if err := compact.Verify(&priv.PublicKey, fapi.PS256); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	token, err := Sign(priv, Header{Algorithm: fapi.ES256}, []byte(`{"amount":10}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parts := strings.Split(token, ".")
	tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"amount":10000}`))
	tampered := parts[0] + "." + tamperedPayload + "." + parts[2]

	compact, err := ParseCompact(tampered)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if err := compact.Verify(&priv.PublicKey, fapi.ES256); err == nil {
		t.Fatalf("Verify(tampered payload) = nil error, want error")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	token, err := Sign(priv, Header{Algorithm: fapi.ES256}, []byte(`{}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parts := strings.Split(token, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sig[0] ^= 0xFF
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)

	compact, err := ParseCompact(tampered)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if err := compact.Verify(&priv.PublicKey, fapi.ES256); err == nil {
		t.Fatalf("Verify(tampered signature) = nil error, want error")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	token, err := Sign(priv, Header{Algorithm: fapi.ES256}, []byte(`{}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	compact, err := ParseCompact(token)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if err := compact.Verify(&other.PublicKey, fapi.ES256); err == nil {
		t.Fatalf("Verify(wrong key) = nil error, want error")
	}
}

func TestVerifyRejectsAlgorithmMismatch(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	token, err := Sign(priv, Header{Algorithm: fapi.ES256}, []byte(`{}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	compact, err := ParseCompact(token)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if err := compact.Verify(&priv.PublicKey, fapi.PS256); err == nil {
		t.Fatalf("Verify(header alg ES256, expected PS256) = nil error, want error")
	}
}

func TestSignRejectsMismatchedHeaderJWK(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	otherJWK, err := NewJWK(&other.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}

	_, err = Sign(priv, Header{Algorithm: fapi.ES256, JWK: &otherJWK}, []byte(`{}`))
	if err == nil {
		t.Fatalf("Sign with mismatched header jwk = nil error, want error")
	}
}

// TestParseCompactRejectsUnknownCriticalHeaderField covers RFC 7515
// §4.1.11: "crit" naming a Header Parameter this package doesn't
// understand and process makes the whole JWS invalid — an issuer
// marking something critical that this package would otherwise
// silently ignore is exactly the case "crit" exists to catch.
func TestParseCompactRejectsUnknownCriticalHeaderField(t *testing.T) {
	// {"alg":"ES256","crit":["foo"]}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","crit":["foo"]}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	token := header + "." + payload + "." + sig

	if _, err := ParseCompact(token); err == nil {
		t.Fatalf("ParseCompact with unknown critical header field = nil error, want error")
	}
}

// TestParseCompactIgnoresUnknownNonCriticalHeaderField covers RFC 7515
// §4.2/§4.3: a Public or Private Header Parameter Name this package
// doesn't act on (here, a made-up "x5t" — a real issuer's own
// certificate-thumbprint member) must be ignored, not rejected, as
// long as it isn't named in "crit". The header is entirely
// signature-covered, so this can't weaken what Verify checks.
func TestParseCompactIgnoresUnknownNonCriticalHeaderField(t *testing.T) {
	// {"alg":"ES256","x5t":"unused-thumbprint"}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","x5t":"unused-thumbprint"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	token := header + "." + payload + "." + sig

	compact, err := ParseCompact(token)
	if err != nil {
		t.Fatalf("ParseCompact with unknown non-critical header field = %v, want nil error", err)
	}
	if compact.Header.Algorithm != fapi.ES256 {
		t.Fatalf("Header.Algorithm = %v, want ES256", compact.Header.Algorithm)
	}
}

// TestParseCompactAcceptsUnderstoodCriticalHeaderField confirms a
// "crit" list naming only parameters this package does understand
// doesn't reject — crit's job is to catch what would otherwise be
// silently ignored, not to reject a header for expressing normal
// requirements.
func TestParseCompactAcceptsUnderstoodCriticalHeaderField(t *testing.T) {
	// {"alg":"ES256","kid":"key-1","crit":["kid"]}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"key-1","crit":["kid"]}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	sig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	token := header + "." + payload + "." + sig

	compact, err := ParseCompact(token)
	if err != nil {
		t.Fatalf("ParseCompact with understood critical header field = %v, want nil error", err)
	}
	if compact.Header.KeyID != "key-1" {
		t.Fatalf("Header.KeyID = %q, want %q", compact.Header.KeyID, "key-1")
	}
}

func TestParseCompactRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"only-one-part",
		"two.parts",
		"..",
		"a.b.c.d",
	}
	for _, c := range cases {
		if _, err := ParseCompact(c); err == nil {
			t.Fatalf("ParseCompact(%q) = nil error, want error", c)
		}
	}
}

func TestParseCompactRejectsOversized(t *testing.T) {
	huge := strings.Repeat("a", maxCompactBytes+1)
	if _, err := ParseCompact(huge); err == nil {
		t.Fatalf("ParseCompact(oversized) = nil error, want error")
	}
}
