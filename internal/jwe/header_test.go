package jwe

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func TestHeaderRoundTripRSA(t *testing.T) {
	h := Header{Algorithm: fapi.RSAOAEP256, Encryption: fapi.A256GCM, ContentType: "JWT", KeyID: "kid-1"}
	data, err := marshalHeader(h)
	if err != nil {
		t.Fatalf("marshalHeader: %v", err)
	}
	got, err := parseHeader(data)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if got.Algorithm != h.Algorithm || got.Encryption != h.Encryption || got.ContentType != h.ContentType || got.KeyID != h.KeyID {
		t.Fatalf("parseHeader(marshalHeader(h)) = %+v, want %+v", got, h)
	}
	if got.EphemeralPublicKey != nil {
		t.Fatalf("EphemeralPublicKey = %v, want nil for RSAOAEP256", got.EphemeralPublicKey)
	}
}

func TestHeaderRoundTripECDHES(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ephemeral key: %v", err)
	}
	h := Header{Algorithm: fapi.ECDHESA256KW, Encryption: fapi.A256GCM, EphemeralPublicKey: priv.PublicKey()}
	data, err := marshalHeader(h)
	if err != nil {
		t.Fatalf("marshalHeader: %v", err)
	}
	got, err := parseHeader(data)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if got.EphemeralPublicKey == nil {
		t.Fatalf("EphemeralPublicKey is nil, want the parsed epk")
	}
	if !got.EphemeralPublicKey.Equal(priv.PublicKey()) {
		t.Fatalf("EphemeralPublicKey = %x, want %x", got.EphemeralPublicKey.Bytes(), priv.PublicKey().Bytes())
	}
}

// TestParseHeaderIgnoresUnknownField covers RFC 7516 §4.2/§4.3: a
// Public or Private Header Parameter Name this package doesn't act on
// (here, a made-up "unexpected" member — the same shape as a real
// issuer's "x5c" or "iss") must be ignored, not rejected. The header
// is JWE AAD either way, so this can't weaken what Decrypt checks.
func TestParseHeaderIgnoresUnknownField(t *testing.T) {
	data := []byte(`{"alg":"RSA-OAEP-256","enc":"A256GCM","unexpected":"value"}`)
	h, err := parseHeader(data)
	if err != nil {
		t.Fatalf("parseHeader(unknown field) = %v, want nil error", err)
	}
	if h.Algorithm != fapi.RSAOAEP256 || h.Encryption != fapi.A256GCM {
		t.Fatalf("parseHeader(unknown field) = %+v, want alg/enc still parsed", h)
	}
}

// TestParseHeaderRejectsUnknownCriticalField covers the flip side: RFC
// 7516 §4.1.13 (inheriting RFC 7515 §4.1.11) requires rejecting the
// whole header if "crit" names anything this package doesn't
// understand and process — an issuer marking something critical that
// this package silently ignores is exactly the case "crit" exists to
// catch.
func TestParseHeaderRejectsUnknownCriticalField(t *testing.T) {
	data := []byte(`{"alg":"RSA-OAEP-256","enc":"A256GCM","crit":["unexpected"]}`)
	if _, err := parseHeader(data); err == nil {
		t.Fatalf("parseHeader(unknown crit field) = nil error, want error")
	}
}

// TestParseHeaderAcceptsUnderstoodCriticalField confirms a "crit" list
// naming only parameters this package does understand doesn't reject —
// crit's job is to catch what would otherwise be silently ignored, not
// to reject a header for expressing normal requirements.
func TestParseHeaderAcceptsUnderstoodCriticalField(t *testing.T) {
	data := []byte(`{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"key-1","crit":["kid"]}`)
	h, err := parseHeader(data)
	if err != nil {
		t.Fatalf("parseHeader(understood crit field) = %v, want nil error", err)
	}
	if h.KeyID != "key-1" {
		t.Fatalf("KeyID = %q, want %q", h.KeyID, "key-1")
	}
}

func TestParseHeaderRejectsInvalidAlgorithm(t *testing.T) {
	data := []byte(`{"alg":"dir","enc":"A256GCM"}`)
	if _, err := parseHeader(data); err == nil {
		t.Fatalf("parseHeader(alg=dir) = nil error, want error")
	}
}

func TestParseHeaderRejectsInvalidEncryption(t *testing.T) {
	data := []byte(`{"alg":"RSA-OAEP-256","enc":"A128GCM"}`)
	if _, err := parseHeader(data); err == nil {
		t.Fatalf("parseHeader(enc=A128GCM) = nil error, want error")
	}
}

func TestParseHeaderRejectsMalformedEPK(t *testing.T) {
	cases := map[string]string{
		"wrong kty":          `{"alg":"ECDH-ES+A256KW","enc":"A256GCM","epk":{"kty":"RSA","crv":"P-256","x":"AA","y":"AA"}}`,
		"wrong curve":        `{"alg":"ECDH-ES+A256KW","enc":"A256GCM","epk":{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}}`,
		"point not on curve": `{"alg":"ECDH-ES+A256KW","enc":"A256GCM","epk":{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}}`,
		"missing x":          `{"alg":"ECDH-ES+A256KW","enc":"A256GCM","epk":{"kty":"EC","crv":"P-256","x":"","y":"AQ"}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseHeader([]byte(raw)); err == nil {
				t.Fatalf("parseHeader(%s) = nil error, want error", name)
			}
		})
	}
}

// A coordinate many times larger than P-256's field size must be
// rejected as a clean error, not panic FillBytes with "buffer too
// small" — this is untrusted wire input reaching parseEPK.
func TestParseHeaderRejectsOversizedEPKCoordinate(t *testing.T) {
	huge := make([]byte, 256)
	for i := range huge {
		huge[i] = 0xFF
	}
	hugeB64 := base64.RawURLEncoding.EncodeToString(huge)
	raw := `{"alg":"ECDH-ES+A256KW","enc":"A256GCM","epk":{"kty":"EC","crv":"P-256","x":"` + hugeB64 + `","y":"AQ"}}`
	if _, err := parseHeader([]byte(raw)); err == nil {
		t.Fatalf("parseHeader(oversized epk x) = nil error, want error")
	}
}

func TestParseHeaderRejectsMalformedJSON(t *testing.T) {
	if _, err := parseHeader([]byte("not json")); err == nil {
		t.Fatalf("parseHeader(malformed json) = nil error, want error")
	}
}

func TestMarshalHeaderRejectsInvalidAlgorithm(t *testing.T) {
	h := Header{Encryption: fapi.A256GCM}
	if _, err := marshalHeader(h); err == nil {
		t.Fatalf("marshalHeader(zero Algorithm) = nil error, want error")
	}
}

func TestMarshalHeaderRejectsInvalidEncryption(t *testing.T) {
	h := Header{Algorithm: fapi.RSAOAEP256}
	if _, err := marshalHeader(h); err == nil {
		t.Fatalf("marshalHeader(zero Encryption) = nil error, want error")
	}
}
