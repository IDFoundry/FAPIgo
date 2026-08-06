package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	fapi "github.com/osanderson/go-fapi"
)

// TestSignEmbedsMatchingHeaderJWK covers the header.JWK-embedding branch
// of marshalHeader (and, on the read side, parseHeader's matching
// branch) directly — DPoP's own proof creation exercises this same code
// path, but that's a different package, so it doesn't count toward this
// package's own coverage; this proves the embedding round-trips
// correctly using only jose's public API.
func TestSignEmbedsMatchingHeaderJWK(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk, err := NewJWK(&priv.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}

	token, err := Sign(priv, Header{Algorithm: fapi.ES256, Type: "dpop+jwt", JWK: &jwk}, []byte(`{}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	compact, err := ParseCompact(token)
	if err != nil {
		t.Fatalf("ParseCompact: %v", err)
	}
	if compact.Header.JWK == nil {
		t.Fatalf("parsed header has no embedded JWK")
	}
	pub, ok := compact.Header.JWK.PublicKey().(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&priv.PublicKey) {
		t.Fatalf("embedded JWK public key does not match signer")
	}
	if err := compact.Verify(&priv.PublicKey, fapi.ES256); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSignRejectsInvalidAlgorithm(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := Sign(priv, Header{Algorithm: 0}, []byte(`{}`)); err == nil {
		t.Fatalf("Sign(invalid algorithm) = nil error, want error")
	}
}

func TestSignRejectsNilSigner(t *testing.T) {
	if _, err := Sign(nil, Header{Algorithm: fapi.ES256}, []byte(`{}`)); err == nil {
		t.Fatalf("Sign(nil signer) = nil error, want error")
	}
}

func TestJWKAlgorithm(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk, err := NewJWK(&priv.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("NewJWK: %v", err)
	}
	if jwk.Algorithm() != fapi.ES256 {
		t.Fatalf("Algorithm() = %v, want ES256", jwk.Algorithm())
	}
}

func TestNewJWKRejectsWrongCurve(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p384 key: %v", err)
	}
	if _, err := NewJWK(&priv.PublicKey, fapi.ES256); err == nil {
		t.Fatalf("NewJWK(P-384 key, ES256) = nil error, want error")
	}
}

func TestParseJWKRejectsUnsupportedCurve(t *testing.T) {
	raw := `{"kty":"EC","crv":"P-384","x":"AAAA","y":"AAAA"}`
	if _, err := ParseJWK([]byte(raw), fapi.ES256); err == nil {
		t.Fatalf("ParseJWK(unsupported curve) = nil error, want error")
	}
}

func TestParseJWKRejectsUnsupportedKeyType(t *testing.T) {
	raw := `{"kty":"oct","k":"AAAA"}`
	if _, err := ParseJWK([]byte(raw), fapi.ES256); err == nil {
		t.Fatalf("ParseJWK(kty=oct) = nil error, want error")
	}
}

func TestParseJWKRejectsMalformedECCoordinates(t *testing.T) {
	cases := map[string]string{
		"bad x":   `{"kty":"EC","crv":"P-256","x":"not-base64!!","y":"AAAA"}`,
		"bad y":   `{"kty":"EC","crv":"P-256","x":"AAAA","y":"not-base64!!"}`,
		"empty x": `{"kty":"EC","crv":"P-256","x":"","y":"AAAA"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseJWK([]byte(raw), fapi.ES256); err == nil {
				t.Fatalf("ParseJWK(%s) = nil error, want error", name)
			}
		})
	}
}

func TestParseJWKRejectsMalformedRSACoordinates(t *testing.T) {
	cases := map[string]string{
		"bad n":          `{"kty":"RSA","n":"not-base64!!","e":"AQAB"}`,
		"bad e":          `{"kty":"RSA","n":"AAAA","e":"not-base64!!"}`,
		"e out of range": `{"kty":"RSA","n":"AAAA","e":"////////////////////////////////"}`,
		"e zero":         `{"kty":"RSA","n":"AAAA","e":"AA"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseJWK([]byte(raw), fapi.PS256); err == nil {
				t.Fatalf("ParseJWK(%s) = nil error, want error", name)
			}
		})
	}
}

func TestParseJWKRejectsPointAtInfinityAndOffCurve(t *testing.T) {
	cases := map[string]string{
		"point at infinity":  `{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
		"point not on curve": `{"kty":"EC","crv":"P-256","x":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","y":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseJWK([]byte(raw), fapi.ES256); err == nil {
				t.Fatalf("ParseJWK(%s) = nil error, want error", name)
			}
		})
	}
}

// The following call signECDSA/verifyECDSA/signRSAPSS/verifyRSAPSS
// directly (this file is part of package jose) to exercise their own
// key-type guards precisely, rather than trying to coax Sign/Verify's
// higher-level algorithm dispatch into reaching them indirectly.

func TestSignECDSARejectsNonECDSASigner(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	if _, err := signECDSA(rsaPriv, make([]byte, 32)); err == nil {
		t.Fatalf("signECDSA(rsa signer) = nil error, want error")
	}
}

func TestSignECDSARejectsWrongCurve(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate p384 key: %v", err)
	}
	if _, err := signECDSA(priv, make([]byte, 32)); err == nil {
		t.Fatalf("signECDSA(P-384 key) = nil error, want error")
	}
}

func TestVerifyECDSARejectsNonECDSAKey(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	if err := verifyECDSA(&rsaPriv.PublicKey, make([]byte, 32), make([]byte, 64)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("verifyECDSA(rsa public key) = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyECDSARejectsWrongSignatureLength(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := verifyECDSA(&priv.PublicKey, make([]byte, 32), make([]byte, 10)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("verifyECDSA(wrong-length sig) = %v, want ErrInvalidSignature", err)
	}
}

func TestSignRSAPSSRejectsNonRSASigner(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := signRSAPSS(priv, make([]byte, 32)); err == nil {
		t.Fatalf("signRSAPSS(ecdsa signer) = nil error, want error")
	}
}

func TestSignRSAPSSRejectsSmallKey(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate small rsa key: %v", err)
	}
	if _, err := signRSAPSS(small, make([]byte, 32)); err == nil {
		t.Fatalf("signRSAPSS(1024-bit key) = nil error, want error")
	}
}

func TestVerifyRSAPSSRejectsNonRSAKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := verifyRSAPSS(&priv.PublicKey, make([]byte, 32), make([]byte, 32)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("verifyRSAPSS(ecdsa public key) = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRSAPSSRejectsBadSignature(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	if err := verifyRSAPSS(&priv.PublicKey, make([]byte, 32), make([]byte, 256)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("verifyRSAPSS(garbage signature) = %v, want ErrInvalidSignature", err)
	}
}
