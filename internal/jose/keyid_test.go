package jose

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// TestThumbprintKeyID: a key's thumbprint kid is its RFC 7638 JWK
// thumbprint, base64url without padding — RFC 7638 Appendix A.1's
// worked example — and a key that doesn't fit the algorithm has none.
func TestThumbprintKeyID(t *testing.T) {
	const rfc7638Example = `{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}`
	jwk, err := ParseJWK([]byte(rfc7638Example), fapi.PS256)
	if err != nil {
		t.Fatalf("ParseJWK: %v", err)
	}
	kid, err := ThumbprintKeyID(jwk.PublicKey(), fapi.PS256)
	if err != nil || kid != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("ThumbprintKeyID = %q, %v; want RFC 7638's example thumbprint", kid, err)
	}
	if kid, err := ThumbprintKeyID(jwk.PublicKey(), fapi.ES256); err == nil || kid != "" {
		t.Fatalf("ThumbprintKeyID(an RSA key, ES256) = %q, %v; want no kid and an error", kid, err)
	}
}
