package federation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

// shortCoordinateJWKS is a JWK Set whose only entry, kid "k", writes x
// without its leading octet, which RFC 7518 §6.2.1.2 forbids, so the
// entry is skipped.
func shortCoordinateJWKS(t *testing.T) json.RawMessage {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := key.X.FillBytes(make([]byte, 32))[1:]
	y := key.Y.FillBytes(make([]byte, 32))
	return json.RawMessage(fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","kid":"k","x":%q,"y":%q}]}`,
		base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y)))
}

// TestNoCandidateKeySaysWhyTheEntryWasSkipped: when the only entry with
// a statement's kid was skipped, the "no candidate key" error says why,
// so an operator reading OnResolutionFailure sees the malformed entry,
// not just a kid the set seems to list. A kid no entry has gets no such
// note.
func TestNoCandidateKeySaysWhyTheEntryWasSkipped(t *testing.T) {
	jwks := shortCoordinateJWKS(t)
	verify := func(crypto.PublicKey) (struct{}, error) { return struct{}{}, nil }
	_, err := verifyAgainstCandidateKeys(jwks, "k", fapi.ES256, verify)
	if err == nil || !strings.Contains(err.Error(), `entry with kid "k" was skipped`) || !strings.Contains(err.Error(), "octets") {
		t.Fatalf("verifyAgainstCandidateKeys = %v, want the skipped entry's reason", err)
	}
	_, err = verifyAgainstCandidateKeys(jwks, "other", fapi.ES256, verify)
	if err == nil || strings.Contains(err.Error(), "skipped") {
		t.Fatalf("verifyAgainstCandidateKeys(another kid) = %v, want no note about the skipped entry", err)
	}
}

// TestNoUsableRPKeySaysWhyEntriesWereSkipped: an RP JWK Set left with no
// usable key says which entries were skipped and why, for the
// certificate checks of both mTLS client authentication methods.
func TestNoUsableRPKeySaysWhyEntriesWereSkipped(t *testing.T) {
	jwks := shortCoordinateJWKS(t)
	if _, err := keyThumbprintsFromJWKS(jwks); err == nil || !strings.Contains(err.Error(), `1 JWK Set entries were skipped (kid "k":`) {
		t.Errorf("keyThumbprintsFromJWKS = %v, want the skipped entry named", err)
	}
	if _, err := certificateThumbprintsFromJWKS(jwks); err == nil || !strings.Contains(err.Error(), `1 JWK Set entries were skipped (kid "k":`) {
		t.Errorf("certificateThumbprintsFromJWKS = %v, want the skipped entry named", err)
	}
}
