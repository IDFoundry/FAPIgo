package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// FuzzParseResolveResponse exercises ParseResolveResponse against
// arbitrary strings. A Resolve Response is returned by a Trust Anchor's
// own federation resolve endpoint (OpenID Federation 1.0 §8.3) — an
// external party's response, parsed before any signature is checked.
// Exercises parseResolveResponseClaims' own JSON handling (metadata,
// trust_chain, trust_marks) beyond what jose.ParseCompact's own
// splitting (already covered by internal/jose.FuzzParseCompact) and
// FuzzParseEntityStatement's shared trust_marks parsing reach. Only
// checks for panics/hangs.
func FuzzParseResolveResponse(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	metadata := map[string]json.RawMessage{"openid_relying_party": json.RawMessage(`{"client_name":"fuzz"}`)}

	withoutTrustMarks, err := CreateResolveResponse(CreateResolveResponseParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://trust-anchor.example", Subject: "https://entity.example",
		Now: now, Lifetime: time.Hour,
		Metadata:   metadata,
		TrustChain: []string{"token-a", "token-b"},
	})
	if err != nil {
		f.Fatalf("CreateResolveResponse(without trust marks): %v", err)
	}

	withTrustMarks, err := CreateResolveResponse(CreateResolveResponseParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://trust-anchor.example", Subject: "https://entity.example",
		Now: now, Lifetime: time.Hour,
		Metadata:   metadata,
		TrustChain: []string{"token-a", "token-b"},
		TrustMarks: []RawTrustMark{{TrustMarkType: "https://trust-mark.example", TrustMark: "not-a-real-jwt"}},
	})
	if err != nil {
		f.Fatalf("CreateResolveResponse(with trust marks): %v", err)
	}

	wrongType, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "not-resolve-response+jwt"}, []byte(`{}`))
	if err != nil {
		f.Fatalf("sign wrong-type token: %v", err)
	}

	f.Add(withoutTrustMarks)
	f.Add(withTrustMarks)
	f.Add(wrongType)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, token string) {
		_, _ = ParseResolveResponse(token)
	})
}
