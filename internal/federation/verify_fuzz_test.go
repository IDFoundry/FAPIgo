package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// FuzzParseEntityStatement exercises Parse against arbitrary strings —
// the least-trusted input boundary in this module: an Entity Statement
// is fetched live from whichever federation participant a
// federation.Resolver is currently walking a Trust Chain through (see
// doc.go), and Parse runs before any signature is checked. Beyond
// jose.ParseCompact itself (already covered by
// internal/jose.FuzzParseCompact), this exercises parseClaims'
// federation-specific JSON handling — metadata, authority_hints,
// metadata_policy, constraints, trust_marks, trust_mark_owners — none
// of which any jose-level fuzz target reaches. Only checks for
// panics/hangs: almost everything the fuzzer generates is expected to
// be rejected, so there is no useful correctness oracle beyond "never
// crashes, never loops".
func FuzzParseEntityStatement(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		f.Fatalf("NewJWK: %v", err)
	}
	jwkJSON, err := jwk.WithKeyID("fuzz-kid").MarshalJSON()
	if err != nil {
		f.Fatalf("marshal jwk: %v", err)
	}
	jwksBody := []byte(`{"keys":[` + string(jwkJSON) + `]}`)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	entityConfig, err := Create(CreateParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://entity.example", Subject: "https://entity.example",
		Now: now, Lifetime: time.Hour,
		JWKS:           jwksBody,
		AuthorityHints: []string{"https://superior.example"},
		TrustMarks:     []RawTrustMark{{TrustMarkType: "https://trust-mark.example", TrustMark: "not-a-real-jwt"}},
		TrustMarkOwners: map[string]TrustMarkOwner{
			"https://trust-mark.example": {Subject: "https://owner.example", JWKS: jwksBody},
		},
	})
	if err != nil {
		f.Fatalf("Create(entity config): %v", err)
	}

	hasMaxPathLength := true
	subordinate, err := Create(CreateParams{
		Signer: key, Algorithm: fapi.ES256, KeyID: "fuzz-kid",
		Issuer: "https://superior.example", Subject: "https://entity.example",
		Now: now, Lifetime: time.Hour,
		JWKS:           jwksBody,
		SourceEndpoint: "https://superior.example/fetch",
		MetadataPolicy: MetadataPolicy{
			"openid_relying_party": {"subject_type": {"value": []byte(`"pairwise"`)}},
		},
		Constraints: &Constraints{
			MaxPathLength: 1, HasMaxPathLength: hasMaxPathLength,
			AllowedEntityTypes: []string{"openid_relying_party"},
		},
	})
	if err != nil {
		f.Fatalf("Create(subordinate statement): %v", err)
	}

	wrongType, err := jose.Sign(key, jose.Header{Algorithm: fapi.ES256, Type: "not-entity-statement+jwt"}, []byte(`{}`))
	if err != nil {
		f.Fatalf("sign wrong-type token: %v", err)
	}

	f.Add(entityConfig)
	f.Add(subordinate)
	f.Add(wrongType)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, token string) {
		_, _ = Parse(token)
	})
}
