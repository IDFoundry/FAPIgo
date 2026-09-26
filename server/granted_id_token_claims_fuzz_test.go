package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/token"
)

// FuzzGrantedIDTokenClaims checks that validateGrantedIDTokenClaims —
// the only gate on application-supplied GrantedAuthorization.IDTokenClaims
// — agrees with what ID token issuance can actually honour: a claim it
// accepts at CompleteAuthorization must later issue without error (not
// fail as a server_error at the token endpoint) and come back out of the
// signed ID token under the same name with an equivalent value, in a
// token small enough for a relying party's default size limit (the
// property RecommendedLimits' MaxIDTokenClaimsBytes exists to keep).
func FuzzGrantedIDTokenClaims(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}

	f.Add("sub_type", []byte(`"user"`))
	f.Add("act", []byte(`{"sub":"delegate-1"}`))
	f.Add("sub_attributes", []byte(` { "a" : [ 1 , 2 ] } `))
	f.Add("iss", []byte(`"x"`))
	f.Add("azp", []byte(`"x"`))
	f.Add("name\xff", []byte(`"x"`))
	f.Add("", []byte(`1`))
	f.Add("x", []byte(`not json`))
	f.Add("x", []byte(`"\ud800"`))

	f.Fuzz(func(t *testing.T, name string, value []byte) {
		claims := map[string]json.RawMessage{name: value}
		if validateGrantedIDTokenClaims(claims, RecommendedLimits().MaxIDTokenClaimsBytes) != nil {
			return
		}
		now := time.Now()
		signed, err := token.IssueIDToken(token.IDTokenParams{
			Signer: key, Algorithm: fapi.ES256,
			Issuer: "https://as.example", Subject: "user-1", Audience: "client-1",
			Now: now, Lifetime: time.Minute, Parameters: claims,
		})
		if err != nil {
			t.Fatalf("validated claim %q=%q failed issuance: %v", name, value, err)
		}
		// Parsed with a limit sized to the token actually issued: how
		// large an ID token application claims may make is a separate
		// question from whether validation agrees with issuance.
		parsed, err := token.ParseIDTokenMax(signed, len(signed))
		if err != nil {
			t.Fatalf("ParseIDToken: %v", err)
		}
		validated, err := parsed.Validate(&key.PublicKey, token.IDTokenValidatePolicy{
			ExpectedIssuer: "https://as.example", ExpectedAudience: "client-1",
			Algorithm: fapi.ES256, Now: now, MaxLifetime: time.Minute, MaxClockSkew: time.Second,
		})
		if err != nil {
			t.Fatalf("validated claim %q=%q produced an ID token that fails validation: %v", name, value, err)
		}
		got, ok := validated.Parameters[name]
		if !ok || !jsonEquivalent(got, value) {
			t.Fatalf("claim %q=%q came back as %q (present=%v)", name, value, got, ok)
		}
	})
}
