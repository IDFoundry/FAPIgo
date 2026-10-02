package clientattestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// FuzzParseClientAttestation exercises Parse against arbitrary strings.
// A Client Attestation JWT is issued out of band by an external
// Attester (this package never creates one, only parses/verifies), and
// is client-supplied at the protocol boundary — parsed before any
// signature is checked. Unlike clientassertion's own claims,
// attestationClaims deliberately tolerates unrecognized fields
// (draft-07 §5.1 rule 1) rather than rejecting them, and carries a
// nested "cnf.jwk" object this package leaves as raw JSON. Also
// decodes the "x5c" header through CertificateChain, which must never
// panic and must keep its bounds.
func FuzzParseClientAttestation(f *testing.F) {
	for _, seed := range clientAttestationSeeds(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, attestation string) {
		a, err := Parse(attestation)
		if err != nil {
			return
		}
		// CertificateChain decodes the untrusted "x5c" header; it must
		// never panic, and never hand back more than the bound or an
		// empty certificate.
		ders, present, err := a.CertificateChain()
		if err != nil || !present {
			return
		}
		if len(ders) == 0 || len(ders) > MaxCertificateChainLength {
			t.Fatalf("CertificateChain returned %d certificates", len(ders))
		}
		for i, der := range ders {
			if len(der) == 0 {
				t.Fatalf("CertificateChain returned an empty certificate at %d", i)
			}
		}
	})
}

// clientAttestationSeeds is FuzzParseClientAttestation's corpus: a valid
// attestation, one with an unrecognized claim, one missing cnf, one with
// an x5c header, and a few malformed strings.
func clientAttestationSeeds(f *testing.F) []string {
	f.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	jwk, err := jose.NewJWK(&key.PublicKey, fapi.ES256)
	if err != nil {
		f.Fatalf("NewJWK: %v", err)
	}
	jwkJSON, err := jwk.MarshalJSON()
	if err != nil {
		f.Fatalf("marshal jwk: %v", err)
	}
	const claims = `{"iss":"https://attester.example","sub":"https://client.example","exp":4102444800`
	cnf := `,"cnf":{"jwk":` + string(jwkJSON) + `}`
	header := jose.Header{Algorithm: fapi.ES256, Type: TypHeader}
	withX5C := header
	withX5C.X5C = []byte(`["MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBBQUAMA0xCzAJBgNVBAYTAlVTMB4X","AAAA"]`)
	sign := func(what string, h jose.Header, payload string) string {
		compact, err := jose.Sign(key, h, []byte(payload))
		if err != nil {
			f.Fatalf("sign %s: %v", what, err)
		}
		return compact
	}
	return []string{
		sign("valid attestation", header, claims+cnf+`}`),
		sign("attestation with unrecognized field", header, claims+cnf+`,"some_future_claim":"ignored"}`),
		sign("attestation missing cnf", header, claims+`}`),
		"", ".", "a.b.c",
		sign("attestation with x5c", withX5C, claims+cnf+`}`),
	}
}
