package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/canonical"
)

// FuzzVerifyDPoPProofClaimMismatch checks a property FuzzVerifyDPoPProof
// deliberately doesn't: not just "does Verify avoid panicking on
// arbitrary bytes", but "does Verify's semantic claim matching actually
// reject a genuinely, validly-signed proof whose htm/htu/ath/nonce claim
// doesn't match what the request actually was". A proof built purely
// from fuzzed strings almost never reaches this check at all — it fails
// signature verification or JSON parsing first. This target instead
// builds a real proof via CreateProof for a request that differs from
// the fixed VerifyRequest in exactly one field, guaranteeing (by
// skipping any fuzzer-chosen value that would coincidentally still
// compare equal, e.g. two URLs that canonicalize the same way) that the
// mismatch is real, then asserts Verify rejects it. This is the kind of
// bug class byte-tampering can't reach: e.g. an accidental case-fold, a
// substring match where an exact match was intended, or a comparison
// against the wrong field entirely.
func FuzzVerifyDPoPProofClaimMismatch(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	baseURL, err := url.Parse("https://as.example/token")
	if err != nil {
		f.Fatalf("parse url: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const baseMethod = "POST"
	const baseAccessToken = "base-access-token"
	const baseNonce = "base-nonce"

	f.Add(uint8(0), "GET")
	f.Add(uint8(1), "https://attacker.example/token")
	f.Add(uint8(2), "different-access-token")
	f.Add(uint8(3), "different-nonce")

	f.Fuzz(func(t *testing.T, field uint8, alt string) {
		proofReq := ProofRequest{
			Signer: key, Algorithm: fapi.ES256,
			Method: baseMethod, URL: baseURL,
			AccessToken: baseAccessToken, Nonce: baseNonce,
			Now: now,
		}

		switch field % 4 {
		case 0: // htm mismatch
			if alt == "" || strings.ToUpper(alt) == baseMethod {
				return
			}
			proofReq.Method = alt
		case 1: // htu mismatch
			altURL, err := url.Parse(alt)
			if err != nil {
				return
			}
			if canonical.URI(altURL) == canonical.URI(baseURL) {
				return
			}
			proofReq.URL = altURL
		case 2: // ath mismatch
			if alt == baseAccessToken {
				return
			}
			proofReq.AccessToken = alt
		case 3: // nonce mismatch
			if alt == baseNonce {
				return
			}
			proofReq.Nonce = alt
		}

		proof, err := CreateProof(proofReq)
		if err != nil {
			return
		}

		if _, err := Verify(context.Background(), VerifyRequest{
			Proof: proof, Method: baseMethod, URL: baseURL,
			AccessToken: baseAccessToken, RequiredNonce: baseNonce,
			Now: now, MaxProofAge: time.Hour,
		}); err == nil {
			t.Fatalf("Verify succeeded despite mismatched field %d: alt=%q", field%4, alt)
		}
	})
}
