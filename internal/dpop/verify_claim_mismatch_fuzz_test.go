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
		if !mismatchProofRequest(&proofReq, field, alt) {
			return
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

// mismatchProofRequest replaces the one ProofRequest field selected by
// field%4 (htm, htu, ath, nonce) with alt, reporting false — skip this
// input — when alt wouldn't actually differ from the original value
// after the comparison Verify itself applies (e.g. a case-folded method,
// or a URL that canonicalizes the same way).
func mismatchProofRequest(req *ProofRequest, field uint8, alt string) bool {
	switch field % 4 {
	case 0: // htm mismatch — req.Method is still the upper-case base
		// method here. Conservatively skips any alt that upper-cases to
		// it (e.g. "post"), even though Verify would reject that too.
		if alt == "" || strings.ToUpper(alt) == req.Method {
			return false
		}
		req.Method = alt
	case 1: // htu mismatch
		altURL, err := url.Parse(alt)
		if err != nil || canonical.URI(altURL) == canonical.URI(req.URL) {
			return false
		}
		req.URL = altURL
	case 2: // ath mismatch
		if alt == req.AccessToken {
			return false
		}
		req.AccessToken = alt
	case 3: // nonce mismatch
		if alt == req.Nonce {
			return false
		}
		req.Nonce = alt
	}
	return true
}
