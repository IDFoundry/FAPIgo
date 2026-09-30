package resource_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/fapigo/resource"
)

// challengeFor verifies req with f's verifier and returns the response
// WriteJSON makes of the error.
func challengeFor(t *testing.T, f fixture, req resource.VerifyRequest) (*resource.Error, *httptest.ResponseRecorder) {
	t.Helper()
	req.Method, req.URL = "GET", f.target
	_, err := f.verifier.Verify(context.Background(), req)
	var rerr *resource.Error
	if !errors.As(err, &rerr) {
		t.Fatalf("Verify = %v, want a *resource.Error", err)
	}
	rec := httptest.NewRecorder()
	rerr.WriteJSON(rec)
	return rerr, rec
}

// TestNoCredentialsChallenge covers RFC 6750 §3.1 and RFC 9449 §7.2
// (Figure 17): a request with no credentials this verifier accepts gets
// 401, and a challenge for each scheme with no error information.
func TestNoCredentialsChallenge(t *testing.T) {
	f := newFixture(t)
	for name, authorization := range map[string]string{
		"no Authorization header": "",
		"blank header":            "  ",
		"unsupported scheme":      "Basic dXNlcjpwYXNz",
		"scheme alone":            "Negotiate",
	} {
		t.Run(name, func(t *testing.T) {
			rerr, rec := challengeFor(t, f, resource.VerifyRequest{Authorization: authorization})
			if rerr.Code() != "" || rec.Code != 401 {
				t.Errorf("Code, status = %q, %d; want none, 401", rerr.Code(), rec.Code)
			}
			if got, want := rec.Header().Get("WWW-Authenticate"), `Bearer, DPoP algs="ES256 PS256 EdDSA"`; got != want {
				t.Errorf("WWW-Authenticate = %q, want %q", got, want)
			}
			if rec.Body.Len() != 0 || rec.Header().Get("Content-Type") != "" {
				t.Errorf("body %q (Content-Type %q), want none", rec.Body.String(), rec.Header().Get("Content-Type"))
			}
		})
	}
}

// TestChallengeFollowsScheme covers RFC 9449 §7.2: an error for a
// request whose scheme is known goes in that scheme's challenge.
func TestChallengeFollowsScheme(t *testing.T) {
	f := newFixture(t)
	for name, tc := range map[string]struct {
		req    resource.VerifyRequest
		status int
		want   string
	}{
		"DPoP without a token": {
			resource.VerifyRequest{Authorization: "DPoP", DPoPProofs: []string{f.dpopProof}},
			400, `DPoP error="invalid_request", algs="ES256 PS256 EdDSA"`,
		},
		"DPoP without a proof": {
			resource.VerifyRequest{Authorization: "DPoP " + f.accessToken},
			400, `DPoP error="invalid_request", algs="ES256 PS256 EdDSA"`,
		},
		// The proof's ath is bound to the real token, so the proof itself
		// is invalid for any other (RFC 9449 §4.3).
		"DPoP with another token": {
			resource.VerifyRequest{Authorization: "DPoP not-a-token", DPoPProofs: []string{f.dpopProof}},
			401, `DPoP error="invalid_dpop_proof", algs="ES256 PS256 EdDSA"`,
		},
		"two DPoP proofs": {
			resource.VerifyRequest{Authorization: "DPoP " + f.accessToken, DPoPProofs: []string{f.dpopProof, f.dpopProof}},
			401, `DPoP error="invalid_dpop_proof", algs="ES256 PS256 EdDSA"`,
		},
		"Bearer without a token": {
			resource.VerifyRequest{Authorization: "Bearer "},
			400, `Bearer error="invalid_request"`,
		},
		"Bearer without a client certificate": {
			resource.VerifyRequest{Authorization: "Bearer " + f.accessToken},
			400, `Bearer error="invalid_request"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, rec := challengeFor(t, f, tc.req)
			if rec.Code != tc.status || rec.Header().Get("WWW-Authenticate") != tc.want {
				t.Errorf("status %d, WWW-Authenticate %q; want %d, %q", rec.Code, rec.Header().Get("WWW-Authenticate"), tc.status, tc.want)
			}
		})
	}
}

// sharedErrorResolver is an AccessTokenResolver returning the same
// *Error every time.
type sharedErrorResolver struct{ err *resource.Error }

func (r sharedErrorResolver) ResolveAccessToken(context.Context, resource.ResolveAccessTokenRequest) (resource.ResolvedAccessToken, error) {
	return resource.ResolvedAccessToken{}, r.err
}

// TestDPoPChallengeDoesNotModifyResolverError covers Verify copying an
// AccessTokenResolver's own *Error before marking it for a DPoP
// challenge.
func TestDPoPChallengeDoesNotModifyResolverError(t *testing.T) {
	f := newFixture(t)
	shared := resource.NewError(resource.ErrorInvalidToken, 401, "unknown token")
	verifier, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
		AccessTokens: sharedErrorResolver{err: shared},
		Replay:       f.replay, Revocation: f.revocation, Clock: fixedClock{now: f.now},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.verifier = verifier
	_, rec := challengeFor(t, f, resource.VerifyRequest{Authorization: "DPoP " + f.accessToken, DPoPProofs: []string{f.dpopProof}})
	if want := `DPoP error="invalid_token", algs="ES256 PS256 EdDSA"`; rec.Header().Get("WWW-Authenticate") != want {
		t.Errorf("WWW-Authenticate = %q, want %q", rec.Header().Get("WWW-Authenticate"), want)
	}
	direct := httptest.NewRecorder()
	shared.WriteJSON(direct)
	if got := direct.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
		t.Errorf("the resolver's own error now writes %q; it was modified", got)
	}
}
