package server_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// attestedCode runs PAR and authorization authenticated by i's
// attestation and returns the authorization code: what a front-channel
// attacker could intercept.
func (i *attestedInstance) attestedCode() string {
	t := i.t
	t.Helper()
	ctx := context.Background()
	attestations, pops := i.headers()
	push, err := i.h.server.PushAuthorizationRequest(ctx, server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_id", testClientID.String()),
			formParam("response_type", "code"),
			formParam("redirect_uri", testRedirectURI),
			formParam("scope", "openid accounts offline_access"),
			formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
			formParam("code_challenge_method", "S256"),
		}},
		ClientAttestations: attestations, ClientAttestationPoPs: pops,
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := i.h.server.BeginAuthorization(ctx, server.BeginAuthorizationRequest{RequestURI: push.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("BeginAuthorization = %T, want InteractionRequired", action)
	}
	subjectID, _ := server.NewSubjectID("user-1")
	subject, _ := server.NewAuthenticatedSubject(subjectID)
	authCtx, _ := server.NewAuthenticationContext(i.h.now, "", nil)
	completed, err := i.h.server.CompleteAuthorization(ctx, server.CompleteAuthorizationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts", "offline_access"}}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := completed.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("CompleteAuthorization = %T, want AuthorizationRedirect", completed)
	}
	dest := redirect.Destination().URL()
	return dest.Query().Get("code")
}

// exchangeCode presents code authenticated by i's attestation, with
// verifier as its PKCE code_verifier.
func (i *attestedInstance) exchangeCode(code, verifier string) (server.TokenResult, error) {
	attestations, pops := i.headers()
	return i.h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_id", testClientID.String()),
			formParam("grant_type", "authorization_code"),
			formParam("code", code),
			formParam("redirect_uri", testRedirectURI),
			formParam("code_verifier", verifier),
		}},
		DPoPProofs:         []string{createDPoPProof(i.t, generateKey(i.t), i.h.now)},
		ClientAttestations: attestations, ClientAttestationPoPs: pops,
	})
}

const wrongCodeVerifier = "not-the-verifier-of-this-code-0123456789abcdefghijk"

func requireInvalidGrant(t *testing.T, err error) {
	t.Helper()
	var serverErr *server.Error
	if !errors.As(err, &serverErr) || serverErr.Code() != server.ErrorInvalidGrant {
		t.Fatalf("err = %v, want invalid_grant", err)
	}
}

// TestAttestedCodeReusedByAnotherInstanceRevokesNothing covers an
// authorization code presented again by another installation of the
// same wallet app — same client_id, its own genuine attestation, but
// not the code's PKCE verifier. The code is bound to the instance that
// pushed its authorization request, so the presentation isn't a reuse
// of it (RFC 6749 §4.1.2): the tokens the user's own installation got
// from it stay valid. The installation the code was issued to presenting
// it again still revokes them.
func TestAttestedCodeReusedByAnotherInstanceRevokesNothing(t *testing.T) {
	attesterKey := generateKey(t)
	h := newInstanceBindingHarness(t, attesterKey)
	victim := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	other := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}

	code := victim.attestedCode()
	tokens, err := victim.exchangeCode(code, testCodeVerifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	revokedBefore := len(h.revocation.revoked)

	_, err = other.exchangeCode(code, wrongCodeVerifier)
	requireInvalidGrant(t, err)
	if revoked := h.revocation.revoked[revokedBefore:]; len(revoked) != 0 {
		t.Fatalf("another instance's presentation revoked %v", revoked)
	}
	if _, err := victim.refresh(tokens.RefreshToken.Reveal()); err != nil {
		t.Fatalf("refresh after another instance presented the code: %v", err)
	}

	// The same instance presenting it again is a reuse.
	_, err = victim.exchangeCode(code, testCodeVerifier)
	requireInvalidGrant(t, err)
	if _, err := victim.refresh(tokens.RefreshToken.Reveal()); err == nil {
		t.Fatal("refresh succeeded after the code was reused by its own instance")
	}
}

// TestAttestedCodeFromAnotherInstanceIsNotSpent covers another
// installation presenting a code before the user's own installation
// exchanges it: it's unknown to the other instance, so it isn't spent,
// and the user's exchange still succeeds.
func TestAttestedCodeFromAnotherInstanceIsNotSpent(t *testing.T) {
	attesterKey := generateKey(t)
	h := newInstanceBindingHarness(t, attesterKey)
	victim := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}
	other := &attestedInstance{t: t, h: h, attesterKey: attesterKey, instanceKey: generateKey(t)}

	code := victim.attestedCode()
	for _, verifier := range []string{wrongCodeVerifier, testCodeVerifier} {
		_, err := other.exchangeCode(code, verifier)
		requireInvalidGrant(t, err)
	}
	if _, err := victim.exchangeCode(code, testCodeVerifier); err != nil {
		t.Fatalf("exchange after another instance presented the code: %v", err)
	}
}
