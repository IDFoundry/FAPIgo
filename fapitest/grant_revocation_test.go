package fapitest_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
)

// accessTokenClaim is a JWT access token's claim name, unverified.
func accessTokenClaim(t *testing.T, tokens client.TokenSet, name string) any {
	t.Helper()
	parts := strings.Split(tokens.AccessToken.Reveal(), ".")
	if len(parts) != 3 {
		t.Fatalf("access token isn't a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims[name]
}

// verifyError is resource.Verify's answer for tokens' access token.
func verifyError(t *testing.T, h *fapitest.Harness, tokens client.TokenSet) error {
	t.Helper()
	ctx := context.Background()
	target, err := url.Parse("https://rs.fapitest.internal/accounts")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := h.NewResourceRequestDPoPProof(ctx, "GET", target, tokens.AccessToken.Reveal())
	if err != nil {
		t.Fatalf("NewResourceRequestDPoPProof: %v", err)
	}
	_, err = h.Resource.Verify(ctx, resource.VerifyRequest{
		Method: "GET", URL: target, Authorization: "DPoP " + tokens.AccessToken.Reveal(), DPoPProofs: []string{proof},
	})
	return err
}

func serverErrorCodeOf(err error) string {
	var cerr *client.Error
	if errors.As(err, &cerr) {
		if resp, ok := cerr.ServerResponse(); ok {
			return resp.Code
		}
	}
	return ""
}

// TestRevokeGrant covers a grant revoked after its tokens are in use:
// its refresh token stops working, and so does every access token issued
// from it, the original and the refreshed one alike.
func TestRevokeGrant(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity, GrantID: "grant-1"})
	ctx := context.Background()
	first, err := h.RunAuthorizationCodeFlow(ctx, offlineScope)
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	if got := accessTokenClaim(t, first, "grant_id"); got != "grant-1" {
		t.Fatalf("access token grant_id = %v, want grant-1", got)
	}
	refreshed, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: first})
	if err != nil {
		t.Fatalf("RefreshTokens: %v", err)
	}
	if got := accessTokenClaim(t, refreshed, "grant_id"); got != "grant-1" {
		t.Fatalf("refreshed access token grant_id = %v, want grant-1", got)
	}
	for _, tokens := range []client.TokenSet{first, refreshed} {
		if err := verifyError(t, h, tokens); err != nil {
			t.Fatalf("resource.Verify before revocation: %v", err)
		}
	}

	if err := h.RevokeGrant(ctx, "grant-1"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}

	if _, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: first}); serverErrorCodeOf(err) != "invalid_grant" {
		t.Errorf("RefreshTokens after revocation = %v, want invalid_grant", err)
	}
	for name, tokens := range map[string]client.TokenSet{"original": first, "refreshed": refreshed} {
		var rerr *resource.Error
		if err := verifyError(t, h, tokens); !errors.As(err, &rerr) || rerr.Code() != resource.ErrorInvalidToken {
			t.Errorf("resource.Verify(%s access token) after revocation = %v, want invalid_token", name, err)
		}
	}
}

// TestRevokeGrantBeforeTheCodeIsRedeemed covers a grant revoked between
// approval and the client's code exchange.
func TestRevokeGrantBeforeTheCodeIsRedeemed(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity, GrantID: "grant-1"})
	ctx := context.Background()
	session, err := h.Client.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: offlineScope})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	callback, err := h.CaptureCallback(ctx, session)
	if err != nil {
		t.Fatalf("CaptureCallback: %v", err)
	}
	if err := h.RevokeGrant(ctx, "grant-1"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if _, err := h.RunAuthorizationCodeFlowWithCallback(ctx, session.Handle(), callback); serverErrorCodeOf(err) != "invalid_grant" {
		t.Fatalf("code exchange after revocation = %v, want invalid_grant", err)
	}
}

// TestRevokeGrantLeavesOtherGrantsAlone covers tokens from a grant with
// no grant ID: revoking a grant ID doesn't touch them, and they carry no
// grant_id claim.
func TestRevokeGrantLeavesOtherGrantsAlone(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity})
	ctx := context.Background()
	tokens, err := h.RunAuthorizationCodeFlow(ctx, offlineScope)
	if err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}
	if got := accessTokenClaim(t, tokens, "grant_id"); got != nil {
		t.Fatalf("access token grant_id = %v, want none", got)
	}
	if err := h.RevokeGrant(ctx, "grant-1"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	if _, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: tokens}); err != nil {
		t.Errorf("RefreshTokens after revoking another grant: %v", err)
	}
	if err := verifyError(t, h, tokens); err != nil {
		t.Errorf("resource.Verify after revoking another grant: %v", err)
	}
}
