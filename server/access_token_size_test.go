package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/token"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
)

// exchangeWithPaymentAmount issues an access token for a payment
// authorization_details entry whose amount is amountBytes long, under
// the test harness's Limits (RecommendedLimits' MaxAccessTokenClaimsBytes).
func exchangeWithPaymentAmount(t *testing.T, amountBytes int) (server.TokenResult, error) {
	t.Helper()
	big := extension.RARDefinition[testPaymentDetail]{Type: "payment", MaxObjects: 5, MaxBytesPerObject: 64 << 10}
	registry, err := extension.NewRARRegistry(64<<10, 4, big)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarnessWithRAR(t, server.ProfileFAPISecurity, registry, fakeRARPolicy{allow: map[string]bool{"payment": true}}, nil)
	requested := `[{"type":"payment","actions":["approve"],"amount":"` + strings.Repeat("9", amountBytes) + `"}]`
	code := issueCodeWithDetails(t, h, big, requested)
	return h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:       server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
}

// issueCodeWithDetails pushes requested, grants every requested
// detail, and returns the authorization code.
func issueCodeWithDetails(t *testing.T, h harness, def extension.RARDefinition[testPaymentDetail], requested string) string {
	t.Helper()
	push, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{
			"authorization_details": requested,
		})},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{RequestURI: push.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction := action.(server.InteractionRequired)
	details, err := extension.RARGet(interaction.Interaction.AuthorizationDetails, def)
	if err != nil {
		t.Fatalf("RARGet: %v", err)
	}
	var granted []json.RawMessage
	for _, d := range details {
		granted = append(granted, mustMarshal(t, d.Fields))
	}
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts"}, AuthorizationDetails: granted}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	dest := result.(server.AuthorizationRedirect).Destination().URL()
	return dest.Query().Get("code")
}

// TestAccessTokenClaimsBoundedForTheResourceServer: authorization_details
// over Limits.MaxAccessTokenClaimsBytes fail the exchange as
// server_error, rather than issuing an access token a resource server's
// default 16 KiB limit refuses; ones within it issue a token that limit
// accepts.
func TestAccessTokenClaimsBoundedForTheResourceServer(t *testing.T) {
	_, err := exchangeWithPaymentAmount(t, 13000)
	var e *server.Error
	if !errors.As(err, &e) || e.Code() != server.ErrorServerError {
		t.Fatalf("exchange with 13000-byte details = %v, want server_error", err)
	}
	if !strings.Contains(e.Error(), "max_access_token_claims_bytes") {
		t.Fatalf("Error() = %q, want the claims limit named", e.Error())
	}

	res, err := exchangeWithPaymentAmount(t, 5000)
	if err != nil {
		t.Fatalf("exchange with 5000-byte details: %v", err)
	}
	at := res.AccessToken.Reveal()
	if len(at) > resource.DefaultMaxAccessTokenBytes {
		t.Fatalf("access token is %d bytes, over resource.DefaultMaxAccessTokenBytes", len(at))
	}
	if _, err := token.ParseAccessToken(at); err != nil {
		t.Fatalf("token.ParseAccessToken: %v", err)
	}
}

// TestRecommendedMaxAccessTokenBytesIsTheResourceDefault: with
// RecommendedLimits, MaxAccessTokenBytes is exactly what a resource
// server accepts by default, and it only grows past that as
// MaxAccessTokenClaimsBytes does.
func TestRecommendedMaxAccessTokenBytesIsTheResourceDefault(t *testing.T) {
	limits := server.RecommendedLimits()
	if got := limits.MaxAccessTokenBytes(); got != resource.DefaultMaxAccessTokenBytes {
		t.Errorf("RecommendedLimits().MaxAccessTokenBytes() = %d, want %d", got, resource.DefaultMaxAccessTokenBytes)
	}
	for claims, want := range map[int]int{1: 16 << 10, 6144: 16 << 10, 6145: 16<<10 + 2, 12 << 10: 24 << 10} {
		limits.MaxAccessTokenClaimsBytes = claims
		if got := limits.MaxAccessTokenBytes(); got != want {
			t.Errorf("MaxAccessTokenBytes() with %d claims bytes = %d, want %d", claims, got, want)
		}
	}
}
