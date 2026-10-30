package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
)

// mintedIDsDetail has a member, "ids", the authorization server mints: a
// grant may add identifiers to an object requested without them, and a
// token request may only keep a subset of those granted.
type mintedIDsDetail struct {
	Type    string   `json:"type"`
	Actions []string `json:"actions"`
	IDs     []string `json:"ids,omitempty"`
}

// mintedIDsGrant lets a grant add identifiers, and not change any already
// there.
func mintedIDsGrant(requested, granted mintedIDsDetail) error {
	if !slices.Equal(requested.Actions, granted.Actions) {
		return errors.New("actions differ")
	}
	if len(requested.IDs) > 0 && !slices.Equal(requested.IDs, granted.IDs) {
		return errors.New("ids differ")
	}
	return nil
}

// mintedIDsNarrowing lets a token request keep only granted identifiers.
func mintedIDsNarrowing(granted, narrowed mintedIDsDetail) error {
	if !slices.Equal(granted.Actions, narrowed.Actions) {
		return errors.New("actions differ")
	}
	for _, id := range narrowed.IDs {
		if !slices.Contains(granted.IDs, id) {
			return errors.New("id was not granted")
		}
	}
	return nil
}

var mintedIDsRARDef = extension.RARDefinition[mintedIDsDetail]{
	Type: "minted_ids", MaxObjects: 5, MaxBytesPerObject: 1024,
	ValidateGrant:     mintedIDsGrant,
	ValidateNarrowing: mintedIDsNarrowing,
}

const (
	mintedIDsNone   = `[{"type":"minted_ids","actions":["issue"]}]`
	mintedIDsAB     = `[{"type":"minted_ids","actions":["issue"],"ids":["a","b"]}]`
	mintedIDsA      = `[{"type":"minted_ids","actions":["issue"],"ids":["a"]}]`
	mintedIDsChosen = `[{"type":"minted_ids","actions":["issue"],"ids":["chosen-by-client"]}]`
)

// mintedIDsHarness is a RAR harness registering def, whose client may use
// its type under both grants, with policy as both grants' RARPolicy.
func mintedIDsHarness(t *testing.T, def extension.RARDefinition[mintedIDsDetail], policy server.RARPolicy) harness {
	t.Helper()
	registry, err := extension.NewRARRegistry(4096, 4, def)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	return newHarnessWithRARTypes(t, server.ProfileFAPISecurity, registry, policy, policy, []string{def.Type})
}

func allowMintedIDs() server.RARPolicy {
	return fakeRARPolicy{allow: map[string]bool{"minted_ids": true}}
}

func rawDetails(t *testing.T, details string) []json.RawMessage {
	t.Helper()
	var objects []json.RawMessage
	if err := json.Unmarshal([]byte(details), &objects); err != nil {
		t.Fatalf("unmarshal %s: %v", details, err)
	}
	return objects
}

// pushAndBeginAuthorization pushes a request for requested with scope
// "openid accounts offline_access" and begins it.
func pushAndBeginAuthorization(t *testing.T, h harness, requested string) server.InteractionRequired {
	t.Helper()
	push, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", h.clientAssertion(t)),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("response_type", "code"),
			formParam("redirect_uri", testRedirectURI),
			formParam("scope", "openid accounts offline_access"),
			formParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
			formParam("code_challenge_method", "S256"),
			formParam("state", "opaque-state"),
			formParam("authorization_details", requested),
		}},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{RequestURI: push.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	return action.(server.InteractionRequired)
}

// issueCodeGranting requests mintedIDsNone, grants granted at consent and
// returns the authorization code.
func issueCodeGranting(t *testing.T, h harness, granted string) string {
	t.Helper()
	interaction := pushAndBeginAuthorization(t, h, mintedIDsNone)
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                []string{"openid", "accounts", "offline_access"},
			AuthorizationDetails: rawDetails(t, granted),
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization granting %s: %v", granted, err)
	}
	dest := result.(server.AuthorizationRedirect).Destination().URL()
	return dest.Query().Get("code")
}

// approveBackchannelGranting begins a CIBA request for mintedIDsNone,
// grants granted and returns the auth_req_id.
func approveBackchannelGranting(t *testing.T, h harness, granted string) string {
	t.Helper()
	params := standardBackchannelParams(t)
	params["authorization_details"] = json.RawMessage(mintedIDsNone)
	required := beginBackchannel(t, h, params)
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                []string{"openid", "accounts"},
			AuthorizationDetails: rawDetails(t, granted),
		}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication granting %s: %v", granted, err)
	}
	return required.AuthReqID.String()
}

func assertIssuedMintedIDs(t *testing.T, h harness, result server.TokenResult, want []string) {
	t.Helper()
	for what, raw := range map[string]json.RawMessage{
		"TokenResult.AuthorizationDetails":         result.AuthorizationDetails,
		"access token authorization_details claim": authorizationDetailsAccessTokenClaim(t, result.AccessToken.Reveal(), &h.serverKey.PublicKey),
	} {
		var got []mintedIDsDetail
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%s: unmarshal %s: %v", what, raw, err)
		}
		if len(got) != 1 || !slices.Equal(got[0].IDs, want) {
			t.Fatalf("%s = %s, want ids %q", what, raw, want)
		}
	}
}

// Consent may add identifiers the server mints; a token request may not
// add any to a grant that holds none — at code exchange, CIBA token
// exchange or refresh — and may keep a subset of those granted
// (RARDefinition.ValidateNarrowing).
func TestTokenRequestNarrowingCannotAddServerMintedMember(t *testing.T) {
	h := mintedIDsHarness(t, mintedIDsRARDef, allowMintedIDs())

	_, err := rarExchangeCode(t, h, issueCodeGranting(t, h, mintedIDsNone), rarParam(mintedIDsChosen))
	assertInvalidAuthorizationDetails(t, err)

	_, err = rarExchangeBackchannel(t, h, approveBackchannelGranting(t, h, mintedIDsNone), rarParam(mintedIDsChosen))
	assertInvalidAuthorizationDetails(t, err)

	result, err := rarExchangeCode(t, h, issueCodeGranting(t, h, mintedIDsAB), rarParam(mintedIDsA))
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode narrowing to a subset of the granted ids: %v", err)
	}
	assertIssuedMintedIDs(t, h, result, []string{"a"})

	_, err = rarExchangeCode(t, h, issueCodeGranting(t, h, mintedIDsAB), rarParam(mintedIDsChosen))
	assertInvalidAuthorizationDetails(t, err)
}

func TestRefreshNarrowingCannotAddServerMintedMember(t *testing.T) {
	h := mintedIDsHarness(t, mintedIDsRARDef, allowMintedIDs())
	refreshTokenFor := func(granted string) string {
		t.Helper()
		first, err := rarExchangeCode(t, h, issueCodeGranting(t, h, granted), nil)
		if err != nil {
			t.Fatalf("ExchangeAuthorizationCode: %v", err)
		}
		if !first.HasRefreshToken {
			t.Fatal("no refresh token issued")
		}
		return first.RefreshToken.Reveal()
	}

	_, err := rarRefresh(t, h, refreshTokenFor(mintedIDsNone), rarParam(mintedIDsChosen))
	assertInvalidAuthorizationDetails(t, err)

	result, err := rarRefresh(t, h, refreshTokenFor(mintedIDsAB), rarParam(mintedIDsA))
	if err != nil {
		t.Fatalf("RefreshAccessToken narrowing to a subset of the granted ids: %v", err)
	}
	assertIssuedMintedIDs(t, h, result, []string{"a"})
}

// A definition with only ValidateGrant judges a token request's narrowing
// with it, as before ValidateNarrowing existed.
func TestTokenRequestNarrowingFallsBackToValidateGrant(t *testing.T) {
	def := mintedIDsRARDef
	def.ValidateNarrowing = nil
	h := mintedIDsHarness(t, def, allowMintedIDs())

	result, err := rarExchangeCode(t, h, issueCodeGranting(t, h, mintedIDsNone), rarParam(mintedIDsChosen))
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode under ValidateGrant alone: %v", err)
	}
	assertIssuedMintedIDs(t, h, result, []string{"chosen-by-client"})

	_, err = rarExchangeCode(t, h, issueCodeGranting(t, h, mintedIDsAB), rarParam(mintedIDsA))
	assertInvalidAuthorizationDetails(t, err)
}

// mintingRARPolicy grants every requested object with identifiers added.
type mintingRARPolicy struct{}

func (mintingRARPolicy) Authorize(_ context.Context, _ fapi.ClientID, requested []json.RawMessage) ([]json.RawMessage, error) {
	granted := make([]json.RawMessage, 0, len(requested))
	for _, raw := range requested {
		var d mintedIDsDetail
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		d.IDs = []string{"policy-minted"}
		encoded, err := json.Marshal(d)
		if err != nil {
			return nil, err
		}
		granted = append(granted, encoded)
	}
	return granted, nil
}

// A RARPolicy's decision is the server's grant, judged by ValidateGrant,
// so it may add identifiers ValidateNarrowing would refuse.
func TestRARPolicyDecisionJudgedByValidateGrant(t *testing.T) {
	h := mintedIDsHarness(t, mintedIDsRARDef, mintingRARPolicy{})
	interaction := pushAndBeginAuthorization(t, h, mintedIDsNone)
	details, err := extension.RARGet(interaction.Interaction.AuthorizationDetails, mintedIDsRARDef)
	if err != nil {
		t.Fatalf("RARGet: %v", err)
	}
	if len(details) != 1 || !slices.Equal(details[0].Fields.IDs, []string{"policy-minted"}) {
		t.Fatalf("interaction authorization_details = %+v, want the policy's minted ids", details)
	}
}
