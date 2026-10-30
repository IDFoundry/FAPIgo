package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/server"
)

// mintedDetail has a member, "minted", that only the authorization server
// may set: it adds one to its grant (as an identifier the client names
// later), and a client must not choose one.
type mintedDetail struct {
	Type    string   `json:"type"`
	Actions []string `json:"actions"`
	Minted  string   `json:"minted,omitempty"`
}

var mintedRARDef = extension.RARDefinition[mintedDetail]{
	Type: "minted", MaxObjects: 5, MaxBytesPerObject: 1024,
	ValidateRequest: func(v mintedDetail) error {
		if v.Minted != "" {
			return errors.New("minted is set by the authorization server")
		}
		return nil
	},
	// The grant may add a minted value, and may not change one already
	// granted.
	ValidateGrant: func(requested, granted mintedDetail) error {
		if !slices.Equal(requested.Actions, granted.Actions) {
			return errors.New("actions differ")
		}
		if requested.Minted != "" && granted.Minted != requested.Minted {
			return errors.New("minted differs")
		}
		return nil
	},
}

const (
	mintedRequested       = `[{"type":"minted","actions":["issue"]}]`
	mintedClientSupplied  = `[{"type":"minted","actions":["issue"],"minted":"chosen-by-client"}]`
	mintedGrantedByServer = `[{"type":"minted","actions":["issue"],"minted":"minted-by-server"}]`
)

func newMintedRARRegistry(t *testing.T) *extension.RARRegistry {
	t.Helper()
	registry, err := extension.NewRARRegistry(4096, 4, mintedRARDef)
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	return registry
}

func mintedRARHarness(t *testing.T) harness {
	t.Helper()
	allow := fakeRARPolicy{allow: map[string]bool{"minted": true}}
	return newHarnessWithRARTypes(t, server.ProfileFAPISecurity, newMintedRARRegistry(t), allow, allow, []string{"minted"})
}

func pushMintedRequest(t *testing.T, details string) error {
	t.Helper()
	h := mintedRARHarness(t)
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{
			"authorization_details": details,
		})},
	})
	return err
}

func beginMintedBackchannel(t *testing.T, details string) error {
	t.Helper()
	h := mintedRARHarness(t)
	params := standardBackchannelParams(t)
	params["authorization_details"] = json.RawMessage(details)
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), h.backchannelRequestObject(t, params))},
	})
	if err != nil {
		return err
	}
	if localErr, ok := action.(server.BackchannelAuthenticationLocalError); ok {
		return localErr.Error
	}
	return nil
}

func requestMintedClientCredentials(t *testing.T, details string) error {
	t.Helper()
	h := newHarnessWithClientCredentialsGrantAndRARTypes(t, newMintedRARRegistry(t), fakeRARPolicy{allow: map[string]bool{"minted": true}}, []string{"minted"})
	params := clientCredentialsFormParams(h.clientAssertion(t), "accounts")
	params = append(params, formParam("authorization_details", details))
	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP:       server.FormRequest{Parameters: params},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	return err
}

// RARDefinition.ValidateRequest refuses a server-only member wherever a
// client submits authorization_details to start a grant.
func TestClientRequestRefusesServerOnlyAuthorizationDetailsMember(t *testing.T) {
	for _, flow := range []struct {
		name    string
		request func(*testing.T, string) error
	}{
		{"PAR", pushMintedRequest},
		{"CIBA", beginMintedBackchannel},
		{"client_credentials", requestMintedClientCredentials},
	} {
		t.Run(flow.name, func(t *testing.T) {
			if err := flow.request(t, mintedRequested); err != nil {
				t.Fatalf("request without minted: %v", err)
			}
			err := flow.request(t, mintedClientSupplied)
			if err == nil {
				t.Fatal("request with a client-supplied minted member succeeded, want invalid_authorization_details")
			}
			if code := serverErrorCode(t, err); code != server.ErrorInvalidAuthorizationDetails {
				t.Fatalf("error code = %q, want %q (%v)", code, server.ErrorInvalidAuthorizationDetails, err)
			}
		})
	}
}

// issueMintedCode pushes mintedRequested, grants it with the server's
// minted member added, and returns the authorization code.
func issueMintedCode(t *testing.T, h harness) string {
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
			formParam("authorization_details", mintedRequested),
		}},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := h.server.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{RequestURI: push.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction := action.(server.InteractionRequired)
	var granted []json.RawMessage
	_ = json.Unmarshal([]byte(mintedGrantedByServer), &granted)
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(context.Background(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope:                []string{"openid", "accounts", "offline_access"},
			AuthorizationDetails: granted,
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization with a server-minted member: %v", err)
	}
	redirect, ok := result.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("CompleteAuthorization result = %T, want server.AuthorizationRedirect", result)
	}
	dest := redirect.Destination().URL()
	code := dest.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect %s has no code", dest.String())
	}
	return code
}

func assertMintedIssued(t *testing.T, h harness, result server.TokenResult) {
	t.Helper()
	for what, raw := range map[string]json.RawMessage{
		"TokenResult.AuthorizationDetails":         result.AuthorizationDetails,
		"access token authorization_details claim": authorizationDetailsAccessTokenClaim(t, result.AccessToken.Reveal(), &h.serverKey.PublicKey),
	} {
		var got []mintedDetail
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%s: unmarshal %s: %v", what, raw, err)
		}
		if len(got) != 1 || got[0].Minted != "minted-by-server" {
			t.Fatalf("%s = %s, want the server-minted member", what, raw)
		}
	}
}

// A grant may add a member ValidateRequest refuses from clients, and later
// requests against that grant may echo it: the token endpoint's narrowing
// and a refresh check details against the grant, not as a new request.
func TestServerOnlyAuthorizationDetailsMemberSurvivesGrant(t *testing.T) {
	h := mintedRARHarness(t)
	echo := mintedGrantedByServer

	first, err := rarExchangeCode(t, h, issueMintedCode(t, h), nil)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	assertMintedIssued(t, h, first)
	if !first.HasRefreshToken {
		t.Fatal("no refresh token issued")
	}

	narrowed, err := rarExchangeCode(t, h, issueMintedCode(t, h), &echo)
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode echoing the granted member: %v", err)
	}
	assertMintedIssued(t, h, narrowed)

	for name, details := range map[string]*string{"absent": nil, "echoed": &echo} {
		t.Run("refresh "+name, func(t *testing.T) {
			result, err := rarRefresh(t, h, first.RefreshToken.Reveal(), details)
			if err != nil {
				t.Fatalf("RefreshAccessToken: %v", err)
			}
			assertMintedIssued(t, h, result)
		})
	}
}
