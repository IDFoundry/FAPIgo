package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/requestobject"
)

const (
	gold   = "urn:example:gold"
	silver = "urn:example:silver"
)

// TestBeginAuthorizationSendsEssentialACR checks EssentialACRValues'
// encoding: an essential "acr" entry in the ID token's claims (OIDC
// Core §5.5.1.1), alongside any other requested claims, replacing an
// "acr" Claims.IDToken also names.
func TestBeginAuthorizationSendsEssentialACR(t *testing.T) {
	for name, tc := range map[string]struct {
		claims client.RequestedClaims
		want   string
	}{
		"alone":         {client.RequestedClaims{}, `{"id_token":{"acr":{"essential":true,"values":["urn:example:gold","urn:example:silver"]}}}`},
		"with claims":   {client.RequestedClaims{IDToken: []string{"email"}, UserInfo: []string{"address"}}, `{"id_token":{"acr":{"essential":true,"values":["urn:example:gold","urn:example:silver"]},"email":null},"userinfo":{"address":null}}`},
		"replacing acr": {client.RequestedClaims{IDToken: []string{"acr"}}, `{"id_token":{"acr":{"essential":true,"values":["urn:example:gold","urn:example:silver"]}}}`},
	} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClient(t, false)
			if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{
				Scope: []string{"openid"}, Claims: tc.claims, EssentialACRValues: []string{gold, silver},
			}); err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			if got := as.lastPARForm.Get("claims"); got != tc.want {
				t.Errorf("claims = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestBeginAuthorizationRefusesBadEssentialACR covers the requirement's
// own checks, made before anything is pushed: only an ID token can meet
// it, and an empty value is no class at all.
func TestBeginAuthorizationRefusesBadEssentialACR(t *testing.T) {
	for name, req := range map[string]client.BeginAuthorizationRequest{
		"no openid":   {Scope: []string{"accounts"}, EssentialACRValues: []string{gold}},
		"empty value": {Scope: []string{"openid"}, EssentialACRValues: []string{gold, ""}},
	} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClient(t, false)
			_, err := c.BeginAuthorization(context.Background(), req)
			var cerr *client.Error
			if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
				t.Fatalf("BeginAuthorization = %v, want invalid_request", err)
			}
			if as.lastPARForm != nil {
				t.Error("the request was pushed anyway")
			}
		})
	}
}

// TestCompleteAuthorizationChecksEssentialACR covers the client's own
// check of the server's answer: an ID token at a class the request
// didn't accept, or with none, is refused, so a server that ignored an
// essential acr can't pass off a weaker authentication.
func TestCompleteAuthorizationChecksEssentialACR(t *testing.T) {
	for name, tc := range map[string]struct {
		essential []string
		acr       string
		wantErr   bool
	}{
		"first value":      {[]string{gold, silver}, gold, false},
		"second value":     {[]string{gold, silver}, silver, false},
		"other value":      {[]string{gold}, silver, true},
		"no acr":           {[]string{gold}, "", true},
		"nothing required": {nil, "", false},
		"case differs":     {[]string{gold}, "urn:example:GOLD", true},
	} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClient(t, false)
			as.idTokenACR = tc.acr
			ctx := context.Background()
			session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}, EssentialACRValues: tc.essential})
			if err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{
				RawQuery: as.callbackFor(t, session.Handle().String(), "auth-code-123", ""), Session: session.Handle(),
			})
			if tc.wantErr {
				var cerr *client.Error
				if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidResponse {
					t.Fatalf("CompleteAuthorization = %v, %v; want invalid_response", result, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CompleteAuthorization: %v", err)
			}
		})
	}
}

// TestBackchannelAuthenticationEssentialACR is the CIBA counterpart: the
// requirement goes in the signed request object's claims, survives
// sealing, and is checked against the approval's ID token.
func TestBackchannelAuthenticationEssentialACR(t *testing.T) {
	for name, tc := range map[string]struct {
		acr     string
		wantErr bool
	}{
		"met":     {silver, false},
		"not met": {"urn:example:bronze", true},
		"no acr":  {"", true},
	} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClientWithCIBA(t)
			session, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
				Scope: []string{"openid", "accounts"}, LoginHint: "user@example.com", EssentialACRValues: []string{gold, silver},
			})
			if err != nil {
				t.Fatalf("BeginBackchannelAuthentication: %v", err)
			}
			assertRequestObjectAsksEssentialGoldOrSilver(t, as.lastBCForm.Get("request"))
			restored := resealBackchannelSession(t, c, session)
			as.tokenResponses = []cibaTokenResponse{{status: http.StatusOK, body: map[string]any{
				"access_token": "opaque-access-token", "token_type": "DPoP", "expires_in": 300, "scope": "openid accounts",
				"id_token": newCIBAIDTokenWithACR(t, as, tc.acr),
			}}}
			result, err := c.PollBackchannelAuthentication(context.Background(), restored)
			assertApprovedOrInvalidResponse(t, result, err, tc.wantErr)
		})
	}
}

// TestBeginBackchannelAuthenticationRefusesEssentialACRWithoutOpenID
// mirrors the authorization flow's check.
func TestBeginBackchannelAuthenticationRefusesEssentialACRWithoutOpenID(t *testing.T) {
	c, as, _ := newTestClientWithCIBA(t)
	for name, req := range map[string]client.BeginBackchannelAuthenticationRequest{
		"no openid":   {Scope: []string{"accounts"}, LoginHint: "user@example.com", EssentialACRValues: []string{gold}},
		"empty value": {Scope: []string{"openid"}, LoginHint: "user@example.com", EssentialACRValues: []string{""}},
	} {
		_, err := c.BeginBackchannelAuthentication(context.Background(), req)
		var cerr *client.Error
		if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
			t.Errorf("%s: BeginBackchannelAuthentication = %v, want invalid_request", name, err)
		}
	}
	if as.lastBCForm != nil {
		t.Error("a request was sent anyway")
	}
}

// assertRequestObjectAsksEssentialGoldOrSilver checks that the signed
// request object's claims ask for an essential acr of gold or silver.
func assertRequestObjectAsksEssentialGoldOrSilver(t *testing.T, request string) {
	t.Helper()
	obj, err := requestobject.Parse(request)
	if err != nil {
		t.Fatalf("parse request object: %v", err)
	}
	raw, ok := obj.Parameter("claims")
	if !ok {
		t.Fatal("request object has no claims")
	}
	var claims struct {
		IDToken struct {
			ACR struct {
				Essential bool     `json:"essential"`
				Values    []string `json:"values"`
			} `json:"acr"`
		} `json:"id_token"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("claims is not a JSON object: %s", raw)
	}
	if acr := claims.IDToken.ACR; !acr.Essential || len(acr.Values) != 2 || acr.Values[0] != gold || acr.Values[1] != silver {
		t.Fatalf("claims = %s, want an essential acr of gold or silver", raw)
	}
}

// resealBackchannelSession seals session and opens it again, as a
// caller storing it between polls would.
func resealBackchannelSession(t *testing.T, c *client.Client, session client.BackchannelAuthenticationSession) client.BackchannelAuthenticationSession {
	t.Helper()
	sealer, err := client.NewBackchannelSessionSealer(c, [][]byte{[]byte("essential-acr-test-seal-key-000\x01")})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealer.Seal(session, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	restored, _, err := sealer.Open(sealed, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	return restored
}

// assertApprovedOrInvalidResponse checks a poll's outcome: refused as
// invalid_response when wantErr, approved otherwise.
func assertApprovedOrInvalidResponse(t *testing.T, result client.BackchannelAuthenticationResult, err error, wantErr bool) {
	t.Helper()
	if wantErr {
		var cerr *client.Error
		if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidResponse {
			t.Fatalf("PollBackchannelAuthentication = %v, %v; want invalid_response", result, err)
		}
		return
	}
	if _, ok := result.(client.BackchannelAuthenticationApproved); err != nil || !ok {
		t.Fatalf("PollBackchannelAuthentication = %T, %v; want approved", result, err)
	}
}
