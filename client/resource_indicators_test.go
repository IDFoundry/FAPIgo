package client_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/requestobject"
)

const (
	issuerA = "https://issuer-a.example"
	issuerB = "https://issuer-b.example/credentials"
)

// TestBeginAuthorizationSendsResourcesAsPlainParameters covers the
// baseline profile's plain PAR form: one "resource" parameter per
// resource indicator, in order (RFC 8707 §2), and none when Resource is
// empty.
func TestBeginAuthorizationSendsResourcesAsPlainParameters(t *testing.T) {
	for name, resources := range map[string][]string{
		"none":    nil,
		"one":     {issuerA},
		"several": {issuerA, issuerB},
	} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClient(t, false)
			if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{
				Scope: []string{"openid"}, Resource: resources,
			}); err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			if got := as.lastPARForm["resource"]; !slices.Equal(got, resources) {
				t.Errorf("PAR resource = %q, want %q", got, resources)
			}
		})
	}
}

// TestBeginAuthorizationSendsResourcesInRequestObject covers both
// request-object shapes — message signing and
// PushedRequestEncodingRequestObject: "resource" is a JSON string for
// one resource and an array for several, and never a plain parameter
// beside the request object.
func TestBeginAuthorizationSendsResourcesInRequestObject(t *testing.T) {
	newClients := map[string]func(*testing.T) (*client.Client, *fakeAS){
		"message signing": func(t *testing.T) (*client.Client, *fakeAS) {
			c, as, _ := newTestClient(t, true)
			return c, as
		},
		"request object encoding": newTestClientWithRequestObjectEncoding,
	}
	for shape, newClient := range newClients {
		for name, tc := range map[string]struct {
			resources []string
			want      string
		}{
			"none":    {nil, ""},
			"one":     {[]string{issuerA}, `"https://issuer-a.example"`},
			"several": {[]string{issuerA, issuerB}, `["https://issuer-a.example","https://issuer-b.example/credentials"]`},
		} {
			t.Run(shape+"/"+name, func(t *testing.T) {
				c, as := newClient(t)
				if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{
					Scope: []string{"openid"}, Resource: tc.resources,
				}); err != nil {
					t.Fatalf("BeginAuthorization: %v", err)
				}
				if got := requestObjectParameter(t, as.lastPARForm.Get("request"), "resource"); got != tc.want {
					t.Errorf("request object resource = %s, want %s", got, tc.want)
				}
				if as.lastPARForm.Has("resource") {
					t.Errorf("PAR form also carries resource %q beside the request object", as.lastPARForm["resource"])
				}
			})
		}
	}
}

// requestObjectParameter is the raw JSON of request's parameter name,
// or "" when it has none.
func requestObjectParameter(t *testing.T, request, name string) string {
	t.Helper()
	obj, err := requestobject.Parse(request)
	if err != nil {
		t.Fatalf("parse request object: %v", err)
	}
	raw, _ := obj.Parameter(name)
	return string(raw)
}

// TestExchangeCodeRepeatsResources covers RFC 8707 §2.2: the code
// exchange names the authorization request's resources again, carried
// through the session record (none when the request had none), and the
// TokenSet records them for RefreshTokens.
func TestExchangeCodeRepeatsResources(t *testing.T) {
	for name, resources := range map[string][]string{
		"none":    nil,
		"one":     {issuerA},
		"several": {issuerA, issuerB},
	} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClient(t, false)
			ctx := context.Background()
			session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid"}, Resource: resources})
			if err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{
				RawQuery: as.callbackFor(t, session.Handle().String(), "auth-code-123", ""), Session: session.Handle(),
			})
			if err != nil {
				t.Fatalf("CompleteAuthorization: %v", err)
			}
			if got := as.lastTokenForm["resource"]; !slices.Equal(got, resources) {
				t.Errorf("token request resource = %q, want %q", got, resources)
			}
			success, ok := result.(client.CompletionSuccess)
			if !ok {
				t.Fatalf("result = %T, want success", result)
			}
			if !slices.Equal(success.Tokens.Resource, resources) {
				t.Errorf("TokenSet.Resource = %q, want %q", success.Tokens.Resource, resources)
			}
		})
	}
}

// TestBeginAuthorizationRefusesBadResources covers RFC 8707 §2's rules,
// checked before anything is pushed.
func TestBeginAuthorizationRefusesBadResources(t *testing.T) {
	for name, resources := range map[string][]string{
		"empty":       {""},
		"relative":    {"/credentials"},
		"no scheme":   {"issuer-a.example"},
		"fragment":    {"https://issuer-a.example/#frag"},
		"empty frag":  {"https://issuer-a.example/#"},
		"repeated":    {issuerA, issuerB, issuerA},
		"space":       {"https://issuer-a.example/a b"},
		"newline":     {"https://issuer-a.example/\nhttps://evil.example"},
		"control":     {"https://issuer-a.example/\x7f"},
		"unparseable": {"https://issuer-a.example:port/"},
	} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClient(t, false)
			_, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{Scope: []string{"openid"}, Resource: resources})
			assertInvalidRequest(t, err)
			if as.lastPARForm != nil {
				t.Error("the request was pushed anyway")
			}
		})
	}
}

// TestBeginAuthorizationRefusesResourceAlsoAsExtension covers a caller
// setting "resource" both ways: refused, rather than one silently
// replacing the other. An Extensions value alone still goes through, as
// it did before Resource existed.
func TestBeginAuthorizationRefusesResourceAlsoAsExtension(t *testing.T) {
	resourceDef := extension.Definition[string]{Sensitivity: extension.NotSensitive, Name: "resource", Cardinality: extension.Single, MaxBytes: 256}
	for name, messageSigned := range map[string]bool{"plain": false, "request object": true} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClient(t, messageSigned)
			var req client.BeginAuthorizationRequest
			req.Scope = []string{"openid"}
			if err := extension.Set(&req.Extensions, resourceDef, issuerB); err != nil {
				t.Fatalf("extension.Set: %v", err)
			}
			if _, err := c.BeginAuthorization(context.Background(), req); err != nil {
				t.Fatalf("BeginAuthorization(extension alone): %v", err)
			}
			as.lastPARForm = nil
			req.Resource = []string{issuerA}
			_, err := c.BeginAuthorization(context.Background(), req)
			assertInvalidRequest(t, err)
			if !strings.Contains(err.Error(), "Resource") {
				t.Errorf("error %q doesn't say to use Resource", err)
			}
			if as.lastPARForm != nil {
				t.Error("the request was pushed anyway")
			}
		})
	}
}

func assertInvalidRequest(t *testing.T, err error) {
	t.Helper()
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidRequest {
		t.Fatalf("err = %v, want invalid_request", err)
	}
}

// resourceRefreshClient is a client whose token endpoint records each
// refresh request's resource parameters in *got.
func resourceRefreshClient(t *testing.T, got *[]string) *client.Client {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		*got = r.PostForm["resource"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-2","token_type":"DPoP","expires_in":300}`))
	}))
	t.Cleanup(ts.Close)
	cfg, d := validConfig(t), validDependencies(t)
	oauthOnly(&cfg, &d)
	token, err := fapi.ParseEndpointURL(ts.URL+"/token", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Endpoints, cfg.RedirectURI, d.Sessions, d.HTTP = client.Endpoints{Token: token}, "", nil, ts.Client()
	c, err := client.New(cfg, d)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c
}

// TestRefreshTokensRepeatsOrNarrowsResources covers RFC 8707 §2.2 on
// refresh: the token set's resources by default, a subset of them when
// RefreshTokenRequest.Resource narrows, and the result records which.
func TestRefreshTokensRepeatsOrNarrowsResources(t *testing.T) {
	for name, tc := range map[string]struct {
		granted, narrowed, want []string
	}{
		"none":           {nil, nil, nil},
		"repeated":       {[]string{issuerA, issuerB}, nil, []string{issuerA, issuerB}},
		"narrowed":       {[]string{issuerA, issuerB}, []string{issuerB}, []string{issuerB}},
		"all, reordered": {[]string{issuerA, issuerB}, []string{issuerB, issuerA}, []string{issuerB, issuerA}},
	} {
		t.Run(name, func(t *testing.T) {
			var sent []string
			c := resourceRefreshClient(t, &sent)
			tokens := client.TokenSet{RefreshToken: fapi.NewSecret("rt-1"), HasRefreshToken: true, Issuer: testIssuer, Resource: tc.granted}
			refreshed, err := c.RefreshTokens(context.Background(), client.RefreshTokenRequest{Tokens: tokens, Resource: tc.narrowed})
			if err != nil {
				t.Fatalf("RefreshTokens: %v", err)
			}
			if !slices.Equal(sent, tc.want) {
				t.Errorf("refresh resource = %q, want %q", sent, tc.want)
			}
			if !slices.Equal(refreshed.Resource, tc.want) {
				t.Errorf("refreshed TokenSet.Resource = %q, want %q", refreshed.Resource, tc.want)
			}
		})
	}
}

// TestRefreshTokensRefusesWideningResources covers the client-side
// subset check: a refresh can't name a resource the token set wasn't
// obtained for, nor a malformed one, and a hand-built token set with a
// malformed resource is refused too — all before anything is sent.
func TestRefreshTokensRefusesWideningResources(t *testing.T) {
	for name, tc := range map[string]struct {
		granted, narrowed []string
	}{
		"other resource":    {[]string{issuerA}, []string{issuerB}},
		"one too many":      {[]string{issuerA}, []string{issuerA, issuerB}},
		"none granted":      {nil, []string{issuerA}},
		"repeated":          {[]string{issuerA}, []string{issuerA, issuerA}},
		"empty":             {[]string{issuerA}, []string{""}},
		"malformed granted": {[]string{"https://issuer-a.example/#f"}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			sent := []string{"not sent"}
			c := resourceRefreshClient(t, &sent)
			tokens := client.TokenSet{RefreshToken: fapi.NewSecret("rt-1"), HasRefreshToken: true, Issuer: testIssuer, Resource: tc.granted}
			_, err := c.RefreshTokens(context.Background(), client.RefreshTokenRequest{Tokens: tokens, Resource: tc.narrowed})
			assertInvalidRequest(t, err)
			if !slices.Equal(sent, []string{"not sent"}) {
				t.Error("the refresh was sent anyway")
			}
		})
	}
}

// TestTokenSetSealerKeepsResources covers a sealed set's resources
// surviving Open, and a set sealed before TokenSet.Resource existed —
// the same format without the member — still opening, with none.
func TestTokenSetSealerKeepsResources(t *testing.T) {
	s := sealer(t, testClientID, sealKey(1))
	tokens := client.TokenSet{AccessToken: fapi.NewSecret("at-1"), TokenType: "DPoP", Issuer: testIssuer, Resource: []string{issuerA, issuerB}}
	sealed, err := s.Seal(tokens, "user-1")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	opened, _, err := s.Open(sealed, "user-1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !slices.Equal(opened.Resource, tokens.Resource) {
		t.Errorf("opened Resource = %q, want %q", opened.Resource, tokens.Resource)
	}

	tokens.Resource = []string{"https://issuer-a.example/#f"}
	if _, err := s.Seal(tokens, "user-1"); err == nil {
		t.Error("Seal accepted a malformed resource")
	}

	legacySealed, err := base64.RawURLEncoding.DecodeString(legacySealedTokenSet)
	if err != nil {
		t.Fatal(err)
	}
	legacy, _, err := s.Open(legacySealed, "user-1")
	if err != nil {
		t.Fatalf("Open(legacy): %v", err)
	}
	if legacy.Resource != nil || legacy.AccessToken.Reveal() != "at-legacy" || legacy.RefreshToken.Reveal() != "rt-legacy" {
		t.Errorf("opened legacy set = %q, %q, %q; want at-legacy, rt-legacy, no resource",
			legacy.AccessToken.Reveal(), legacy.RefreshToken.Reveal(), legacy.Resource)
	}
}

// legacySealedTokenSet is a TokenSet (at-legacy, refresh token
// rt-legacy, no resources) that v0.56.0's TokenSetSealer sealed for
// "user-1", with sealKey(1), testClientID and testIssuer — before
// TokenSet.Resource existed.
const legacySealedTokenSet = "Aa4hbC505L8hvBlH9PYxEMCnWtB1FWOTKw6SLKMVOR6kJadOc9wp7CAWpwvMq5DZz-_o83uPZG_eGphUZfOEIUcKwwpDts3SLrlMY-YNgTlMXGanIAwV464iZc_46uE1K5TfbSy3FaQJWlbgBT8lg9eVCXu5EU3nTXEr4tEe6ACxKeL94sFPGhUEwVlNGAkEneg"

// TestBackchannelAuthenticationSendsResources is the CIBA counterpart:
// the resources go in the signed request object, survive sealing the
// session, are named again on the poll, and are the approved TokenSet's.
func TestBackchannelAuthenticationSendsResources(t *testing.T) {
	for name, tc := range map[string]struct {
		resources []string
		want      string
	}{
		"none":    {nil, ""},
		"one":     {[]string{issuerA}, `"https://issuer-a.example"`},
		"several": {[]string{issuerA, issuerB}, `["https://issuer-a.example","https://issuer-b.example/credentials"]`},
	} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClientWithCIBA(t)
			session, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
				Scope: []string{"openid", "accounts"}, LoginHint: "user@example.com", Resource: tc.resources,
			})
			if err != nil {
				t.Fatalf("BeginBackchannelAuthentication: %v", err)
			}
			if got := requestObjectParameter(t, as.lastBCForm.Get("request"), "resource"); got != tc.want {
				t.Errorf("request object resource = %s, want %s", got, tc.want)
			}
			as.tokenResponses = []cibaTokenResponse{{status: http.StatusOK, body: map[string]any{
				"access_token": "opaque-access-token", "token_type": "DPoP", "expires_in": 300, "scope": "openid accounts",
				"id_token": newCIBAIDToken(t, as),
			}}}
			result, err := c.PollBackchannelAuthentication(context.Background(), resealBackchannelSession(t, c, session))
			if err != nil {
				t.Fatalf("PollBackchannelAuthentication: %v", err)
			}
			if got := as.lastPollForm["resource"]; !slices.Equal(got, tc.resources) {
				t.Errorf("poll resource = %q, want %q", got, tc.resources)
			}
			approved, ok := result.(client.BackchannelAuthenticationApproved)
			if !ok {
				t.Fatalf("result = %T, want approved", result)
			}
			if !slices.Equal(approved.Tokens.Resource, tc.resources) {
				t.Errorf("TokenSet.Resource = %q, want %q", approved.Tokens.Resource, tc.resources)
			}
		})
	}
}

// TestBeginBackchannelAuthenticationRefusesBadResources covers CIBA's
// own validation, before anything is sent.
func TestBeginBackchannelAuthenticationRefusesBadResources(t *testing.T) {
	for name, resources := range map[string][]string{
		"relative": {"/credentials"},
		"fragment": {"https://issuer-a.example#f"},
		"repeated": {issuerA, issuerA},
	} {
		t.Run(name, func(t *testing.T) {
			c, as, _ := newTestClientWithCIBA(t)
			_, err := c.BeginBackchannelAuthentication(context.Background(), client.BeginBackchannelAuthenticationRequest{
				Scope: []string{"accounts"}, LoginHint: "user@example.com", Resource: resources,
			})
			assertInvalidRequest(t, err)
			if as.lastBCForm != nil {
				t.Error("the request was sent anyway")
			}
		})
	}
}

// TestPlainFormEscapesResources checks a resource's own reserved
// characters reach the server intact: each is form-encoded on its own.
func TestPlainFormEscapesResources(t *testing.T) {
	resources := []string{"https://issuer-a.example/path?x=1&y=2", "urn:example:resource+one"}
	c, as, _ := newTestClient(t, false)
	if _, err := c.BeginAuthorization(context.Background(), client.BeginAuthorizationRequest{
		Scope: []string{"openid"}, Resource: resources,
	}); err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	if got := as.lastPARForm["resource"]; !slices.Equal(got, resources) {
		t.Errorf("PAR resource = %q, want %q", got, resources)
	}
	if got := as.lastPARForm.Get("y"); got != "" {
		t.Errorf("a resource's query leaked out as its own parameter: y=%q", got)
	}
}
