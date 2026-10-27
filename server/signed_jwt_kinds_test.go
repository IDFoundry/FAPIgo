package server_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// signClientJWT signs claims with the harness client's key, under typ
// (none when empty): any of the JWT kinds a client signs with that one
// key — a client assertion, a request object, a CIBA request.
func signClientJWT(t *testing.T, h harness, typ string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	jwt, err := jose.Sign(h.key, jose.Header{Algorithm: fapi.ES256, Type: typ}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return jwt
}

// clientJWTClaims is the claims every client-signed JWT carries — iss,
// aud, jti and its times — plus extra.
func clientJWTClaims(h harness, jti string, extra map[string]any) map[string]any {
	claims := map[string]any{
		"iss": testClientID.String(), "aud": testIssuer, "jti": jti,
		"exp": h.now.Add(30 * time.Second).Unix(), "nbf": h.now.Unix(), "iat": h.now.Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	return claims
}

// capturedRequestObject is a typ-less request object carrying sub =
// client_id, as some client libraries sign one: its claims are a
// superset of a client assertion's.
func capturedRequestObject(h harness, jti string) map[string]any {
	return clientJWTClaims(h, jti, map[string]any{
		"sub": testClientID.String(), "client_id": testClientID.String(),
		"response_type": "code", "redirect_uri": testRedirectURI, "scope": "openid accounts",
		"code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256",
		"state": "s", "nonce": "n",
	})
}

// capturedBackchannelRequest is capturedRequestObject's CIBA
// counterpart.
func capturedBackchannelRequest(h harness, jti string) map[string]any {
	return clientJWTClaims(h, jti, map[string]any{
		"sub": testClientID.String(), "scope": "openid accounts", "login_hint": "user-1",
	})
}

// assertionClaims is a client assertion's claims (RFC 7523 §3).
func assertionClaims(h harness, jti string) map[string]any {
	return clientJWTClaims(h, jti, map[string]any{"sub": testClientID.String()})
}

// clientAuthenticatedEndpoint calls one endpoint that authenticates the
// client, presenting assertion as its client_assertion.
type clientAuthenticatedEndpoint struct {
	harness func(t *testing.T) harness
	call    func(t *testing.T, h harness, assertion string) error
}

func assertionParams(assertion string, params ...server.FormParameter) []server.FormParameter {
	return append([]server.FormParameter{
		formParam("client_assertion", assertion),
		formParam("client_assertion_type", clientassertion.AssertionType),
	}, params...)
}

func clientAuthenticatedEndpoints() map[string]clientAuthenticatedEndpoint {
	plain := func(t *testing.T) harness { return newHarness(t, server.ProfileFAPISecurity, true) }
	ciba := func(t *testing.T) harness { h, _ := newHarnessWithBackchannel(t); return h }
	return map[string]clientAuthenticatedEndpoint{
		"PAR": {plain, func(t *testing.T, h harness, assertion string) error {
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
			})
			return err
		}},
		"authorization code": {plain, func(t *testing.T, h harness, assertion string) error {
			_, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
				HTTP:       server.FormRequest{Parameters: exchangeFormParams(assertion, "unknown-code", testRedirectURI, testCodeVerifier)},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			return err
		}},
		"refresh": {plain, func(t *testing.T, h harness, assertion string) error {
			_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
				HTTP:       server.FormRequest{Parameters: refreshFormParams(assertion, "unknown-refresh-token", "")},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			return err
		}},
		"client credentials": {func(t *testing.T) harness {
			return newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)
		}, func(t *testing.T, h harness, assertion string) error {
			_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
				HTTP:       server.FormRequest{Parameters: clientCredentialsFormParams(assertion, "accounts")},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			return err
		}},
		"CIBA token": {ciba, func(t *testing.T, h harness, assertion string) error {
			_, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
				HTTP: server.FormRequest{Parameters: assertionParams(assertion,
					formParam("grant_type", server.CIBAGrantType), formParam("auth_req_id", "unknown-auth-req-id"))},
				DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
			})
			return err
		}},
		"revocation": {func(t *testing.T) harness {
			return newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), func(c *server.Config) {
				revocation, err := fapi.ParseEndpointURL(testRevocationEndpoint)
				if err != nil {
					t.Fatal(err)
				}
				c.Endpoints.Revocation = revocation
			}, func(d *server.Dependencies) { d.Revocation = &fakeRevocationSink{} })
		}, func(_ *testing.T, h harness, assertion string) error {
			_, err := h.server.RevokeToken(context.Background(), server.TokenRevocationRequest{
				HTTP: server.FormRequest{Parameters: assertionParams(assertion, formParam("token", "unknown-token"))},
			})
			return err
		}},
	}
}

// TestSignedRequestRefusedAsClientAssertion: a request object or a CIBA
// request the client signed — typ-less, with sub = client_id, which RFC
// 9101 doesn't forbid of the client — is refused as that client's
// client_assertion at every endpoint that authenticates a client, so
// whoever later reads one (an audit log, a debugging proxy) can't
// authenticate as the client with it.
func TestSignedRequestRefusedAsClientAssertion(t *testing.T) {
	captured := map[string]func(harness, string) map[string]any{
		"request object": capturedRequestObject,
		"CIBA request":   capturedBackchannelRequest,
	}
	for endpointName, endpoint := range clientAuthenticatedEndpoints() {
		for kind, claims := range captured {
			t.Run(endpointName+"/"+kind, func(t *testing.T) {
				h := endpoint.harness(t)
				jwt := signClientJWT(t, h, "", claims(h, "captured-"+kind))
				requireServerErrorCode(t, endpoint.call(t, h, jwt), server.ErrorInvalidClient)
			})
		}
	}
}

// TestPushedRequestObjectReplayedForClientCredentials: the whole chain —
// the client pushes a typ-less request object carrying sub, and someone
// who reads it presents it as the client's client_assertion for a
// client_credentials token bound to their own DPoP key. The request
// object is refused at PAR, and the replay at the token endpoint.
func TestPushedRequestObjectReplayedForClientCredentials(t *testing.T) {
	base := newHarnessWithClientCredentialsGrant(t, storage.SenderConstrainDPoP, true)
	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                           testClientID,
		RedirectURIs:                 []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm:     fapi.ES256,
		RequestObjectAlgorithm:       fapi.ES256,
		SenderConstrain:              storage.SenderConstrainDPoP,
		AllowedScopes:                []string{"openid", "accounts"},
		AllowsClientCredentialsGrant: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, deps := base.cfg, base.deps
	cfg.Profile = server.ProfileFAPISecurityWithMessageSigning
	deps.Clients = &fakeClientRepository{clients: map[fapi.ClientID]storage.RegisteredClient{testClientID: client}}
	deps.Replay = memstore.NewReplayStore()
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	obj := signClientJWT(t, base, "", capturedRequestObject(base, "ro-1"))

	_, err = srv.PushAuthorizationRequest(ctx, server.PushAuthorizationRequest{HTTP: server.FormRequest{
		Parameters: assertionParams(base.clientAssertion(t), formParam("client_id", testClientID.String()), formParam("request", obj)),
	}})
	requireServerErrorCode(t, err, server.ErrorInvalidRequestObject)

	_, err = srv.RequestClientCredentialsToken(ctx, server.ClientCredentialsTokenRequest{
		HTTP:       server.FormRequest{Parameters: clientCredentialsFormParams(obj, "accounts")},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), base.now)},
	})
	requireServerErrorCode(t, err, server.ErrorInvalidClient)
}

// TestBackchannelRequestReplayedAsClientAssertion is
// TestPushedRequestObjectReplayedForClientCredentials for a CIBA
// request, replayed at the CIBA token endpoint.
func TestBackchannelRequestReplayedAsClientAssertion(t *testing.T) {
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), nil, func(d *server.Dependencies) { d.Replay = memstore.NewReplayStore() })
	ctx := context.Background()
	obj := signClientJWT(t, h, "", capturedBackchannelRequest(h, "ciba-req-1"))
	action, err := h.server.BeginBackchannelAuthentication(ctx, server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), obj)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if local, ok := action.(server.BackchannelAuthenticationLocalError); !ok || local.Error.Code() != server.ErrorInvalidRequest {
		t.Fatalf("Begin = %T, want invalid_request", action)
	}
	_, err = h.server.ExchangeBackchannelAuthentication(ctx, server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: assertionParams(obj,
			formParam("grant_type", server.CIBAGrantType), formParam("auth_req_id", "unknown-auth-req-id"))},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	requireServerErrorCode(t, err, server.ErrorInvalidClient)
}

// TestRequestObjectWithSubjectRefused: RFC 9101 §10.8 and RFC 8725
// §3.12 have JWT kinds signed with one key kept apart; a request object
// or CIBA request from any client — not only one registered
// automatically through OpenID Federation — carrying sub, the claim a
// client assertion authenticates by, is refused.
func TestRequestObjectWithSubjectRefused(t *testing.T) {
	for name, sub := range map[string]string{"client_id": testClientID.String(), "other": "someone-else"} {
		t.Run("PAR/"+name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			params := standardAuthParams(t)
			params["sub"] = jsonRaw(t, sub)
			requireServerErrorCode(t, pushRequestObject(t, h, h.requestObject(t, params)), server.ErrorInvalidRequestObject)
		})
		t.Run("CIBA/"+name, func(t *testing.T) {
			h, _ := newHarnessWithBackchannel(t)
			params := standardBackchannelParams(t)
			params["sub"] = jsonRaw(t, sub)
			requireBackchannelErrorCode(t, h, h.backchannelRequestObject(t, params), server.ErrorInvalidRequest)
		})
	}
}

// TestClientAssertionWithRequestClaimsRefused: a client assertion
// carrying a claim only an authorization or CIBA request carries is a
// request, not an assertion, and is refused.
func TestClientAssertionWithRequestClaimsRefused(t *testing.T) {
	requestClaims := []string{
		"response_type", "redirect_uri", "scope", "client_notification_token", "login_hint",
		"login_hint_token", "id_token_hint", "binding_message", "request", "request_uri",
		"code_challenge", "authorization_details", "claims", "nonce", "state",
	}
	for _, name := range requestClaims {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, server.ProfileFAPISecurity, true)
			claims := assertionClaims(h, "assertion-"+name)
			claims[name] = "x"
			_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
				HTTP: server.FormRequest{Parameters: plainFormParameters(t, signClientJWT(t, h, "", claims), nil)},
			})
			requireServerErrorCode(t, err, server.ErrorInvalidClient)
		})
	}
}

// TestClientSignedJWTsShareOneReplayNamespace: a jti the client used in
// one kind of signed JWT is spent for every other kind, whichever was
// first.
func TestClientSignedJWTsShareOneReplayNamespace(t *testing.T) {
	const jti = "shared-jti"
	t.Run("request object, then assertion", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		obj := signClientJWT(t, h, "oauth-authz-req+jwt", clientJWTClaims(h, jti, requestObjectClaims(t)))
		if err := pushRequestObject(t, h, obj); err != nil {
			t.Fatalf("PAR with the request object: %v", err)
		}
		_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
			HTTP: server.FormRequest{Parameters: plainFormParameters(t, signClientJWT(t, h, "", assertionClaims(h, jti)), nil)},
		})
		requireServerErrorCode(t, err, server.ErrorInvalidClient)
	})
	t.Run("assertion, then request object", func(t *testing.T) {
		h := newHarness(t, server.ProfileFAPISecurity, true)
		_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
			HTTP: server.FormRequest{Parameters: plainFormParameters(t, signClientJWT(t, h, "", assertionClaims(h, jti)), nil)},
		})
		if err != nil {
			t.Fatalf("PAR with the assertion: %v", err)
		}
		obj := signClientJWT(t, h, "oauth-authz-req+jwt", clientJWTClaims(h, jti, requestObjectClaims(t)))
		requireServerErrorCode(t, pushRequestObject(t, h, obj), server.ErrorInvalidRequestObject)
	})
	t.Run("CIBA request, then assertion", func(t *testing.T) {
		h, _ := newHarnessWithBackchannel(t)
		obj := signClientJWT(t, h, "", clientJWTClaims(h, jti, map[string]any{"scope": "openid accounts", "login_hint": "user-1"}))
		requireBackchannelAccepted(t, h, h.clientAssertion(t), obj)
		_, err := h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
			HTTP: server.FormRequest{Parameters: assertionParams(signClientJWT(t, h, "", assertionClaims(h, jti)),
				formParam("grant_type", server.CIBAGrantType), formParam("auth_req_id", "unknown-auth-req-id"))},
			DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
		})
		requireServerErrorCode(t, err, server.ErrorInvalidClient)
	})
	t.Run("assertion, then CIBA request", func(t *testing.T) {
		h, _ := newHarnessWithBackchannel(t)
		assertion := signClientJWT(t, h, "", assertionClaims(h, jti))
		requireBackchannelAccepted(t, h, assertion, h.backchannelRequestObject(t, standardBackchannelParams(t)))
		obj := signClientJWT(t, h, "", clientJWTClaims(h, jti, map[string]any{"scope": "openid accounts", "login_hint": "user-1"}))
		requireBackchannelErrorCode(t, h, obj, server.ErrorInvalidRequest)
	})
}

// requestObjectClaims is standardAuthParams as plain values, plus
// client_id.
func requestObjectClaims(t *testing.T) map[string]any {
	t.Helper()
	out := map[string]any{"client_id": testClientID.String()}
	for k, v := range standardAuthParams(t) {
		out[k] = v
	}
	return out
}

func pushRequestObject(t *testing.T, h harness, obj string) error {
	t.Helper()
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: assertionParams(h.clientAssertion(t), formParam("request", obj))},
	})
	return err
}

func requireBackchannelAccepted(t *testing.T, h harness, assertion, obj string) {
	t.Helper()
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(assertion, obj)},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	if _, ok := action.(server.BackchannelInteractionRequired); !ok {
		t.Fatalf("BeginBackchannelAuthentication = %T, want BackchannelInteractionRequired", action)
	}
}

func requireBackchannelErrorCode(t *testing.T, h harness, obj string, want server.ErrorCode) {
	t.Helper()
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(h.clientAssertion(t), obj)},
	})
	if err != nil {
		requireServerErrorCode(t, err, want)
		return
	}
	local, ok := action.(server.BackchannelAuthenticationLocalError)
	if !ok {
		t.Fatalf("BeginBackchannelAuthentication = %T, want %s", action, want)
	}
	if local.Error.Code() != want {
		t.Fatalf("BeginBackchannelAuthentication = %v, want %s", local.Error, want)
	}
}

func requireServerErrorCode(t *testing.T, err error, want server.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", want)
	}
	if got := serverErrorCode(t, err); got != want {
		t.Fatalf("error = %v (%s), want %s", err, got, want)
	}
}
