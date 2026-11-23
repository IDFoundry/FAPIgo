package server_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
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

// testMTLSTokenEndpoint is the RFC 8705 §5 mTLS alias of the token
// endpoint newMTLSCIBAAudienceHarness configures.
const testMTLSTokenEndpoint = "https://mtls.as.example/token"

// clientAuthenticationType is the explicit typ RFC 10070 §4 gives a
// client assertion, with which a client says it follows that
// specification's audience rule.
const clientAuthenticationType = "client-authentication+jwt"

// issuerOnlyAudienceDescription is the error_description of a client
// assertion refused for an aud other than the issuer, where only the
// issuer is accepted.
const issuerOnlyAudienceDescription = "client assertion aud must be the authorization server's issuer identifier"

// withCIBAEndpointURLAudiences turns Config.CIBAEndpointURLAudiences on.
func withCIBAEndpointURLAudiences(cfg *server.Config) { cfg.CIBAEndpointURLAudiences = true }

// newCIBAAudienceHarness is newHarnessWithBackchannel with
// Config.CIBAEndpointURLAudiences set to optIn, and a revocation store
// it can read, so each grant records the grant ID a grant without a
// recorded type needs to be refreshed at all (see
// untypedCIBAGrantRefreshToken).
func newCIBAAudienceHarness(t *testing.T, optIn bool) harness {
	t.Helper()
	return newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), func(cfg *server.Config) {
		cfg.CIBAEndpointURLAudiences = optIn
	}, func(deps *server.Dependencies) {
		deps.Revocation = memstore.NewRevocationStore()
	})
}

// newMTLSCIBAAudienceHarness is newCIBAAudienceHarness with testClientID
// registered SenderConstrainMTLS, and testMTLSTokenEndpoint as the token
// endpoint's mTLS alias.
func newMTLSCIBAAudienceHarness(t *testing.T, optIn bool) harness {
	t.Helper()
	alias, err := fapi.ParseEndpointURL(testMTLSTokenEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), func(cfg *server.Config) {
		cfg.CIBAEndpointURLAudiences = optIn
		cfg.MTLSEndpoints = server.MTLSEndpoints{Token: alias}
	}, func(deps *server.Dependencies) {
		registerAudienceTestClient(t, deps, storage.SenderConstrainMTLS, true)
	})
}

// registerAudienceTestClient replaces testClientID's registration in
// deps with one sender-constrained by senderConstrain, and registered
// for CIBA only when ciba is set.
func registerAudienceTestClient(t *testing.T, deps *server.Dependencies, senderConstrain storage.SenderConstrain, ciba bool) {
	t.Helper()
	registration := storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		SenderConstrain:          senderConstrain,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
	}
	if ciba {
		registration.BackchannelAuthenticationRequestAlgorithm = fapi.ES256
	}
	client, err := storage.NewRegisteredClient(registration)
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}
	deps.Clients.(*fakeClientRepository).clients[testClientID] = client
}

// typedAssertion signs a client assertion for testClientID naming aud,
// with typ as its header's typ, or none when typ is empty.
func typedAssertion(t *testing.T, h harness, aud, typ string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"iss": testClientID.String(), "sub": testClientID.String(), "aud": aud, "jti": rand.Text(),
		"iat": h.now.Unix(), "exp": h.now.Add(30 * time.Second).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := jose.Sign(h.key, jose.Header{Algorithm: fapi.ES256, Type: typ}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return assertion
}

// senderBinding sender-constrains a test's token request: with cert, a
// SenderConstrainMTLS client's certificate, when set, or else a DPoP
// proof from a fresh key.
type senderBinding struct{ cert *x509.Certificate }

// dpopProofs is the request's DPoP header values for b.
func (b senderBinding) dpopProofs(t *testing.T, h harness) []string {
	t.Helper()
	if b.cert != nil {
		return nil
	}
	return []string{createDPoPProof(t, generateKey(t), h.now)}
}

// beginOutcome is the error code BeginBackchannelAuthentication answers
// a request authenticated by assertion with: "" when it accepts it.
func beginOutcome(t *testing.T, h harness, assertion string) server.ErrorCode {
	t.Helper()
	action, err := h.server.BeginBackchannelAuthentication(context.Background(), server.BeginBackchannelAuthenticationRequest{
		HTTP: server.FormRequest{Parameters: backchannelFormParams(assertion, h.backchannelRequestObject(t, standardBackchannelParams(t)))},
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	if local, ok := action.(server.BackchannelAuthenticationLocalError); ok {
		return local.Error.Code()
	}
	return ""
}

// pollBackchannelWith polls for authReqID with a token request
// authenticated by assertion.
func pollBackchannelWith(t *testing.T, h harness, authReqID, assertion string, b senderBinding) (server.TokenResult, error) {
	t.Helper()
	return h.server.ExchangeBackchannelAuthentication(context.Background(), server.BackchannelTokenExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", assertion),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", server.CIBAGrantType),
			formParam("auth_req_id", authReqID),
		}},
		DPoPProofs:      b.dpopProofs(t, h),
		PeerCertificate: b.cert,
	})
}

// refreshWithAssertion refreshes refreshToken with a request
// authenticated by assertion and sender-constrained by b.
func refreshWithAssertion(t *testing.T, h harness, assertion, refreshToken string, b senderBinding) error {
	t.Helper()
	_, err := h.server.RefreshAccessToken(context.Background(), server.RefreshTokenRequest{
		HTTP:            server.FormRequest{Parameters: refreshFormParams(assertion, refreshToken, "")},
		DPoPProofs:      b.dpopProofs(t, h),
		PeerCertificate: b.cert,
	})
	return err
}

// codeGrantRefreshToken authorizes "openid accounts offline_access" and
// exchanges the code, its token request bound by b, returning the
// authorization code grant's refresh token.
func codeGrantRefreshToken(t *testing.T, h harness, b senderBinding) string {
	t.Helper()
	code := completeSuccessfulAuthorization(t, h, []string{"openid", "accounts", "offline_access"})
	tokens, err := h.server.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP:            server.FormRequest{Parameters: exchangeFormParams(h.clientAssertion(t), code, testRedirectURI, testCodeVerifier)},
		DPoPProofs:      b.dpopProofs(t, h),
		PeerCertificate: b.cert,
	})
	if err != nil || !tokens.HasRefreshToken {
		t.Fatalf("ExchangeAuthorizationCode = %v (refresh token %v), want a refresh token", err, tokens.HasRefreshToken)
	}
	return tokens.RefreshToken.Reveal()
}

// cibaGrantRefreshToken runs a CIBA flow approving "openid accounts
// offline_access", its token request authenticated by an issuer
// assertion and bound by b, and returns the CIBA grant's refresh token.
func cibaGrantRefreshToken(t *testing.T, h harness, b senderBinding) string {
	t.Helper()
	params := standardBackchannelParams(t)
	params["scope"] = jsonRaw(t, "openid accounts offline_access")
	required := beginBackchannel(t, h, params)
	subject, err := server.NewSubjectID("user-1")
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := server.NewAuthenticatedSubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	authCtx, err := server.NewAuthenticationContext(h.now, "", []string{"pwd"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.server.CompleteBackchannelAuthentication(context.Background(), server.CompleteBackchannelAuthenticationRequest{
		Handle: required.Handle,
		Result: server.Authorize(authenticated, authCtx, server.GrantedAuthorization{Scope: []string{"openid", "accounts", "offline_access"}}),
	}); err != nil {
		t.Fatalf("CompleteBackchannelAuthentication: %v", err)
	}
	tokens, err := pollBackchannelWith(t, h, required.AuthReqID.String(), h.clientAssertion(t), b)
	if err != nil || !tokens.HasRefreshToken {
		t.Fatalf("ExchangeBackchannelAuthentication = %v (refresh token %v), want a refresh token", err, tokens.HasRefreshToken)
	}
	return tokens.RefreshToken.Reveal()
}

// untypedCIBAGrantRefreshToken is cibaGrantRefreshToken with the
// grant's record as a server before v0.61.0 wrote it, with no grant
// type: a CIBA grant the record doesn't say is one.
func untypedCIBAGrantRefreshToken(t *testing.T, h harness, b senderBinding) string {
	t.Helper()
	refreshToken := cibaGrantRefreshToken(t, h, b)
	grants := h.deps.Grants.(*fakeGrantStore)
	grants.mu.Lock()
	defer grants.mu.Unlock()
	for hash, rec := range grants.refreshByHash {
		rec.Grant = withoutGrantType(t, rec.Grant)
		grants.refreshByHash[hash] = rec
	}
	return refreshToken
}

// withoutGrantType is record without the grant_type every grant record
// has carried since v0.61.0.
func withoutGrantType(t *testing.T, record json.RawMessage) json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(record, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["grant_type"]; !ok {
		t.Fatalf("record %s has no grant_type to remove", record)
	}
	delete(fields, "grant_type")
	stripped, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return stripped
}

// TestCIBAEndpointURLAudiencesAtBackchannelEndpoint: by default the
// backchannel authentication endpoint accepts only the issuer as a
// client assertion's aud (RFC 10070 §4). Config.CIBAEndpointURLAudiences
// adds CIBA Core 1.0 §7.1's token and backchannel endpoint URLs, but
// not another endpoint's, and not from an assertion typed
// client-authentication+jwt, whose client says it follows RFC 10070.
// Any other typ isn't explicit: neither none, which the OIDF FAPI-CIBA
// suite sends, nor a generic one, nor one this package doesn't know.
func TestCIBAEndpointURLAudiencesAtBackchannelEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name     string
		optIn    bool
		aud, typ string
		want     server.ErrorCode
	}{
		{"default, issuer", false, testIssuer, "", ""},
		{"default, token endpoint URL", false, testTokenEndpoint, "", server.ErrorInvalidClient},
		{"default, backchannel endpoint URL", false, testBackchannelAuthenticationEndpoint, "", server.ErrorInvalidClient},
		{"opted in, token endpoint URL", true, testTokenEndpoint, "", ""},
		{"opted in, backchannel endpoint URL", true, testBackchannelAuthenticationEndpoint, "", ""},
		{"opted in, token endpoint URL typed JWT", true, testTokenEndpoint, "JWT", ""},
		{"opted in, token endpoint URL typed JOSE", true, testTokenEndpoint, "JOSE", ""},
		{"opted in, token endpoint URL with an unknown type", true, testTokenEndpoint, "example-client-authentication+jwt", ""},
		{"opted in, token endpoint URL explicitly typed", true, testTokenEndpoint, clientAuthenticationType, server.ErrorInvalidClient},
		{"opted in, backchannel endpoint URL explicitly typed", true, testBackchannelAuthenticationEndpoint, "application/" + clientAuthenticationType, server.ErrorInvalidClient},
		{"opted in, issuer explicitly typed", true, testIssuer, clientAuthenticationType, ""},
		{"opted in, PAR endpoint URL", true, testPAREndpoint, "", server.ErrorInvalidClient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCIBAAudienceHarness(t, tc.optIn)
			if got := beginOutcome(t, h, typedAssertion(t, h, tc.aud, tc.typ)); got != tc.want {
				t.Errorf("BeginBackchannelAuthentication = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCIBAEndpointURLAudiencesMTLSAliasAtBackchannelEndpoint: for a
// client registered SenderConstrainMTLS, the backchannel endpoint's mTLS
// alias is refused by default like the plain URL, and accepted with it
// under Config.CIBAEndpointURLAudiences.
func TestCIBAEndpointURLAudiencesMTLSAliasAtBackchannelEndpoint(t *testing.T) {
	for optIn, want := range map[bool]server.ErrorCode{false: server.ErrorInvalidClient, true: ""} {
		h := newHarnessWithBackchannelMTLSConfig(t, func(cfg *server.Config) { cfg.CIBAEndpointURLAudiences = optIn })
		if got := beginOutcome(t, h, typedAssertion(t, h, testMTLSBackchannelAuthenticationEndpoint, "")); got != want {
			t.Errorf("opted in %v: BeginBackchannelAuthentication with the mTLS alias = %q, want %q", optIn, got, want)
		}
	}
}

// newDPoPCIBAAudienceHarness is newCIBAAudienceHarness opted in, with
// testClientID registered SenderConstrainDPoP for CIBA, and mTLS aliases
// for the token and backchannel authentication endpoints.
func newDPoPCIBAAudienceHarness(t *testing.T) harness {
	t.Helper()
	tokenAlias, err := fapi.ParseEndpointURL(testMTLSTokenEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	backchannelAlias, err := fapi.ParseEndpointURL(testMTLSBackchannelAuthenticationEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), func(cfg *server.Config) {
		cfg.CIBAEndpointURLAudiences = true
		cfg.MTLSEndpoints = server.MTLSEndpoints{Token: tokenAlias, BackchannelAuthentication: backchannelAlias}
	}, func(deps *server.Dependencies) {
		registerAudienceTestClient(t, deps, storage.SenderConstrainDPoP, true)
	})
}

// TestCIBAEndpointURLAudiencesMTLSAliasesOnlyForMTLSClients: under
// Config.CIBAEndpointURLAudiences, an endpoint's mTLS alias is accepted
// only from a client registered SenderConstrainMTLS. A DPoP-bound CIBA
// client naming the backchannel or token endpoint's alias is refused
// with invalid_client at the backchannel authentication endpoint, and
// naming the token endpoint's alias to refresh its CIBA grant, while
// the plain URLs authenticate it.
func TestCIBAEndpointURLAudiencesMTLSAliasesOnlyForMTLSClients(t *testing.T) {
	h := newDPoPCIBAAudienceHarness(t)
	for aud, want := range map[string]server.ErrorCode{
		testMTLSBackchannelAuthenticationEndpoint: server.ErrorInvalidClient,
		testMTLSTokenEndpoint:                     server.ErrorInvalidClient,
		testBackchannelAuthenticationEndpoint:     "",
	} {
		if got := beginOutcome(t, h, typedAssertion(t, h, aud, "")); got != want {
			t.Errorf("BeginBackchannelAuthentication naming %s = %q, want %q", aud, got, want)
		}
	}
	for aud, want := range map[string]server.ErrorCode{testMTLSTokenEndpoint: server.ErrorInvalidClient, testTokenEndpoint: ""} {
		refreshToken := cibaGrantRefreshToken(t, h, senderBinding{})
		requireTokenOutcome(t, refreshWithAssertion(t, h, typedAssertion(t, h, aud, ""), refreshToken, senderBinding{}), want)
	}
}

// TestCIBAEndpointURLAudiencesAtCIBATokenRequest: the CIBA token request
// accepts the token endpoint URL only under
// Config.CIBAEndpointURLAudiences, and never the backchannel endpoint's,
// which CIBA Core 1.0 §7.1 lists for the backchannel endpoint alone.
// authorization_pending means the client authenticated.
func TestCIBAEndpointURLAudiencesAtCIBATokenRequest(t *testing.T) {
	for _, tc := range []struct {
		name     string
		optIn    bool
		aud, typ string
		want     server.ErrorCode
	}{
		{"default, issuer", false, testIssuer, "", server.ErrorAuthorizationPending},
		{"default, token endpoint URL", false, testTokenEndpoint, "", server.ErrorInvalidClient},
		{"opted in, token endpoint URL", true, testTokenEndpoint, "", server.ErrorAuthorizationPending},
		{"opted in, token endpoint URL explicitly typed", true, testTokenEndpoint, clientAuthenticationType, server.ErrorInvalidClient},
		{"opted in, backchannel endpoint URL", true, testBackchannelAuthenticationEndpoint, "", server.ErrorInvalidClient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCIBAAudienceHarness(t, tc.optIn)
			required := beginBackchannel(t, h, standardBackchannelParams(t))
			_, err := pollBackchannelWith(t, h, required.AuthReqID.String(), typedAssertion(t, h, tc.aud, tc.typ), senderBinding{})
			if got := serverErrorCode(t, err); got != tc.want {
				t.Errorf("ExchangeBackchannelAuthentication = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCIBATokenRequestDescribesTheIssuerAudience: by default, the CIBA
// token request's aud mismatch names the issuer alone, as every other
// endpoint's does.
func TestCIBATokenRequestDescribesTheIssuerAudience(t *testing.T) {
	h := newCIBAAudienceHarness(t, false)
	required := beginBackchannel(t, h, standardBackchannelParams(t))
	_, err := pollBackchannelWith(t, h, required.AuthReqID.String(), typedAssertion(t, h, testTokenEndpoint, ""), senderBinding{})
	if got := serverErrorDescription(t, err); got != issuerOnlyAudienceDescription {
		t.Errorf("error_description = %q, want %q", got, issuerOnlyAudienceDescription)
	}
}

// TestCIBAEndpointURLAudiencesAtRefresh: a refresh's client assertion
// names the issuer, whichever grant the refresh token is from. Under
// Config.CIBAEndpointURLAudiences a CIBA client may name the token
// endpoint URL instead, but only to refresh a CIBA grant: not an
// authorization code grant (FAPI 2.0 Security Profile §5.3.2.1), and
// not a grant whose type was never recorded, which may be either. Only
// the redeemed grant tells which it is, so the code grant's refusal
// comes after redemption, and is what keeps an attacker holding the
// code grant's refresh token and an assertion its client signed for
// another server from getting an access token bound to its own key.
func TestCIBAEndpointURLAudiencesAtRefresh(t *testing.T) {
	for _, tc := range []struct {
		name     string
		grant    func(*testing.T, harness, senderBinding) string
		optIn    bool
		aud, typ string
		want     server.ErrorCode
	}{
		{"code grant, issuer", codeGrantRefreshToken, true, testIssuer, "", ""},
		{"code grant, token endpoint URL", codeGrantRefreshToken, true, testTokenEndpoint, "", server.ErrorInvalidClient},
		{"code grant, token endpoint URL by default", codeGrantRefreshToken, false, testTokenEndpoint, "", server.ErrorInvalidClient},
		{"CIBA grant, issuer by default", cibaGrantRefreshToken, false, testIssuer, "", ""},
		{"CIBA grant, token endpoint URL by default", cibaGrantRefreshToken, false, testTokenEndpoint, "", server.ErrorInvalidClient},
		{"CIBA grant, token endpoint URL", cibaGrantRefreshToken, true, testTokenEndpoint, "", ""},
		{"CIBA grant, token endpoint URL explicitly typed", cibaGrantRefreshToken, true, testTokenEndpoint, clientAuthenticationType, server.ErrorInvalidClient},
		{"CIBA grant, backchannel endpoint URL", cibaGrantRefreshToken, true, testBackchannelAuthenticationEndpoint, "", server.ErrorInvalidClient},
		{"untyped grant, issuer", untypedCIBAGrantRefreshToken, true, testIssuer, "", ""},
		{"untyped grant, token endpoint URL", untypedCIBAGrantRefreshToken, true, testTokenEndpoint, "", server.ErrorInvalidClient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCIBAAudienceHarness(t, tc.optIn)
			refreshToken := tc.grant(t, h, senderBinding{})
			requireTokenOutcome(t, refreshWithAssertion(t, h, typedAssertion(t, h, tc.aud, tc.typ), refreshToken, senderBinding{}), tc.want)
		})
	}
}

// TestCIBAEndpointURLAudiencesAtRefreshMTLS: for a CIBA client
// registered SenderConstrainMTLS, Config.CIBAEndpointURLAudiences covers
// the token endpoint's mTLS alias too, again only to refresh a CIBA
// grant, so a refresh of a code grant naming either URL is refused and
// no access token is bound to the certificate it presents.
func TestCIBAEndpointURLAudiencesAtRefreshMTLS(t *testing.T) {
	for _, tc := range []struct {
		name  string
		grant func(*testing.T, harness, senderBinding) string
		optIn bool
		aud   string
		want  server.ErrorCode
	}{
		{"code grant, mTLS alias", codeGrantRefreshToken, true, testMTLSTokenEndpoint, server.ErrorInvalidClient},
		{"code grant, token endpoint URL", codeGrantRefreshToken, true, testTokenEndpoint, server.ErrorInvalidClient},
		{"code grant, issuer", codeGrantRefreshToken, true, testIssuer, ""},
		{"CIBA grant, mTLS alias", cibaGrantRefreshToken, true, testMTLSTokenEndpoint, ""},
		{"CIBA grant, mTLS alias by default", cibaGrantRefreshToken, false, testMTLSTokenEndpoint, server.ErrorInvalidClient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newMTLSCIBAAudienceHarness(t, tc.optIn)
			refreshToken := tc.grant(t, h, senderBinding{cert: selfSignedTestClientCert(t)})
			other := senderBinding{cert: selfSignedTestClientCert(t)}
			requireTokenOutcome(t, refreshWithAssertion(t, h, typedAssertion(t, h, tc.aud, ""), refreshToken, other), tc.want)
		})
	}
}

// TestCIBAEndpointURLAudienceAssertionIsSingleUse: an assertion naming
// the token endpoint URL refreshes a CIBA grant once. Its jti is spent
// whether or not the refresh goes on to succeed, so a second refresh
// with it is refused as a replay, with the generic description, for a
// code grant too, where the first was already refused for its aud.
func TestCIBAEndpointURLAudienceAssertionIsSingleUse(t *testing.T) {
	for name, tc := range map[string]struct {
		grant func(*testing.T, harness, senderBinding) string
		first server.ErrorCode
	}{
		"CIBA grant": {cibaGrantRefreshToken, ""},
		"code grant": {codeGrantRefreshToken, server.ErrorInvalidClient},
	} {
		t.Run(name, func(t *testing.T) {
			h := newCIBAAudienceHarness(t, true)
			refreshToken := tc.grant(t, h, senderBinding{})
			assertion := typedAssertion(t, h, testTokenEndpoint, "")
			requireTokenOutcome(t, refreshWithAssertion(t, h, assertion, refreshToken, senderBinding{}), tc.first)
			err := refreshWithAssertion(t, h, assertion, refreshToken, senderBinding{})
			requireTokenOutcome(t, err, server.ErrorInvalidClient)
			if got := serverErrorDescription(t, err); got != "client assertion verification failed" {
				t.Errorf("replayed assertion: error_description = %q, want the generic one", got)
			}
		})
	}
}

// TestRevokeTokenAcceptsTheIssuerAudienceAlone: revocation accepts only
// the issuer as a client assertion's aud, even under
// Config.CIBAEndpointURLAudiences, since CIBA Core 1.0 §7.1 names no
// revocation endpoint. An assertion naming the revocation or token
// endpoint URL doesn't revoke a CIBA client's live refresh token, which
// still refreshes afterwards; one naming the issuer does.
func TestRevokeTokenAcceptsTheIssuerAudienceAlone(t *testing.T) {
	revocation, err := fapi.ParseEndpointURL(testRevocationEndpoint)
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	for _, tc := range []struct {
		aud               string
		want, wantRefresh server.ErrorCode
	}{
		{testRevocationEndpoint, server.ErrorInvalidClient, ""},
		{testTokenEndpoint, server.ErrorInvalidClient, ""},
		{testIssuer, "", server.ErrorInvalidGrant},
	} {
		t.Run(tc.aud, func(t *testing.T) {
			h := newHarnessWithBackchannelConfig(t, memstore.NewBackchannelAuthenticationStore(), func(cfg *server.Config) {
				cfg.CIBAEndpointURLAudiences = true
				cfg.Endpoints.Revocation = revocation
			})
			refreshToken := codeGrantRefreshToken(t, h, senderBinding{})
			_, err := h.server.RevokeToken(context.Background(), server.TokenRevocationRequest{
				HTTP: server.FormRequest{Parameters: []server.FormParameter{
					formParam("client_assertion", typedAssertion(t, h, tc.aud, "")),
					formParam("client_assertion_type", clientassertion.AssertionType),
					formParam("token", refreshToken),
				}},
			})
			requireTokenOutcome(t, err, tc.want)
			requireTokenOutcome(t, refreshWithAssertion(t, h, h.clientAssertion(t), refreshToken, senderBinding{}), tc.wantRefresh)
		})
	}
}

// TestCIBAEndpointURLAudiencesNeedACIBAEndpoint:
// Config.CIBAEndpointURLAudiences has no effect on a server that serves
// no backchannel authentication endpoint. Even a CIBA grant, issued
// while it did, then refreshes with the issuer alone.
func TestCIBAEndpointURLAudiencesNeedACIBAEndpoint(t *testing.T) {
	h := newCIBAAudienceHarness(t, true)
	cibaRefreshToken := cibaGrantRefreshToken(t, h, senderBinding{})
	codeRefreshToken := codeGrantRefreshToken(t, h, senderBinding{})
	cfg, deps := h.cfg, h.deps
	cfg.Endpoints.BackchannelAuthentication = fapi.URL{}
	cfg.Algorithms.BackchannelAuthenticationRequest = nil
	cfg.Limits.BackchannelAuthenticationRequestLifetime = 0
	cfg.Limits.MaxBackchannelAuthenticationRequestLifetime = 0
	cfg.Limits.BackchannelAuthenticationPollInterval = 0
	deps.Backchannel, deps.BackchannelNotifier = nil, nil
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New without CIBA: %v", err)
	}
	h.server = srv
	for _, tc := range []struct {
		name, refreshToken, aud string
		want                    server.ErrorCode
	}{
		{"CIBA grant, token endpoint URL", cibaRefreshToken, testTokenEndpoint, server.ErrorInvalidClient},
		{"code grant, token endpoint URL", codeRefreshToken, testTokenEndpoint, server.ErrorInvalidClient},
		{"CIBA grant, issuer", cibaRefreshToken, testIssuer, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireTokenOutcome(t, refreshWithAssertion(t, h, typedAssertion(t, h, tc.aud, ""), tc.refreshToken, senderBinding{}), tc.want)
		})
	}
}

// TestCIBAEndpointURLAudiencesNotForOtherClients:
// Config.CIBAEndpointURLAudiences widens only what a client registered
// for CIBA may name. Another client's assertion naming the token
// endpoint URL is refused with invalid_client at the backchannel
// authentication endpoint, where one naming the issuer authenticates
// the client before it's refused as unauthorized_client, and to refresh
// its code grant, which the issuer does.
func TestCIBAEndpointURLAudiencesNotForOtherClients(t *testing.T) {
	h := newHarnessWithBackchannelOptions(t, memstore.NewBackchannelAuthenticationStore(), withCIBAEndpointURLAudiences, func(deps *server.Dependencies) {
		registerAudienceTestClient(t, deps, storage.SenderConstrainDPoP, false)
	})
	for aud, want := range map[string]server.ErrorCode{testTokenEndpoint: server.ErrorInvalidClient, testIssuer: server.ErrorUnauthorizedClient} {
		if got := beginOutcome(t, h, typedAssertion(t, h, aud, "")); got != want {
			t.Errorf("BeginBackchannelAuthentication naming %s = %q, want %q", aud, got, want)
		}
	}
	refreshToken := codeGrantRefreshToken(t, h, senderBinding{})
	requireTokenOutcome(t, refreshWithAssertion(t, h, typedAssertion(t, h, testTokenEndpoint, ""), refreshToken, senderBinding{}), server.ErrorInvalidClient)
	requireTokenOutcome(t, refreshWithAssertion(t, h, typedAssertion(t, h, testIssuer, ""), refreshToken, senderBinding{}), "")
}

// pushAuthenticatedBy pushes a plain authorization request
// authenticated by assertion.
func pushAuthenticatedBy(t *testing.T, h harness, assertion string) error {
	t.Helper()
	_, err := h.server.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, assertion, nil)},
	})
	return err
}

// requestClientCredentialsWith requests a client_credentials token
// authenticated by assertion.
func requestClientCredentialsWith(t *testing.T, h harness, assertion string) error {
	t.Helper()
	_, err := h.server.RequestClientCredentialsToken(context.Background(), server.ClientCredentialsTokenRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			formParam("client_assertion", assertion),
			formParam("client_assertion_type", clientassertion.AssertionType),
			formParam("grant_type", "client_credentials"),
		}},
		DPoPProofs: []string{createDPoPProof(t, generateKey(t), h.now)},
	})
	return err
}

// TestCIBAEndpointURLAudiencesNotAtOtherGrants: even under
// Config.CIBAEndpointURLAudiences, a CIBA client's assertion names the
// issuer alone at PAR and in the client_credentials grant, which are
// FAPI 2.0's (TestExchangeAuthorizationCodeKeepsCIBAClientIssuerOnly
// covers the code exchange). The client isn't registered for
// client_credentials, so unauthorized_client there means it
// authenticated.
func TestCIBAEndpointURLAudiencesNotAtOtherGrants(t *testing.T) {
	h := newHarnessWithBackchannelConfig(t, memstore.NewBackchannelAuthenticationStore(), func(cfg *server.Config) {
		cfg.CIBAEndpointURLAudiences = true
		cfg.ClientCredentialsGrant = true
	})
	for _, tc := range []struct {
		name string
		send func(*testing.T, harness, string) error
		aud  string
		want server.ErrorCode
	}{
		{"PAR, issuer", pushAuthenticatedBy, testIssuer, ""},
		{"PAR, token endpoint URL", pushAuthenticatedBy, testTokenEndpoint, server.ErrorInvalidClient},
		{"PAR, backchannel endpoint URL", pushAuthenticatedBy, testBackchannelAuthenticationEndpoint, server.ErrorInvalidClient},
		{"client_credentials, issuer", requestClientCredentialsWith, testIssuer, server.ErrorUnauthorizedClient},
		{"client_credentials, token endpoint URL", requestClientCredentialsWith, testTokenEndpoint, server.ErrorInvalidClient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireTokenOutcome(t, tc.send(t, h, typedAssertion(t, h, tc.aud, "")), tc.want)
		})
	}
}
