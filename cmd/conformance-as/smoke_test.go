package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

// This is the go/no-go gate before ever pointing a real OIDF conformance
// suite instance at this binary: it drives a full PAR -> authorize ->
// consent -> token flow, over a real TLS listener running the exact
// production wiring (newServerMux), using the existing client package
// rather than a hand-rolled HTTP script.

const smokeSubject = "conformance-smoke-test-user"

// selfSignedCert generates a throwaway ECDSA P-256 self-signed
// certificate for 127.0.0.1, entirely in-memory (no shelling out to
// openssl/mkcert, no temp files) — a hermetic substitute for the real
// cert/key an operator supplies via -cert/-key for an actual conformance
// run.
func selfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate cert key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	pool := x509.NewCertPool()
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, pool
}

// memSessionStore is a minimal storage.SessionStore for the smoke test's
// own client.Client — the conformance-as binary itself never needs a
// SessionStore (that's a client-side concept), so there's no production
// implementation to reuse here.
type memSessionStore struct {
	mu       sync.Mutex
	sessions map[string]storage.NewSession
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{sessions: make(map[string]storage.NewSession)}
}

func (s *memSessionStore) Create(_ context.Context, session storage.NewSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.State] = session
	return nil
}

func (s *memSessionStore) Consume(_ context.Context, c storage.SessionConsumption) (storage.ConsumedSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[c.State]
	if !ok {
		return storage.ConsumedSession{}, fmt.Errorf("unknown or already-consumed state")
	}
	delete(s.sessions, c.State)
	return storage.ConsumedSession{
		Nonce: session.Nonce, PKCEVerifier: session.PKCEVerifier,
		ExpectedIssuer: session.ExpectedIssuer, ExpectedRedirectURI: session.ExpectedRedirectURI,
		ExpectedResponseMode: session.ExpectedResponseMode, ExpiresAt: session.ExpiresAt,
	}, nil
}

// smokeHarness bundles everything the smoke test's subtests share: the
// live AS, a client.Client pointed at it, and an HTTP client trusting the
// AS's self-signed cert (for driving the consent form directly).
type smokeHarness struct {
	t          *testing.T
	client     *client.Client
	httpClient *http.Client
	authorize  string // base authorize endpoint URL, for building decision requests

	// backchannelApprove is the base "/backchannel-approve" URL —
	// populated only when newSmokeHarnessWithOptions was built with
	// ciba true — for driving backchannelHandler.handleApprove
	// directly, standing in for the OIDF suite's own
	// CallAutomatedCibaApprovalEndpoint condition.
	backchannelApprove string
}

func newSmokeHarness(t *testing.T, format AccessTokenFormat) *smokeHarness {
	return newSmokeHarnessWithOptions(t, format, false, false, false)
}

// newSmokeHarnessWithNonceChallenge is newSmokeHarnessWithOptions with
// userinfoSigning/ciba left off, for the (much more common)
// nonce-challenge-only callers below.
func newSmokeHarnessWithNonceChallenge(t *testing.T, format AccessTokenFormat, dpopNonceChallenge bool) *smokeHarness {
	return newSmokeHarnessWithOptions(t, format, dpopNonceChallenge, false, false)
}

func newSmokeHarnessWithOptions(t *testing.T, format AccessTokenFormat, dpopNonceChallenge bool, userinfoSigning bool, ciba bool) *smokeHarness {
	t.Helper()

	cert, pool := selfSignedCert(t)
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsListener := tls.NewListener(tcpListener, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})

	issuer, err := fapi.ParseIssuerURL(fmt.Sprintf("https://%s", tcpListener.Addr().String()))
	if err != nil {
		t.Fatalf("parse issuer: %v", err)
	}
	endpoints, err := buildEndpoints(issuer, false)
	if err != nil {
		t.Fatalf("build endpoints: %v", err)
	}
	userinfoURL, err := buildUserinfoURL(issuer, false)
	if err != nil {
		t.Fatalf("build userinfo url: %v", err)
	}

	clientKeyPurposes := map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.ClientAuthentication: fapi.ES256,
		keys.DPoPProofSigning:     fapi.ES256,
	}
	if ciba {
		clientKeyPurposes[keys.BackchannelAuthenticationRequestSigning] = fapi.ES256
	}
	clientKeyManager, err := ephemeral.NewKeyManager(clientKeyPurposes)
	if err != nil {
		t.Fatalf("build client key manager: %v", err)
	}
	clientAuthKey, err := clientKeyManager.PublicKey(context.Background(), keys.ClientAuthentication, fapi.ES256)
	if err != nil {
		t.Fatalf("resolve client auth public key: %v", err)
	}
	jwk, err := jose.NewJWK(clientAuthKey.PublicKey, fapi.ES256)
	if err != nil {
		t.Fatalf("build client jwk: %v", err)
	}
	jwkJSON, err := jwk.WithKeyID(clientAuthKey.KeyID).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal client jwk: %v", err)
	}
	jwksKeys := jwkJSON
	if ciba {
		// The server verifies a CIBA backchannel authentication request
		// against BackchannelAuthenticationRequestVerification, a
		// distinct purpose from ClientAuthentication — see
		// keys.SigningPurpose's own doc comment for why — so this
		// client's second key must be published to the server's known
		// JWKS too, or resolveClientKey finds no matching kid.
		cibaKey, err := clientKeyManager.PublicKey(context.Background(), keys.BackchannelAuthenticationRequestSigning, fapi.ES256)
		if err != nil {
			t.Fatalf("resolve client backchannel authentication public key: %v", err)
		}
		cibaJWK, err := jose.NewJWK(cibaKey.PublicKey, fapi.ES256)
		if err != nil {
			t.Fatalf("build client backchannel authentication jwk: %v", err)
		}
		cibaJWKJSON, err := cibaJWK.WithKeyID(cibaKey.KeyID).MarshalJSON()
		if err != nil {
			t.Fatalf("marshal client backchannel authentication jwk: %v", err)
		}
		jwksKeys = append(append(jwksKeys[:len(jwksKeys):len(jwksKeys)], ','), cibaJWKJSON...)
	}
	inlineJWKS := json.RawMessage(fmt.Sprintf(`{"keys":[%s]}`, jwksKeys))

	// clientUserInfoAlg mirrors wiring.go's own reuse of Algorithms.IDToken
	// for UserInfo signing when -userinfo-signing is on — zero (unset)
	// otherwise, matching client.Algorithms.UserInfo's own "required to
	// call FetchUserInfo" contract.
	var clientUserInfoAlg fapi.SignatureAlgorithm
	if userinfoSigning {
		clientUserInfoAlg = fapi.ES256
	}

	const testClientID = fapi.ClientID("smoke-test-client")
	const testRedirectURI = "https://rp.smoketest.internal/callback"

	// clientCIBAAlg mirrors clientUserInfoAlg above, for -ciba.
	var clientCIBAAlg fapi.SignatureAlgorithm
	if ciba {
		clientCIBAAlg = fapi.ES256
	}

	registered, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
		BackchannelAuthenticationRequestAlgorithm: clientCIBAAlg,
	})
	if err != nil {
		t.Fatalf("build registered client: %v", err)
	}

	resolved := ResolvedConfig{
		ListenAddr:        tcpListener.Addr().String(),
		Issuer:            issuer,
		Profile:           server.ProfileFAPISecurity,
		DefaultSubject:    smokeSubject,
		Algorithms:        server.RecommendedAlgorithms(),
		Limits:            server.RecommendedLimits(),
		AccessTokenFormat: format,
		Clients:           []storage.RegisteredClient{registered},
		ClientKeys:        []ephemeral.ClientKeySpec{{ClientID: testClientID, JWKS: inlineJWKS}},
		AdvertisedScopes:  []string{"openid", "accounts", "offline_access"},
	}

	mux, err := newServerMux(resolved, false, dpopNonceChallenge, userinfoSigning, ciba)
	if err != nil {
		t.Fatalf("build server mux: %v", err)
	}
	httpServer := &http.Server{Handler: mux}
	go httpServer.Serve(tlsListener)
	t.Cleanup(func() { httpServer.Close() })

	httpClient := &http.Client{
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	fetcher, err := fapihttp.New(httpClient, fapihttp.Config{
		MaxResponseBytes: 1 << 16,
		RequestTimeout:   10 * time.Second,
		MaxRedirects:     0,
		// tlsListener is bound to 127.0.0.1; opt in to fapihttp's SSRF
		// pre-check allowing loopback, same as a real deployment
		// pointing at a loopback issuer would.
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("build fetcher: %v", err)
	}
	issuerKeys, err := keys.NewJWKSIssuerKeySource(fetcher, endpoints.JWKS, time.Minute)
	if err != nil {
		t.Fatalf("build issuer key source: %v", err)
	}

	clientCfg := client.Config{
		Issuer:      issuer,
		ClientID:    testClientID,
		RedirectURI: testRedirectURI,
		Endpoints: client.Endpoints{
			Authorization:              endpoints.Authorization,
			Token:                      endpoints.Token,
			PushedAuthorizationRequest: endpoints.PushedAuthorizationRequest,
			UserInfo:                   userinfoURL,
		},
		Profile: client.ProfileFAPISecurity,
		Algorithms: client.Algorithms{
			ClientAuthentication: fapi.ES256,
			DPoP:                 fapi.ES256,
			IDToken:              fapi.ES256,
			UserInfo:             clientUserInfoAlg,
		},
		Limits: client.Limits{
			ClientAssertionLifetime: time.Minute,
			SessionLifetime:         10 * time.Minute,
			// Must be >= server.RecommendedLimits().IDTokenLifetime
			// (the server config this test's AS actually runs under,
			// as of switching to it unconditionally) or the client
			// side rejects its own AS's legitimately-issued token.
			MaxIDTokenLifetime:   10 * time.Minute,
			MaxClockSkew:         10 * time.Second,
			HTTPTimeout:          10 * time.Second,
			MaxHTTPResponseBytes: 1 << 16,
			MaxJOSECompactBytes:  16 * 1024,
		},
	}
	var backchannelApprove string
	if ciba {
		backchannelAuthenticationURL, err := buildBackchannelAuthenticationURL(issuer, false)
		if err != nil {
			t.Fatalf("build backchannel authentication url: %v", err)
		}
		clientCfg.Endpoints.BackchannelAuthentication = backchannelAuthenticationURL
		clientCfg.Algorithms.BackchannelAuthenticationRequest = clientCIBAAlg
		clientCfg.Limits.BackchannelAuthenticationRequestLifetime = time.Minute
		backchannelApprove = issuer.String() + "/backchannel-approve"
	}
	clientDeps := client.Dependencies{
		Sessions:   newMemSessionStore(),
		Keys:       clientKeyManager,
		IssuerKeys: issuerKeys,
		HTTP:       httpClient,
		Clock:      client.SystemClock{},
		Random:     rand.Reader,
	}
	c, err := client.New(clientCfg, clientDeps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	return &smokeHarness{
		t: t, client: c, httpClient: httpClient,
		authorize:          endpoints.Authorization.String(),
		backchannelApprove: backchannelApprove,
	}
}

// runToConsent begins an authorization attempt and GETs the resulting
// authorize URL, returning the interaction handle (read from the
// debug-only X-Interaction-Handle response header — see authorize.go)
// and the redirect-URI/query the client will eventually need.
func (h *smokeHarness) runToConsent(ctx context.Context, scope []string) (handle string) {
	h.t.Helper()
	session, err := h.client.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: scope})
	if err != nil {
		h.t.Fatalf("BeginAuthorization: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, session.URL().String(), nil)
	if err != nil {
		h.t.Fatalf("build authorize request: %v", err)
	}
	res, err := h.httpClient.Do(req)
	if err != nil {
		h.t.Fatalf("GET authorize: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		h.t.Fatalf("GET authorize returned status %d, want %d", res.StatusCode, http.StatusOK)
	}
	handle = res.Header.Get("X-Interaction-Handle")
	if handle == "" {
		h.t.Fatalf("authorize response carried no X-Interaction-Handle")
	}
	return handle
}

// submitDecision POSTs the consent form's decision and returns the
// resulting redirect's raw query string.
func (h *smokeHarness) submitDecision(ctx context.Context, handle, decision string, scope []string) string {
	h.t.Helper()
	form := url.Values{"handle": {handle}, "subject": {smokeSubject}, "decision": {decision}}
	for _, s := range scope {
		form.Add("scope", s)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.authorize+"/decision", strings.NewReader(form.Encode()))
	if err != nil {
		h.t.Fatalf("build decision request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := h.httpClient.Do(req)
	if err != nil {
		h.t.Fatalf("POST decision: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		h.t.Fatalf("POST decision returned status %d, want %d", res.StatusCode, http.StatusFound)
	}
	location := res.Header.Get("Location")
	if location == "" {
		h.t.Fatalf("decision response carried no Location header")
	}
	redirectURL, err := url.Parse(location)
	if err != nil {
		h.t.Fatalf("parse redirect location: %v", err)
	}
	return redirectURL.RawQuery
}

func TestSmokeAuthorizationCodeFlow(t *testing.T) {
	for _, format := range []AccessTokenFormat{AccessTokenFormatJWT, AccessTokenFormatOpaque} {
		t.Run(string(format), func(t *testing.T) {
			testSmokeAuthorizationCodeFlow(t, format)
		})
	}
}

func testSmokeAuthorizationCodeFlow(t *testing.T, format AccessTokenFormat) {
	h := newSmokeHarness(t, format)
	ctx := context.Background()
	scope := []string{"openid", "accounts", "offline_access"}

	handle := h.runToConsent(ctx, scope)
	rawQuery := h.submitDecision(ctx, handle, "approve", scope)

	result, err := h.client.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("CompleteAuthorization result = %T, want client.CompletionSuccess", result)
	}
	if success.Tokens.AccessToken.Reveal() == "" {
		t.Fatalf("access token is empty")
	}
	if !success.Tokens.HasIDToken {
		t.Fatalf("HasIDToken = false, want true (openid was granted)")
	}
	if !success.Tokens.HasRefreshToken {
		t.Fatalf("HasRefreshToken = false, want true (offline_access was granted)")
	}

	// The consent handle is single-use at the HTTP layer (authorize.go's
	// pending map) on top of the protocol-level single-use guarantee
	// TransactionStore.CompleteAuthorization already provides (exercised
	// directly by storage.TestTransactionStoreContract) — reusing it here
	// must fail.
	form := url.Values{"handle": {handle}, "subject": {smokeSubject}, "decision": {"approve"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.authorize+"/decision", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := h.httpClient.Do(req)
	if err != nil {
		t.Fatalf("replay POST decision: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed decision returned status %d, want %d", res.StatusCode, http.StatusBadRequest)
	}

	// The authorization code is single-use end-to-end: replaying the same
	// callback query a second time must fail too (the client's own
	// session is already consumed, which is itself only possible because
	// the first CompleteAuthorization call succeeded — AS-side code
	// single-use is exercised directly by
	// storage.TestGrantStoreContract/RedeemAuthorizationCodeIsSingleUse).
	if _, err := h.client.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery}); err == nil {
		t.Fatalf("replayed CompleteAuthorization succeeded, want an error")
	}
}

// TestSmokeUserInfoWithDPoPNonceChallenge confirms this binary's
// -dpop-nonce-challenge wiring actually interoperates with the client
// package's own nonce-retry logic, not just each side's own unit tests
// in isolation. The flag now gates nonce-challenge on every DPoP proof
// this binary verifies — PAR and the token endpoint (server package,
// RFC 9449 §8) as well as /accounts and /userinfo (resource package,
// §9) — so CompleteAuthorization's own internal PAR/token exchange
// already exercises client.ExchangeCode's token-endpoint nonce retry
// (client/exchange_code.go's sendTokenRequest) before FetchUserInfo
// separately exercises ResourceClient.Do's. FetchUserInfo must succeed
// transparently even though the very first call is challenged and
// retried entirely inside the client, with no special handling from
// this test.
func TestSmokeUserInfoWithDPoPNonceChallenge(t *testing.T) {
	h := newSmokeHarnessWithNonceChallenge(t, AccessTokenFormatJWT, true)
	ctx := context.Background()
	scope := []string{"openid", "accounts"}

	handle := h.runToConsent(ctx, scope)
	rawQuery := h.submitDecision(ctx, handle, "approve", scope)

	result, err := h.client.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("CompleteAuthorization result = %T, want client.CompletionSuccess", result)
	}

	info, err := h.client.FetchUserInfo(ctx, success.Tokens)
	if err != nil {
		t.Fatalf("FetchUserInfo (should retry the nonce challenge transparently): %v", err)
	}
	if info.Subject != smokeSubject {
		t.Fatalf("UserInfo.Subject = %q, want %q", info.Subject, smokeSubject)
	}

	// A second, independent call must succeed too — confirming the
	// server's single-use nonce store doesn't end up in some broken
	// state after one full challenge/consume/reissue cycle. (client
	// itself has no cross-call nonce cache — ResourceClient.Do only
	// reacts to a challenge within the one call it's already making —
	// so this still exercises its own full challenge/retry round trip,
	// same as the first call above; the server's proactive
	// NextDPoPNonce only benefits a caller that tracks and reuses it
	// itself, which this client doesn't do.)
	if _, err := h.client.FetchUserInfo(ctx, success.Tokens); err != nil {
		t.Fatalf("FetchUserInfo (second call): %v", err)
	}
}

// TestSmokeSignedUserInfo confirms this binary's -userinfo-signing
// wiring (resource.go's userinfoHandler calling server.SignUserInfoResponse)
// actually interoperates with client.FetchUserInfo's own JWS
// verification (client.Algorithms.UserInfo) — the "prove both sides
// actually interoperate" shape TestSmokeUserInfoWithDPoPNonceChallenge
// already uses for the nonce-challenge wiring above.
func TestSmokeSignedUserInfo(t *testing.T) {
	h := newSmokeHarnessWithOptions(t, AccessTokenFormatJWT, false, true, false)
	ctx := context.Background()
	scope := []string{"openid", "accounts"}

	handle := h.runToConsent(ctx, scope)
	rawQuery := h.submitDecision(ctx, handle, "approve", scope)

	result, err := h.client.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("CompleteAuthorization result = %T, want client.CompletionSuccess", result)
	}

	info, err := h.client.FetchUserInfo(ctx, success.Tokens)
	if err != nil {
		t.Fatalf("FetchUserInfo (server signs, client must verify the JWS): %v", err)
	}
	if info.Subject != smokeSubject {
		t.Fatalf("UserInfo.Subject = %q, want %q", info.Subject, smokeSubject)
	}
}

func TestSmokeAuthorizationDenied(t *testing.T) {
	h := newSmokeHarness(t, AccessTokenFormatJWT)
	ctx := context.Background()
	scope := []string{"accounts"}

	handle := h.runToConsent(ctx, scope)
	rawQuery := h.submitDecision(ctx, handle, "deny", scope)

	result, err := h.client.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	denied, ok := result.(client.CompletionDenied)
	if !ok {
		t.Fatalf("CompleteAuthorization result = %T, want client.CompletionDenied", result)
	}
	if denied.Code != "access_denied" {
		t.Fatalf("denied.Code = %q, want %q", denied.Code, "access_denied")
	}
}

// callBackchannelApprove drives h.backchannelApprove exactly like the
// OIDF suite's own CallAutomatedCibaApprovalEndpoint condition would
// (see backchannel.go's own doc comment) — standing in for the human on
// the out-of-band device an automated conformance run has no way to
// model.
func (h *smokeHarness) callBackchannelApprove(ctx context.Context, authReqID, action string) {
	h.t.Helper()
	if h.backchannelApprove == "" {
		h.t.Fatalf("callBackchannelApprove: harness was not built with ciba=true")
	}
	q := url.Values{"auth_req_id": {authReqID}, "action": {action}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.backchannelApprove+"?"+q.Encode(), nil)
	if err != nil {
		h.t.Fatalf("build backchannel-approve request: %v", err)
	}
	res, err := h.httpClient.Do(req)
	if err != nil {
		h.t.Fatalf("POST backchannel-approve: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		h.t.Fatalf("POST backchannel-approve returned status %d, want %d", res.StatusCode, http.StatusOK)
	}
}

// TestSmokeCIBAFlow drives client.BeginBackchannelAuthentication and
// client.PollBackchannelAuthentication (Phase 2, the client/RP side)
// against a real -ciba-enabled server (Phase 1), proving the two
// independently-implemented sides actually agree on the wire — the
// same "prove interop, not just each side's own unit tests in
// isolation" pattern TestSmokeUserInfoWithDPoPNonceChallenge already
// applies to UserInfo.
func TestSmokeCIBAFlow(t *testing.T) {
	h := newSmokeHarnessWithOptions(t, AccessTokenFormatJWT, false, false, true)
	ctx := context.Background()
	scope := []string{"openid", "accounts", "offline_access"}

	session, err := h.client.BeginBackchannelAuthentication(ctx, client.BeginBackchannelAuthenticationRequest{
		Scope: scope, LoginHint: smokeSubject,
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}
	if session.AuthReqID() == "" {
		t.Fatalf("AuthReqID() is empty")
	}

	// Before the embedder's own out-of-band authentication component has
	// decided, polling must report Pending, not an error.
	result, err := h.client.PollBackchannelAuthentication(ctx, session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication (before approval): %v", err)
	}
	if _, ok := result.(client.BackchannelAuthenticationPending); !ok {
		t.Fatalf("PollBackchannelAuthentication (before approval) = %T, want client.BackchannelAuthenticationPending", result)
	}

	h.callBackchannelApprove(ctx, session.AuthReqID(), "allow")

	// The server enforces its own poll interval (CIBA §10.3's
	// "interval") between polls for the same auth_req_id, even across
	// a status change — wait it out so this second poll isn't itself
	// rejected as slow_down.
	time.Sleep(session.Interval())

	result, err = h.client.PollBackchannelAuthentication(ctx, session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication (after approval): %v", err)
	}
	approved, ok := result.(client.BackchannelAuthenticationApproved)
	if !ok {
		t.Fatalf("PollBackchannelAuthentication (after approval) = %T, want client.BackchannelAuthenticationApproved", result)
	}
	if approved.Tokens.AccessToken.Reveal() == "" {
		t.Fatalf("access token is empty")
	}
	if !approved.Tokens.HasIDToken {
		t.Fatalf("HasIDToken = false, want true (openid was granted)")
	}
	if approved.Tokens.Subject != smokeSubject {
		t.Fatalf("Subject = %q, want %q", approved.Tokens.Subject, smokeSubject)
	}
	if !approved.Tokens.HasRefreshToken {
		t.Fatalf("HasRefreshToken = false, want true (offline_access was granted)")
	}

	// auth_req_id is single-use end to end, mirroring
	// TestSmokeAuthorizationCodeFlow's own authorization-code
	// single-use check: polling again after a successful exchange must
	// fail.
	if _, err := h.client.PollBackchannelAuthentication(ctx, session); err == nil {
		t.Fatalf("PollBackchannelAuthentication (replay after approval) = nil error, want error")
	}
}

func TestSmokeCIBADenied(t *testing.T) {
	h := newSmokeHarnessWithOptions(t, AccessTokenFormatJWT, false, false, true)
	ctx := context.Background()

	session, err := h.client.BeginBackchannelAuthentication(ctx, client.BeginBackchannelAuthenticationRequest{
		Scope: []string{"openid", "accounts"}, LoginHint: smokeSubject,
	})
	if err != nil {
		t.Fatalf("BeginBackchannelAuthentication: %v", err)
	}

	h.callBackchannelApprove(ctx, session.AuthReqID(), "deny")

	result, err := h.client.PollBackchannelAuthentication(ctx, session)
	if err != nil {
		t.Fatalf("PollBackchannelAuthentication: %v", err)
	}
	denied, ok := result.(client.BackchannelAuthenticationDenied)
	if !ok {
		t.Fatalf("PollBackchannelAuthentication result = %T, want client.BackchannelAuthenticationDenied", result)
	}
	if denied.Code != "access_denied" {
		t.Fatalf("denied.Code = %q, want %q", denied.Code, "access_denied")
	}
}
