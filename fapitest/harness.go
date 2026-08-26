package fapitest

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/internal/dpop"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
)

const (
	Issuer      = "https://as.fapitest.internal"
	ClientID    = fapi.ClientID("fapitest-client")
	RedirectURI = "https://rp.fapitest.internal/callback"
	Subject     = "end-user-1"
)

// Config selects which FAPI 2.0 profile the harness's client and server
// both run under — they must always agree, exactly like a real
// deployment's client and AS configuration must.
type Config struct {
	Profile server.Profile

	// Extensions, if set, is registered on the harness's server.Server —
	// a test can then attach values via BeginAuthorizationRequest.Extensions
	// (only under ProfileFAPISecurityWithMessageSigning — see
	// client.BeginAuthorizationRequest.Extensions) and observe whether a
	// ReturnInTokenClaims value round-trips into the issued tokens.
	Extensions *extension.Registry

	// EncryptIDTokens, if set, registers the harness's client for
	// encrypted ID tokens (OIDC Core §2) on both sides — the client's
	// own Algorithms.IDTokenKeyManagement/ContentEncryption, the
	// server's per-client RegisteredClient fields, and the server-wide
	// AlgorithmPolicy allow-list all agree, exactly like a real
	// deployment's client and AS configuration must — using
	// RSA-OAEP-256 as the key-management algorithm, the same way every
	// other algorithm choice in this harness is a fixed one (ES256),
	// not configurable per test.
	EncryptIDTokens bool

	// IDTokenContentEncryption selects which content-encryption
	// algorithm EncryptIDTokens uses. Zero (the default) means
	// fapi.A256GCM — set explicitly to exercise fapi.A256CBCHS512
	// instead. Ignored unless EncryptIDTokens is set.
	IDTokenContentEncryption fapi.ContentEncryptionAlgorithm

	// SignatureAlgorithm selects which fapi.SignatureAlgorithm every
	// signing purpose in the harness uses — the client's own client
	// assertions/request objects/DPoP proofs, and the server's own
	// JARM/ID token/access token signing. Zero (the default) means
	// fapi.ES256; set explicitly (e.g. fapi.EdDSA) to exercise a full
	// authorization_code flow under a different algorithm end to end.
	SignatureAlgorithm fapi.SignatureAlgorithm
}

// Harness wires a real client.Client, server.Server and resource.Verifier
// together over an httptest.Server, so a test exercises genuine wire
// encoding and HTTP semantics — see doc.go. It is entirely unexported
// apart from its exported methods; construct one with New.
type Harness struct {
	t        *testing.T
	Client   *client.Client
	Resource *resource.Verifier
	Clock    *manualClock

	authServer         *authServer
	httpClient         *http.Client
	clientKeys         keys.KeyManager
	signatureAlgorithm fapi.SignatureAlgorithm
}

// New builds a Harness: an in-memory-backed server.Server exposed over a
// real httptest.Server, a client.Client pointed at it, and a
// resource.Verifier able to check the access tokens it issues.
func New(t *testing.T, cfg Config) *Harness {
	t.Helper()
	if cfg.Profile != server.ProfileFAPISecurity && cfg.Profile != server.ProfileFAPISecurityWithMessageSigning {
		t.Fatalf("fapitest: Config.Profile is invalid")
	}
	clientProfile := client.ProfileFAPISecurity
	if cfg.Profile == server.ProfileFAPISecurityWithMessageSigning {
		clientProfile = client.ProfileFAPISecurityWithMessageSigning
	}

	clock := &manualClock{now: time.Now()}

	// sigAlg resolves Config.SignatureAlgorithm's zero-means-ES256
	// default; every signing purpose below uses this one algorithm, so
	// the client and server always agree, exactly like Config.Profile.
	sigAlg := cfg.SignatureAlgorithm
	if sigAlg == 0 {
		sigAlg = fapi.ES256
	}

	asKeys := newAlgorithmKeyManager(t, sigAlg, keys.JARMSigning, keys.AccessTokenSigning, keys.IDTokenSigning)
	clientKeys := newAlgorithmKeyManager(t, sigAlg, keys.ClientAuthentication, keys.RequestObjectSigning, keys.DPoPProofSigning)

	// contentEncryption resolves Config.IDTokenContentEncryption's
	// zero-means-A256GCM default; only meaningful when EncryptIDTokens
	// is set.
	contentEncryption := cfg.IDTokenContentEncryption
	if contentEncryption == 0 {
		contentEncryption = fapi.A256GCM
	}

	// clientDecryption is only generated (and only wired into the
	// client/server configs below) when EncryptIDTokens is set — a
	// separate keys.Decrypter from clientKeys (an RSA key, unrelated to
	// clientKeys' own sigAlg-keyed signing keys), the same way
	// client.Dependencies itself keeps Decryption separate from Keys.
	var clientDecryption *ephemeral.KeyManager
	if cfg.EncryptIDTokens {
		var err error
		clientDecryption, err = ephemeral.NewKeyManagerWithDecryption(nil, map[keys.DecryptionPurpose]fapi.KeyManagementAlgorithm{
			keys.IDTokenDecryption: fapi.RSAOAEP256,
		})
		if err != nil {
			t.Fatalf("fapitest: ephemeral.NewKeyManagerWithDecryption: %v", err)
		}
	}

	issuer, err := fapi.ParseIssuerURL(Issuer)
	if err != nil {
		t.Fatalf("fapitest: ParseIssuerURL: %v", err)
	}

	registeredClientCfg := storage.RegisteredClientConfig{
		ID:                       ClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{RedirectURI},
		ClientAssertionAlgorithm: sigAlg,
		RequestObjectAlgorithm:   sigAlg,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
	}
	if cfg.EncryptIDTokens {
		registeredClientCfg.IDTokenEncryptionKeyManagement = fapi.RSAOAEP256
		registeredClientCfg.IDTokenEncryptionContentEncryption = contentEncryption
	}
	registeredClient, err := storage.NewRegisteredClient(registeredClientCfg)
	if err != nil {
		t.Fatalf("fapitest: NewRegisteredClient: %v", err)
	}

	replay := newMemReplayStore()

	// Start the HTTP listener before building server.Config: its endpoint
	// URLs must be the httptest.Server's real, assigned-port URL (DPoP's
	// htu binding and the JARM/request-object audience checks compare
	// against them), which isn't known until the listener exists. The
	// handlers only dereference the *server.Server at request time, so
	// attaching it afterward — before any test code makes a request — is
	// safe; see newAuthServer.
	as := newAuthServer(t, clock, AutoApprove{Subject: Subject, ACR: "urn:mace:incommon:iap:silver", AMR: []string{"pwd"}})

	srvCfg := server.Config{
		Issuer:    issuer,
		Endpoints: loopbackEndpoints(as.ts.URL),
		Profile:   cfg.Profile,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{sigAlg},
			RequestObject:   server.AlgorithmSet{sigAlg},
			JARM:            sigAlg,
			IDToken:         sigAlg,
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        5 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
			JARMResponseLifetime:       time.Minute,
			AccessTokenLifetime:        5 * time.Minute,
			IDTokenLifetime:            5 * time.Minute,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance:  server.AssuranceDevelopment,
		Extensions: cfg.Extensions,
	}
	if cfg.EncryptIDTokens {
		srvCfg.Algorithms.IDTokenEncryptionKeyManagement = server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
		srvCfg.Algorithms.IDTokenEncryptionContentEncryption = server.ContentEncryptionAlgorithmSet{contentEncryption}
	}
	revocation := newMemRevocationStore()
	jwtAccessTokens, err := server.NewJWTAccessTokens(asKeys, sigAlg)
	if err != nil {
		t.Fatalf("fapitest: server.NewJWTAccessTokens: %v", err)
	}
	srvDeps := server.Dependencies{
		Clients:      &memClientRepository{client: registeredClient},
		Transactions: newMemTransactionStore(),
		Grants:       newMemGrantStore(),
		Replay:       replay,
		ClientKeys:   &memClientKeySource{clientID: ClientID, manager: clientKeys},
		Keys:         asKeys,
		AccessTokens: jwtAccessTokens,
		Revocation:   revocation,
		Clock:        clock,
		Random:       rand.Reader,
	}
	if cfg.EncryptIDTokens {
		srvDeps.ClientEncryptionKeys = &memClientEncryptionKeySource{clientID: ClientID, decrypter: clientDecryption}
	}
	srv, err := server.New(srvCfg, srvDeps)
	if err != nil {
		t.Fatalf("fapitest: server.New: %v", err)
	}
	as.srv = srv

	httpClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	userInfoURL, err := fapi.ParseEndpointURL(as.ts.URL+"/userinfo", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("fapitest: ParseEndpointURL(userinfo): %v", err)
	}
	clientCfg := client.Config{
		Issuer:      issuer,
		ClientID:    ClientID,
		RedirectURI: RedirectURI,
		Endpoints: client.Endpoints{
			Authorization:              srvCfg.Endpoints.Authorization,
			Token:                      srvCfg.Endpoints.Token,
			PushedAuthorizationRequest: srvCfg.Endpoints.PushedAuthorizationRequest,
			UserInfo:                   userInfoURL,
		},
		Profile: clientProfile,
		Algorithms: client.Algorithms{
			ClientAuthentication: sigAlg,
			RequestObject:        sigAlg,
			DPoP:                 sigAlg,
			JARM:                 sigAlg,
			IDToken:              sigAlg,
		},
		Limits: client.Limits{
			ClientAssertionLifetime: time.Minute,
			RequestObjectLifetime:   time.Minute,
			SessionLifetime:         5 * time.Minute,
			MaxJARMResponseLifetime: time.Minute,
			MaxIDTokenLifetime:      5 * time.Minute,
			MaxClockSkew:            5 * time.Second,
			HTTPTimeout:             5 * time.Second,
			MaxHTTPResponseBytes:    1 << 16,
			MaxJOSECompactBytes:     16 * 1024,
		},
	}
	if cfg.EncryptIDTokens {
		clientCfg.Algorithms.IDTokenKeyManagement = fapi.RSAOAEP256
		clientCfg.Algorithms.IDTokenContentEncryption = contentEncryption
	}
	clientDeps := client.Dependencies{
		Sessions:   newMemSessionStore(),
		Keys:       clientKeys,
		IssuerKeys: &memIssuerKeySource{issuer: Issuer, manager: asKeys},
		HTTP:       httpClient,
		Clock:      clock,
		Random:     rand.Reader,
	}
	if cfg.EncryptIDTokens {
		clientDeps.Decryption = clientDecryption
	}
	c, err := client.New(clientCfg, clientDeps)
	if err != nil {
		t.Fatalf("fapitest: client.New: %v", err)
	}

	resourceCfg := resource.Config{
		Limits: resource.Limits{
			MaxDPoPProofAge: time.Minute,
			MaxClockSkew:    5 * time.Second,
		},
	}
	resourceJWT, err := resource.NewJWTAccessTokens(&memIssuerKeySource{issuer: Issuer, manager: asKeys}, issuer, Issuer, sigAlg, 5*time.Minute)
	if err != nil {
		t.Fatalf("fapitest: resource.NewJWTAccessTokens: %v", err)
	}
	resourceDeps := resource.Dependencies{
		AccessTokens: resourceJWT,
		Replay:       replay,
		Revocation:   revocation,
		Clock:        clock,
	}
	rs, err := resource.NewVerifier(resourceCfg, resourceDeps)
	if err != nil {
		t.Fatalf("fapitest: resource.NewVerifier: %v", err)
	}
	as.resource = rs

	return &Harness{
		t: t, Client: c, Resource: rs, Clock: clock, authServer: as, httpClient: httpClient,
		clientKeys: clientKeys, signatureAlgorithm: sigAlg,
	}
}

func loopbackEndpoints(base string) server.Endpoints {
	mustURL := func(path string) fapi.URL {
		u, err := fapi.ParseEndpointURL(base+path, fapi.AllowLoopbackHTTP())
		if err != nil {
			panic(fmt.Sprintf("fapitest: %v", err))
		}
		return u
	}
	return server.Endpoints{
		Authorization:              mustURL("/authorize"),
		Token:                      mustURL("/token"),
		PushedAuthorizationRequest: mustURL("/par"),
		JWKS:                       mustURL("/jwks"),
	}
}

// RunAuthorizationCodeFlow drives a complete authorization_code flow
// over real HTTP for the given scope, with no extension parameters — see
// RunAuthorizationCodeFlowWithRequest for the general form.
func (h *Harness) RunAuthorizationCodeFlow(ctx context.Context, scope []string) (client.TokenSet, error) {
	h.t.Helper()
	return h.RunAuthorizationCodeFlowWithRequest(ctx, client.BeginAuthorizationRequest{Scope: scope})
}

// RunAuthorizationCodeFlowWithRequest drives a complete authorization_code
// flow over real HTTP: BeginAuthorization pushes req, a real GET to the
// resulting URL exercises the harness's auto-approving authorization
// endpoint, and the redirect it returns is fed to CompleteAuthorization
// exactly as an embedding application's own redirect_uri handler would
// receive it.
func (h *Harness) RunAuthorizationCodeFlowWithRequest(ctx context.Context, req client.BeginAuthorizationRequest) (client.TokenSet, error) {
	h.t.Helper()

	session, err := h.Client.BeginAuthorization(ctx, req)
	if err != nil {
		return client.TokenSet{}, fmt.Errorf("fapitest: BeginAuthorization: %w", err)
	}

	authorizeReq, err := http.NewRequestWithContext(ctx, http.MethodGet, session.URL().String(), nil)
	if err != nil {
		return client.TokenSet{}, fmt.Errorf("fapitest: build authorize request: %w", err)
	}
	res, err := h.httpClient.Do(authorizeReq)
	if err != nil {
		return client.TokenSet{}, fmt.Errorf("fapitest: GET authorize: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		return client.TokenSet{}, fmt.Errorf("fapitest: authorize endpoint returned status %d, want %d", res.StatusCode, http.StatusFound)
	}
	location := res.Header.Get("Location")
	if location == "" {
		return client.TokenSet{}, fmt.Errorf("fapitest: authorize endpoint redirect had no Location header")
	}
	redirectURL, err := url.Parse(location)
	if err != nil {
		return client.TokenSet{}, fmt.Errorf("fapitest: parse redirect location: %w", err)
	}

	return h.RunAuthorizationCodeFlowWithCallback(ctx, redirectURL.RawQuery)
}

// RunAuthorizationCodeFlowWithCallback completes an authorization
// attempt from a caller-supplied raw callback query string directly,
// skipping BeginAuthorization and the authorization-endpoint HTTP round
// trip — for exercising CompleteAuthorization's own error paths (e.g. a
// callback referencing a session that was never started).
func (h *Harness) RunAuthorizationCodeFlowWithCallback(ctx context.Context, rawQuery string) (client.TokenSet, error) {
	h.t.Helper()
	result, err := h.Client.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		return client.TokenSet{}, fmt.Errorf("fapitest: CompleteAuthorization: %w", err)
	}
	switch r := result.(type) {
	case client.CompletionSuccess:
		return r.Tokens, nil
	case client.CompletionDenied:
		return client.TokenSet{}, fmt.Errorf("fapitest: authorization denied: %s: %s", r.Code, r.Description)
	default:
		return client.TokenSet{}, fmt.Errorf("fapitest: unrecognized CompletionResult %T", result)
	}
}

// harnessSigner adapts a keys.KeyManager to crypto.Signer, the same
// pattern client and server each use internally — see
// client/signer.go. Like that adapter, it routes crypto.Signer.Sign's
// incoming bytes through keys.NewSigningRequest rather than always
// assuming a pre-hashed digest, since EdDSA needs the raw message
// instead (see keys.SigningRequest's own doc comment).
type harnessSigner struct {
	ctx       context.Context
	manager   keys.KeyManager
	purpose   keys.SigningPurpose
	algorithm fapi.SignatureAlgorithm
	publicKey crypto.PublicKey
}

func (s harnessSigner) Public() crypto.PublicKey { return s.publicKey }

func (s harnessSigner) Sign(_ io.Reader, digestOrMessage []byte, _ crypto.SignerOpts) ([]byte, error) {
	sig, err := s.manager.Sign(s.ctx, keys.NewSigningRequest(s.purpose, s.algorithm, digestOrMessage))
	if err != nil {
		return nil, err
	}
	return sig.Value, nil
}

// NewResourceRequestDPoPProof signs a DPoP proof for a simulated
// protected-resource request, bound to accessToken and using the same
// DPoP key the client used at token exchange. client's own public API
// ends at token issuance — making a subsequent authenticated call to a
// protected resource is the embedding application's job, not
// client's — so this method exists only to let a fapitest-based test
// exercise resource.Verify against a genuinely client-issued key,
// exactly as that application code would.
func (h *Harness) NewResourceRequestDPoPProof(ctx context.Context, method string, target *url.URL, accessToken string) (string, error) {
	h.t.Helper()
	info, err := h.clientKeys.PublicKey(ctx, keys.DPoPProofSigning, h.signatureAlgorithm)
	if err != nil {
		return "", fmt.Errorf("fapitest: resolve dpop key: %w", err)
	}
	signer := harnessSigner{
		ctx: ctx, manager: h.clientKeys, purpose: keys.DPoPProofSigning,
		algorithm: h.signatureAlgorithm, publicKey: info.PublicKey,
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: signer, Algorithm: h.signatureAlgorithm,
		Method: method, URL: target, AccessToken: accessToken,
		Now: h.Clock.Now(), Random: rand.Reader,
	})
	if err != nil {
		return "", fmt.Errorf("fapitest: create dpop proof: %w", err)
	}
	return proof, nil
}
