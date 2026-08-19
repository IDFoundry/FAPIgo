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

	authServer *authServer
	httpClient *http.Client
	clientKeys *memKeyManager
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

	asKeys := newMemKeyManager(t, "as", keys.JARMSigning, keys.AccessTokenSigning, keys.IDTokenSigning)
	clientKeys := newMemKeyManager(t, "rp", keys.ClientAuthentication, keys.RequestObjectSigning, keys.DPoPProofSigning)

	issuer, err := fapi.ParseIssuerURL(Issuer)
	if err != nil {
		t.Fatalf("fapitest: ParseIssuerURL: %v", err)
	}

	registeredClient, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       ClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{RedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		RequestObjectAlgorithm:   fapi.ES256,
		AllowedScopes:            []string{"openid", "accounts", "offline_access"},
	})
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
			ClientAssertion: server.AlgorithmSet{fapi.ES256},
			RequestObject:   server.AlgorithmSet{fapi.ES256},
			JARM:            fapi.ES256,
			IDToken:         fapi.ES256,
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
	revocation := newMemRevocationStore()
	jwtAccessTokens, err := server.NewJWTAccessTokens(asKeys, fapi.ES256)
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
	srv, err := server.New(srvCfg, srvDeps)
	if err != nil {
		t.Fatalf("fapitest: server.New: %v", err)
	}
	as.srv = srv

	httpClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	clientCfg := client.Config{
		Issuer:      issuer,
		ClientID:    ClientID,
		RedirectURI: RedirectURI,
		Endpoints: client.Endpoints{
			Authorization:              srvCfg.Endpoints.Authorization,
			Token:                      srvCfg.Endpoints.Token,
			PushedAuthorizationRequest: srvCfg.Endpoints.PushedAuthorizationRequest,
		},
		Profile: clientProfile,
		Algorithms: client.Algorithms{
			ClientAuthentication: fapi.ES256,
			RequestObject:        fapi.ES256,
			DPoP:                 fapi.ES256,
			JARM:                 fapi.ES256,
			IDToken:              fapi.ES256,
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
		},
	}
	clientDeps := client.Dependencies{
		Sessions:   newMemSessionStore(),
		Keys:       clientKeys,
		IssuerKeys: &memIssuerKeySource{issuer: Issuer, manager: asKeys},
		HTTP:       httpClient,
		Clock:      clock,
		Random:     rand.Reader,
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
	resourceJWT, err := resource.NewJWTAccessTokens(&memIssuerKeySource{issuer: Issuer, manager: asKeys}, issuer, Issuer, fapi.ES256, 5*time.Minute)
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

	return &Harness{t: t, Client: c, Resource: rs, Clock: clock, authServer: as, httpClient: httpClient, clientKeys: clientKeys}
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
	defer res.Body.Close()
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

// harnessSigner adapts a memKeyManager to crypto.Signer, the same
// pattern client and server each use internally over keys.KeyManager —
// see client/signer.go.
type harnessSigner struct {
	ctx       context.Context
	manager   *memKeyManager
	purpose   keys.SigningPurpose
	algorithm fapi.SignatureAlgorithm
	publicKey crypto.PublicKey
}

func (s harnessSigner) Public() crypto.PublicKey { return s.publicKey }

func (s harnessSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	sig, err := s.manager.Sign(s.ctx, keys.SigningRequest{Purpose: s.purpose, Algorithm: s.algorithm, Digest: digest})
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
	info, err := h.clientKeys.PublicKey(ctx, keys.DPoPProofSigning, fapi.ES256)
	if err != nil {
		return "", fmt.Errorf("fapitest: resolve dpop key: %w", err)
	}
	signer := harnessSigner{
		ctx: ctx, manager: h.clientKeys, purpose: keys.DPoPProofSigning,
		algorithm: fapi.ES256, publicKey: info.PublicKey,
	}
	proof, err := dpop.CreateProof(dpop.ProofRequest{
		Signer: signer, Algorithm: fapi.ES256,
		Method: method, URL: target, AccessToken: accessToken,
		Now: h.Clock.Now(), Random: rand.Reader,
	})
	if err != nil {
		return "", fmt.Errorf("fapitest: create dpop proof: %w", err)
	}
	return proof, nil
}
