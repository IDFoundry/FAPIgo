package main

import (
	"crypto/rand"
	"fmt"
	"net/http"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	fapires "github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// newServerMux builds the full server.Server + HTTP router wiring from a
// resolved config — everything main needs before it can start listening.
// Factored out so the end-to-end smoke test can stand up the exact same
// wiring main.go uses, against its own TLS listener, without going
// through flags or a config file on disk.
func newServerMux(resolved ResolvedConfig, allowLoopbackHTTP bool, dpopNonceChallenge bool) (*http.ServeMux, error) {
	endpoints, err := buildEndpoints(resolved.Issuer, allowLoopbackHTTP)
	if err != nil {
		return nil, err
	}
	resourceURL, err := buildResourceURL(resolved.Issuer, allowLoopbackHTTP, "/accounts")
	if err != nil {
		return nil, err
	}
	userinfoURL, err := buildResourceURL(resolved.Issuer, allowLoopbackHTTP, "/userinfo")
	if err != nil {
		return nil, err
	}

	purposes := map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		// No Algorithms.AccessToken anymore — access-token signing is
		// JWTAccessTokens' own concern (see below), not Config's.
		// Reuses the same recommended value as IDToken (both ES256,
		// per server.RecommendedAlgorithms()) to keep PR #47's "one
		// official value, no override" intent intact.
		keys.AccessTokenSigning: resolved.Algorithms.IDToken,
		keys.IDTokenSigning:     resolved.Algorithms.IDToken,
	}
	if resolved.Profile == server.ProfileFAPISecurityWithMessageSigning {
		purposes[keys.JARMSigning] = resolved.Algorithms.JARM
	}
	keyManager, err := ephemeral.NewKeyManager(purposes)
	if err != nil {
		return nil, err
	}

	fetcher, err := fapihttp.New(&http.Client{Timeout: httpFetchTimeout}, fapihttp.Config{
		MaxResponseBytes:  1 << 20,
		RequestTimeout:    httpFetchTimeout,
		MaxRedirects:      2,
		AllowLoopbackHTTP: allowLoopbackHTTP,
	})
	if err != nil {
		return nil, err
	}
	clientKeys, err := ephemeral.NewClientKeySource(fetcher, resolved.ClientKeys)
	if err != nil {
		return nil, err
	}

	srvCfg := server.Config{
		Issuer:     resolved.Issuer,
		Endpoints:  endpoints,
		Profile:    resolved.Profile,
		Algorithms: resolved.Algorithms,
		Limits:     resolved.Limits,
		// These storage implementations are honestly non-durable
		// in-memory maps. AssuranceProduction would make server.New
		// reject them via checkStoreAssurance — do not change this to
		// AssuranceProduction without also implementing
		// storage.StoreAssurance on every store constructed below.
		Assurance: server.AssuranceDevelopment,
	}
	replayStore := memstore.NewReplayStore()
	revocationStore := memstore.NewRevocationStore()
	identityClaims := newStaticIdentityClaims(resolved.DefaultSubject, server.SystemClock{})
	clientRepo := memstore.NewClientRepository(resolved.Clients)

	// Which server.AccessTokenIssuer/resource.AccessTokenResolver pair
	// this run uses — see main.go's -access-token-format flag. Under
	// AccessTokenFormatOpaque, both sides share one
	// memstore.AccessTokenStore (issuance and verification against the
	// same in-memory table, mirroring how revocationStore is already
	// shared above); under AccessTokenFormatJWT, verification instead
	// resolves the AS's own signing key via selfIssuerKeySource — see
	// resource.go's resourceHandler doc comment for why this
	// conformance binary hosts a stand-in protected-resource endpoint
	// alongside the AS itself.
	var (
		srvAccessTokens      server.AccessTokenIssuer
		resourceAccessTokens fapires.AccessTokenResolver
	)
	switch resolved.AccessTokenFormat {
	case AccessTokenFormatJWT:
		jwtIssuer, err := server.NewJWTAccessTokens(keyManager, resolved.Algorithms.IDToken)
		if err != nil {
			return nil, err
		}
		srvAccessTokens = jwtIssuer
		jwtVerifier, err := fapires.NewJWTAccessTokens(
			selfIssuerKeySource{keyManager: keyManager}, resolved.Issuer,
			resolved.Issuer.String(), // matches server/accesstoken.go's own access-token aud claim
			resolved.Algorithms.IDToken, resolved.Limits.AccessTokenLifetime,
		)
		if err != nil {
			return nil, err
		}
		resourceAccessTokens = jwtVerifier
	case AccessTokenFormatOpaque:
		accessTokenStore := memstore.NewAccessTokenStore()
		opaqueIssuer, err := server.NewOpaqueAccessTokens(accessTokenStore)
		if err != nil {
			return nil, err
		}
		srvAccessTokens = opaqueIssuer
		opaqueVerifier, err := fapires.NewOpaqueAccessTokens(accessTokenStore)
		if err != nil {
			return nil, err
		}
		resourceAccessTokens = opaqueVerifier
	default:
		return nil, fmt.Errorf("conformance-as: unknown access token format %q", resolved.AccessTokenFormat)
	}

	srvDeps := server.Dependencies{
		Clients:        clientRepo,
		Transactions:   memstore.NewTransactionStore(),
		Grants:         memstore.NewGrantStore(),
		Replay:         replayStore,
		ClientKeys:     clientKeys,
		Keys:           keyManager,
		AccessTokens:   srvAccessTokens,
		Revocation:     revocationStore,
		Clock:          server.SystemClock{},
		Random:         rand.Reader,
		IdentityClaims: identityClaims,
	}
	// Off by default (main.go's -dpop-nonce-challenge flag) — same
	// reasoning as the resource-side block below: client.ExchangeCode
	// already retries a use_dpop_nonce challenge, but the OIDF suite's
	// own driver isn't guaranteed to, so this stays opt-in. A separate
	// nonce store from the resource side's: PAR/token (this server's
	// own role, RFC 9449 §8) and /accounts, /userinfo (the resource
	// role, §9) are logically distinct nonce spaces, even though this
	// one demo binary happens to host both.
	if dpopNonceChallenge {
		srvCfg.Limits.DPoPNonceLifetime = dpopNonceLifetime
		srvDeps.Nonces = memstore.NewNonceStore()
	}
	srv, err := server.New(srvCfg, srvDeps)
	if err != nil {
		return nil, err
	}

	resourceCfg := fapires.Config{
		Limits: fapires.Limits{
			MaxDPoPProofAge: resolved.Limits.MaxDPoPProofAge,
			MaxClockSkew:    resolved.Limits.MaxClockSkew,
		},
	}
	resourceDeps := fapires.Dependencies{
		AccessTokens: resourceAccessTokens,
		Replay:       replayStore,
		Revocation:   revocationStore,
		Clock:        fapires.SystemClock{},
	}
	// Off by default (main.go's -dpop-nonce-challenge flag): the OIDF
	// suite's own AS-plan protected-resource caller isn't guaranteed to
	// implement the client-side nonce-challenge retry the way this
	// module's own client package does, so turning this on
	// unconditionally would risk breaking unrelated AS conformance.
	if dpopNonceChallenge {
		resourceCfg.Limits.DPoPNonceLifetime = dpopNonceLifetime
		resourceDeps.Nonces = memstore.NewNonceStore()
		resourceDeps.Random = rand.Reader
	}
	resourceVerifier, err := fapires.NewVerifier(resourceCfg, resourceDeps)
	if err != nil {
		return nil, err
	}

	consent := newConsentHandler(srv, clientRepo, server.SystemClock{}, resolved.DefaultSubject)
	resourceURLValue := resourceURL.URL()
	userinfoURLValue := userinfoURL.URL()
	return newRouter(srv, consent, resolved.AdvertisedScopes, resourceVerifier, &resourceURLValue, &userinfoURLValue, identityClaims), nil
}
