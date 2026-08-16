package main

import (
	"crypto/rand"
	"net/http"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/fapihttp"
	"github.com/osanderson/go-fapi/keys"
	fapires "github.com/osanderson/go-fapi/resource"
	"github.com/osanderson/go-fapi/server"
)

// newServerMux builds the full server.Server + HTTP router wiring from a
// resolved config — everything main needs before it can start listening.
// Factored out so the end-to-end smoke test can stand up the exact same
// wiring main.go uses, against its own TLS listener, without going
// through flags or a config file on disk.
func newServerMux(resolved ResolvedConfig, allowLoopbackHTTP bool) (*http.ServeMux, error) {
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
		keys.AccessTokenSigning: resolved.Algorithms.AccessToken,
		keys.IDTokenSigning:     resolved.Algorithms.IDToken,
	}
	if resolved.Profile == server.ProfileFAPISecurityWithMessageSigning {
		purposes[keys.JARMSigning] = resolved.Algorithms.JARM
	}
	keyManager, err := newEphemeralKeyManager(purposes)
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
	clientKeys, err := newClientKeySource(fetcher, resolved.Clients)
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
	replayStore := newInMemoryReplayStore()
	identityClaims := newStaticIdentityClaims(resolved.DefaultSubject, server.SystemClock{})
	srvDeps := server.Dependencies{
		Clients:        newStaticClientRepository(resolved.Clients),
		Transactions:   newInMemoryTransactionStore(),
		Grants:         newInMemoryGrantStore(),
		Replay:         replayStore,
		ClientKeys:     clientKeys,
		Keys:           keyManager,
		Clock:          server.SystemClock{},
		Random:         rand.Reader,
		IdentityClaims: identityClaims,
	}
	srv, err := server.New(srvCfg, srvDeps)
	if err != nil {
		return nil, err
	}

	// Backs GET /accounts — see resource.go's resourceHandler doc
	// comment for why this conformance binary hosts a stand-in
	// protected-resource endpoint alongside the AS itself.
	resourceVerifier, err := fapires.NewVerifier(fapires.Config{
		Issuer:    resolved.Issuer,
		Audience:  resolved.Issuer.String(), // matches server/token.go's own access-token aud claim
		Algorithm: resolved.Algorithms.AccessToken,
		Limits: fapires.Limits{
			MaxTokenLifetime: resolved.Limits.AccessTokenLifetime,
			MaxDPoPProofAge:  resolved.Limits.MaxDPoPProofAge,
			MaxClockSkew:     resolved.Limits.MaxClockSkew,
		},
	}, fapires.Dependencies{
		IssuerKeys: selfIssuerKeySource{keyManager: keyManager},
		Replay:     replayStore,
		Clock:      fapires.SystemClock{},
	})
	if err != nil {
		return nil, err
	}

	consent := newConsentHandler(srv, server.SystemClock{}, resolved.DefaultSubject)
	resourceURLValue := resourceURL.URL()
	userinfoURLValue := userinfoURL.URL()
	return newRouter(srv, consent, resolved.AdvertisedScopes, resourceVerifier, &resourceURLValue, &userinfoURLValue, identityClaims), nil
}
