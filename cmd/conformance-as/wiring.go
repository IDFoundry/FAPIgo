package main

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	fapires "github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// federationSigningAlgorithm is the algorithm this binary self-issues
// its Entity Configuration with, and requires of an
// automatically-registered client's own openid_relying_party
// private_key_jwt registration — matches every other algorithm choice
// in this binary (server.RecommendedAlgorithms()'s own ES256 default).
const federationSigningAlgorithm = fapi.ES256

// federationStatementLifetime/federationMaxStatementLifetime/
// federationMaxPathLength/federationMaxCacheAge bound this binary's own
// federation.SelfIssuer/federation.Resolver — see server.FederationConfig/
// AutomaticRegistrationConfig for what each configures. Generous, fixed
// values: this binary's own federation posture isn't a conformance-run
// dimension the way -ciba/-mtls are, so unlike Algorithms/Limits (see
// Config's own doc comment) there's no server.Recommended* federation
// equivalent to defer to yet.
const (
	federationStatementLifetime    = time.Hour
	federationMaxStatementLifetime = 2 * time.Hour
	federationMaxPathLength        = 5
	federationMaxCacheAge          = 5 * time.Minute
)

// buildFederationFetcher builds this binary's own outbound TLS client
// for reaching another federation peer over docker-compose's private
// network (peerCertPool, pinned to the shared self-signed cert
// RootCAs when one is actually configured — resolved.TLSCertFile,
// empty under -insecure-http, where there's no TLS to verify at all —
// rather than InsecureSkipVerify), federationFetcherCfg (fapihttp.Config's
// own shared template for every federation peer fetch this binary
// makes, AllowedPrivateHosts deliberately left unset here — see below
// for why), and, when appropriate, the static federationFetcher itself.
//
// federationFetcher is nil when resolved.Federation == nil (nothing
// needs it), or when federationTrustAnchorAdmin is set: in that case
// dynamicFederationClients builds its own fetcher fresh on every
// rebuild instead, with AllowedPrivateHosts computed from the
// *current* trust anchor set rather than a fixed one from startup —
// federation.Resolver's own outbound Trust Chain walk crosses
// container boundaries within docker-compose's own private network
// the same way cmd/conformance-federation-trust-anchor's own /resolve
// endpoint does; see that binary's own doc comment for the full
// reasoning, and dynamicFederationClients' own doc comment for why a
// fixed set isn't enough once a Trust Anchor can be added at runtime.
// Never shared with ephemeral.NewClientKeySource's own fetcher — that
// one resolves a registered client's own, potentially arbitrary
// jwks_uri, and keeps its narrower, unmodified SSRF posture: no reason
// to widen what that unrelated path accepts.
func buildFederationFetcher(resolved ResolvedConfig, allowLoopbackHTTP, federationTrustAnchorAdmin bool) (federationFetcher *fapihttp.Client, federationFetcherCfg fapihttp.Config, peerCertPool *x509.CertPool, err error) {
	var peerHTTPClient *http.Client
	if resolved.Federation != nil {
		peerHTTPClient = &http.Client{Timeout: httpFetchTimeout}
		if resolved.TLSCertFile != "" {
			certPEM, err := os.ReadFile(resolved.TLSCertFile) // #nosec G304 -- operator's own -cert/tls.cert_file config value, not untrusted input
			if err != nil {
				return nil, fapihttp.Config{}, nil, fmt.Errorf("federation: read cert file for peer trust pool: %w", err)
			}
			peerCertPool = x509.NewCertPool()
			if !peerCertPool.AppendCertsFromPEM(certPEM) {
				return nil, fapihttp.Config{}, nil, fmt.Errorf("federation: no certificates found in %s", resolved.TLSCertFile)
			}
			peerHTTPClient.Transport = &http.Transport{TLSClientConfig: fapitest.PeerTLSConfig(peerCertPool, nil)}
		}
	}

	federationFetcherCfg = fapihttp.Config{
		MaxResponseBytes:  1 << 20,
		RequestTimeout:    httpFetchTimeout,
		MaxRedirects:      2,
		AllowLoopbackHTTP: allowLoopbackHTTP,
	}
	if resolved.Federation != nil && !federationTrustAnchorAdmin {
		allowedPrivateHosts := make([]string, 0, len(resolved.Federation.TrustAnchors))
		for _, ta := range resolved.Federation.TrustAnchors {
			u, err := url.Parse(ta.EntityID)
			if err != nil {
				return nil, fapihttp.Config{}, nil, fmt.Errorf("federation: trust anchor entity id %q: %w", ta.EntityID, err)
			}
			allowedPrivateHosts = append(allowedPrivateHosts, u.Hostname())
		}
		cfg := federationFetcherCfg
		cfg.AllowedPrivateHosts = allowedPrivateHosts
		federationFetcher, err = fapihttp.New(peerHTTPClient, cfg)
		if err != nil {
			return nil, fapihttp.Config{}, nil, err
		}
	}
	return federationFetcher, federationFetcherCfg, peerCertPool, nil
}

// newServerMux builds the full server.Server + HTTP router wiring from a
// resolved config — everything main needs before it can start listening.
// Factored out so the end-to-end smoke test can stand up the exact same
// wiring main.go uses, against its own TLS listener, without going
// through flags or a config file on disk.
func newServerMux(resolved ResolvedConfig, allowLoopbackHTTP bool, dpopNonceChallenge bool, userinfoSigning bool, ciba bool, clientCredentialsGrant bool, cibaApprovalUIToken string, federationTrustAnchorAdmin bool) (*http.ServeMux, error) {
	endpoints, err := buildEndpoints(resolved.Issuer, allowLoopbackHTTP)
	if err != nil {
		return nil, err
	}
	userinfoURL, err := buildUserinfoURL(resolved.Issuer, allowLoopbackHTTP)
	if err != nil {
		return nil, err
	}
	accountsURL, err := buildAccountsURL(resolved.Issuer, allowLoopbackHTTP)
	if err != nil {
		return nil, err
	}
	backchannelAuthenticationURL, err := buildBackchannelAuthenticationURL(resolved.Issuer, allowLoopbackHTTP)
	if err != nil {
		return nil, err
	}
	// Populated only under -mtls (resolved.MTLSEndpoints is the zero
	// value otherwise) — see buildMTLSUserinfoURL's own doc comment for
	// why this is computed here rather than folded into
	// server.MTLSEndpoints.
	var mtlsUserinfoURL *fapi.URL
	if !resolved.MTLSEndpoints.IsZero() {
		u, err := buildMTLSUserinfoURL(resolved.Issuer, resolved.MTLSListenAddr)
		if err != nil {
			return nil, err
		}
		mtlsUserinfoURL = &u
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
	if userinfoSigning {
		purposes[keys.UserInfoSigning] = resolved.Algorithms.IDToken
	}
	if resolved.Federation != nil {
		purposes[keys.FederationEntitySigning] = federationSigningAlgorithm
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

	federationFetcher, federationFetcherCfg, peerCertPool, err := buildFederationFetcher(resolved, allowLoopbackHTTP, federationTrustAnchorAdmin)
	if err != nil {
		return nil, err
	}

	algorithms := resolved.Algorithms
	// Off by default (main.go's -userinfo-signing flag): the FAPI 2.0
	// Security Profile doesn't require signed UserInfo responses, so
	// this stays a worked-example opt-in rather than part of
	// RecommendedAlgorithms — reuses the same algorithm as ID tokens,
	// the same "one official value, no override" precedent as
	// AccessTokenSigning above.
	if userinfoSigning {
		algorithms.UserInfo = resolved.Algorithms.IDToken
	}
	limits := resolved.Limits
	// Off by default (main.go's -ciba flag): CIBA isn't part of the
	// FAPI 2.0 Security Profile itself, so this stays a worked-example
	// opt-in like -userinfo-signing above — reuses the same algorithm
	// as ID tokens for the same "one official value, no override"
	// reason.
	if ciba {
		endpoints.BackchannelAuthentication = backchannelAuthenticationURL
		// The full recommended set (ES256/PS256/EdDSA), not just
		// IDToken's single value: unlike UserInfo signing (this
		// server's own choice), this is a client-verification
		// allow-list — the same role ClientAssertion/RequestObject's
		// own algorithm sets play, including a PS256-registered test
		// client's own backchannel authentication requests.
		algorithms.BackchannelAuthenticationRequest = server.RecommendedAlgorithmSet()
		limits.BackchannelAuthenticationRequestLifetime = backchannelAuthenticationRequestLifetime
		limits.MaxBackchannelAuthenticationRequestLifetime = maxBackchannelAuthenticationRequestLifetime
		limits.BackchannelAuthenticationPollInterval = backchannelAuthenticationPollInterval
	}
	rarRegistry, err := newSampleRARRegistry()
	if err != nil {
		return nil, err
	}
	srvCfg := server.Config{
		Issuer:        resolved.Issuer,
		Endpoints:     endpoints,
		MTLSEndpoints: resolved.MTLSEndpoints,
		Profile:       resolved.Profile,
		Algorithms:    algorithms,
		Limits:        limits,
		// These storage implementations are honestly non-durable
		// in-memory maps. AssuranceProduction would make server.New
		// reject them via checkStoreAssurance — do not change this to
		// AssuranceProduction without also implementing
		// storage.StoreAssurance on every store constructed below.
		Assurance: server.AssuranceDevelopment,
		RAR:       rarRegistry,
		// Off by default (main.go's -client-credentials-grant flag) — RFC
		// 6749 §4.4 isn't part of the FAPI 2.0 Security Profile itself,
		// so this stays a worked-example opt-in like -ciba/-userinfo-signing
		// above.
		ClientCredentialsGrant: clientCredentialsGrant,
	}
	// autoRegLimits/autoRegCfg carry the values that would normally go
	// straight into srvCfg.AutomaticRegistration (letting server.New
	// build its own immutable AutomaticClientRepository internally) —
	// under federationTrustAnchorAdmin, srvCfg.AutomaticRegistration is
	// instead left at its zero value (server.New skips that internal
	// construction entirely) and these same values feed
	// newDynamicFederationClients below, once clientRepo/clientKeys
	// exist to use as its own Underlying. See
	// dynamicFederationClients' own doc comment for why.
	var autoRegLimits federation.Limits
	var autoRegCfg federation.AutomaticRegistrationConfig
	if resolved.Federation != nil {
		srvCfg.Federation = server.FederationConfig{
			EntityID:       resolved.Federation.EntityID,
			AuthorityHints: resolved.Federation.AuthorityHints,
			Lifetime:       federationStatementLifetime,
			Algorithm:      federationSigningAlgorithm,
		}
		autoRegLimits = federation.Limits{
			MaxPathLength:        federationMaxPathLength,
			MaxStatementLifetime: federationMaxStatementLifetime,
			MaxClockSkew:         resolved.Limits.MaxClockSkew,
		}
		autoRegCfg = federation.AutomaticRegistrationConfig{
			AllowedScopes: resolved.Federation.AllowedScopes,
			MaxCacheAge:   federationMaxCacheAge,
		}
		if !federationTrustAnchorAdmin {
			srvCfg.AutomaticRegistration = server.AutomaticRegistrationConfig{
				TrustAnchors:         resolved.Federation.TrustAnchors,
				AllowedScopes:        resolved.Federation.AllowedScopes,
				MaxPathLength:        federationMaxPathLength,
				MaxStatementLifetime: federationMaxStatementLifetime,
				MaxClockSkew:         resolved.Limits.MaxClockSkew,
				MaxCacheAge:          federationMaxCacheAge,
			}
		}
	}
	replayStore := memstore.NewReplayStore()
	revocationStore := memstore.NewRevocationStore()
	identityClaims := newStaticIdentityClaims(resolved.DefaultSubject, server.SystemClock{})
	clientRepo := memstore.NewClientRepository(resolved.Clients)

	// dynClients is non-nil only under federationTrustAnchorAdmin — see
	// dynamicFederationClients' own doc comment. It wraps clientRepo/
	// clientKeys as its own Underlying, exactly mirroring what
	// server.New would otherwise build internally from
	// srvCfg.AutomaticRegistration (left at its zero value in that
	// case, above, so server.New skips its own construction).
	var dynClients *dynamicFederationClients
	if resolved.Federation != nil && federationTrustAnchorAdmin {
		var err error
		dynClients, err = newDynamicFederationClients(resolved.Federation.TrustAnchors, clientRepo, clientKeys, dynamicFederationClientsConfig{
			PeerCertPool: peerCertPool, HTTPTimeout: httpFetchTimeout, FetcherCfg: federationFetcherCfg,
			Limits: autoRegLimits, AutoCfg: autoRegCfg, Clock: federation.SystemClock{},
		})
		if err != nil {
			return nil, fmt.Errorf("federation trust anchor admin: %w", err)
		}
	}

	// Which server.AccessTokenIssuer/resource.AccessTokenResolver pair
	// this run uses — see main.go's -access-token-format flag. Under
	// AccessTokenFormatOpaque, both sides share one
	// memstore.AccessTokenStore (issuance and verification against the
	// same in-memory table, mirroring how revocationStore is already
	// shared above); under AccessTokenFormatJWT, verification instead
	// resolves the AS's own signing key via selfIssuerKeySource — see
	// resource.go's userinfoHandler doc comment for why this
	// conformance binary hosts its own protected-resource verification
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
			8, // selfIssuerKeySource reads keyManager directly — never more than a handful of keys
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
		Clients:      clientRepo,
		Transactions: memstore.NewTransactionStore(),
		Grants:       memstore.NewGrantStore(),
		Replay:       replayStore,
		ClientKeys:   clientKeys,
		Keys:         keyManager,
		AccessTokens: srvAccessTokens,
		Revocation:   revocationStore,
		// This binary's mTLS listener (see newMTLSServer in main.go) only
		// requests a client certificate (tls.RequestClientCert); it never
		// verifies the chain itself, and this binary stands up no CA
		// trust store of its own to verify against — see config.go's own
		// top-of-file doc comment. NoClientCertificateChainTrust{} makes
		// that pre-existing, deliberate limitation an explicit, visible
		// choice instead of an implicit one: a real tls_client_auth
		// deployment would pass TrustedClientCAs{Roots: ...} here instead.
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		Clock:                  server.SystemClock{},
		Random:                 rand.Reader,
		IdentityClaims:         identityClaims,
		// Inert unless a request actually sends authorization_details,
		// same as RAR itself (srvCfg.RAR above) — see sampleRARPolicy's
		// own doc comment for why this reference binary always grants
		// everything requested rather than modeling a real per-client
		// policy. AuthorizationCodeRARPolicy/CIBARARPolicy are the
		// Authorization Code and CIBA grants' own independent
		// request-time gates; without them, every request naming
		// authorization_details on either grant would now be refused
		// outright (RARPolicy's own "unconfigured is not permissive"
		// stance).
		ClientCredentialsRARPolicy: sampleRARPolicy{},
		AuthorizationCodeRARPolicy: sampleRARPolicy{},
		CIBARARPolicy:              sampleRARPolicy{},
		// Only required when srvCfg.AutomaticRegistration.TrustAnchors
		// is set (above) — nil otherwise (resolved.Federation == nil),
		// matching AutomaticRegistration's own nil zero value. A
		// separate fetcher from ephemeral.NewClientKeySource's own —
		// see federationFetcher's own doc comment above for why.
		FederationHTTP: federationFetcher,
	}
	if dynClients != nil {
		srvDeps.Clients = dynClients
		srvDeps.ClientKeys = dynClients
	}
	// Off by default (main.go's -dpop-nonce-challenge flag) — same
	// reasoning as the resource-side block below: client.ExchangeCode
	// already retries a use_dpop_nonce challenge, but the OIDF suite's
	// own driver isn't guaranteed to, so this stays opt-in. A separate
	// nonce store from the resource side's: PAR/token (this server's
	// own role, RFC 9449 §8) and /userinfo (the resource role, §9) are
	// logically distinct nonce spaces, even though this one demo binary
	// happens to host both.
	if dpopNonceChallenge {
		srvCfg.Limits.DPoPNonceLifetime = dpopNonceLifetime
		srvDeps.Nonces = memstore.NewNonceStore()
	}
	if ciba {
		srvDeps.Backchannel = memstore.NewBackchannelAuthenticationStore()
		// A client registered storage.BackchannelTokenDeliveryModePoll
		// (config.go's own default) never triggers a Notify call at
		// all, so wiring the real notifier unconditionally here is safe
		// regardless of which delivery mode any given registered client
		// actually uses.
		srvDeps.BackchannelNotifier = newHTTPBackchannelNotifier()
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
	backchannel := newBackchannelHandler(srv, server.SystemClock{}, resolved.DefaultSubject)
	userinfoURLValue := userinfoURL.URL()
	accountsURLValue := accountsURL.URL()
	return newRouter(srv, consent, backchannel, resolved.AdvertisedScopes, resourceVerifier, &userinfoURLValue, mtlsUserinfoURL, &accountsURLValue, identityClaims, clientRepo, userinfoSigning, cibaApprovalUIToken, resolved.Federation != nil, dynClients), nil
}
