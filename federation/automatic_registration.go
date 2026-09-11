package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// relyingPartyEntityType is the Entity Type Identifier a Relying
// Party's own client registration metadata is published under (OpenID
// Federation 1.0 §5.1), read from Resolver.Resolve's own
// ResolvedEntity.Metadata.
const relyingPartyEntityType = "openid_relying_party"

// AutomaticRegistrationConfig configures AutomaticClientRepository —
// see its own doc comment for the mechanism this implements (OpenID
// Federation 1.0 §12.1, "Automatic Registration").
type AutomaticRegistrationConfig struct {
	// AllowedScopes is the scope allowlist granted to every
	// automatically-registered client, uniformly. This deliberately
	// does NOT come from the Relying Party's own self-published
	// metadata: an RP's openid_relying_party metadata is
	// attacker-controlled (any federation member publishes its own), so
	// trusting a self-asserted "these are the scopes I'm allowed" claim
	// would let any RP grant itself unlimited scope. Required — at
	// least one.
	AllowedScopes []string

	// MaxCacheAge bounds how long a resolved client's Trust Chain is
	// reused before it is resolved again — the actual cache lifetime
	// for a given client is min(MaxCacheAge, its own Trust Chain's
	// ResolvedEntity.ExpiresAt), never longer than the chain itself
	// remains valid. Required — must be positive.
	MaxCacheAge time.Duration

	// AllowsClientCredentialsGrant permits every automatically-registered
	// client to use the RFC 6749 §4.4 client_credentials grant —
	// uniformly, exactly like AllowedScopes, and for the identical
	// reason: never inferred from the RP's own self-published metadata.
	// Deciding whether a client may mint a token representing itself,
	// with no end user or authorization code involved at all, is a
	// capability grant, not a mechanism detail an RP can safely
	// self-assert. False (the zero value/default) means no
	// automatically-registered client may use client_credentials,
	// regardless of what it publishes. Also still requires
	// server.Config.ClientCredentialsGrant to be enabled server-wide,
	// exactly as storage.RegisteredClientConfig's own field of the same
	// name does for a statically registered client.
	AllowsClientCredentialsGrant bool

	// AllowsCIBA permits every automatically-registered client to use
	// OpenID Connect Client-Initiated Backchannel Authentication —
	// uniformly, for the identical reason AllowsClientCredentialsGrant
	// is a config-level switch rather than inferred from RP metadata:
	// whether an RP may request authentication for an end user
	// out-of-band, with no browser redirect to anchor consent to, is a
	// capability grant. When true, an RP's own
	// backchannel_authentication_request_signing_alg (which doubles as
	// its CIBA opt-in flag, exactly as
	// storage.RegisteredClientConfig.BackchannelAuthenticationRequestAlgorithm's
	// own doc comment describes), backchannel_token_delivery_mode and
	// backchannel_client_notification_endpoint metadata is read — these
	// are mechanism details (which algorithm, which delivery mode), safe
	// to trust from self-published metadata the same way
	// RequestObjectSigningAlg already is, once the capability itself has
	// been granted here. When false, that metadata is ignored entirely
	// and CIBA stays disabled for every automatically-registered client.
	AllowsCIBA bool
}

// cachedClient is one Relying Party's resolved registration, cached
// until whichever of AutomaticRegistrationConfig.MaxCacheAge or the
// Trust Chain's own ResolvedEntity.ExpiresAt comes first.
type cachedClient struct {
	client    storage.RegisteredClient
	jwks      json.RawMessage
	expiresAt time.Time
}

// AutomaticClientRepository implements storage.ClientRepository via
// OpenID Federation 1.0 §12.1 ("Automatic Registration"): a Relying
// Party that presents its own Entity Identifier as client_id, with no
// prior registration step, is resolved on demand — its Trust Chain is
// walked (via Resolver) and its Resolved Metadata's own
// openid_relying_party object becomes this client's registration,
// exactly as if an operator had configured it via
// storage.NewRegisteredClient by hand.
//
// Static registration always wins: Underlying is tried first, and its
// result returned as-is when it succeeds — federation resolution is
// only attempted when Underlying fails to resolve id AND id is itself
// a well-formed https Entity Identifier (ValidEntityID). Underlying's
// own interface has no way to distinguish "no such client" from a real
// backing-store failure (storage.ClientRepository's own contract), so
// a transient Underlying failure for an id that happens to look like
// an Entity Identifier is indistinguishable from "not statically
// registered" here — an inherent limitation of that interface, not
// something this type can work around.
//
// The client_credentials grant and CIBA are each gated by their own
// config-level switch (AutomaticRegistrationConfig.AllowsClientCredentialsGrant/
// AllowsCIBA) — off by default, since whether an automatically-resolved
// RP may use either is a capability grant an operator makes, never
// something an RP's own self-published metadata can grant itself. See
// doc.go for what this first version still deliberately does not
// implement at all: every RFC 8705 mTLS client authentication method
// (ClientAuthMethodSelfSignedTLSClientAuth and its siblings — verifying
// these correctly needs the "x5c" member of the client's own published
// JWK, which internal/jose's JWK Set parsing does not currently
// preserve, so only ClientAuthMethodPrivateKeyJWT is supported).
// PAR/JAR-level enforcement of OpenID Federation 1.0 §12.1.1's own
// aud/sub/jti Request Object rules is a request-handling concern, not a
// client registration one — see storage.RegisteredClientConfig's own
// AutomaticFederationRegistration field and
// requestobject.VerifyPolicy.AutomaticFederationRegistration.
type AutomaticClientRepository struct {
	underlying storage.ClientRepository
	resolver   *Resolver
	fetcher    *fapihttp.Client
	cfg        AutomaticRegistrationConfig
	clock      Clock

	mu    sync.Mutex
	cache map[fapi.ClientID]cachedClient
}

// NewAutomaticClientRepository validates cfg and returns an
// AutomaticClientRepository. underlying, resolver, fetcher and clock
// must all be non-nil — there is no implicit fallback. Pass an
// underlying that always fails (e.g. one backed by an empty in-memory
// store) to get automatic-registration-only behavior, with no
// statically registered clients at all. fetcher resolves a client's own
// "jwks_uri", when its openid_relying_party metadata declares one
// instead of publishing its keys inline — typically the same
// *fapihttp.Client already passed as resolver's own
// Dependencies.HTTP.
func NewAutomaticClientRepository(underlying storage.ClientRepository, resolver *Resolver, fetcher *fapihttp.Client, cfg AutomaticRegistrationConfig, clock Clock) (*AutomaticClientRepository, error) {
	if underlying == nil {
		return nil, fmt.Errorf("federation: underlying client repository is required")
	}
	if resolver == nil {
		return nil, fmt.Errorf("federation: resolver is required")
	}
	if fetcher == nil {
		return nil, fmt.Errorf("federation: fetcher is required")
	}
	if len(cfg.AllowedScopes) == 0 {
		return nil, fmt.Errorf("federation: config: allowed_scopes is required")
	}
	if cfg.MaxCacheAge <= 0 {
		return nil, fmt.Errorf("federation: config: max_cache_age must be positive")
	}
	if clock == nil {
		return nil, fmt.Errorf("federation: clock is required")
	}
	return &AutomaticClientRepository{
		underlying: underlying, resolver: resolver, fetcher: fetcher, cfg: cfg, clock: clock,
		cache: make(map[fapi.ClientID]cachedClient),
	}, nil
}

// ResolveClient implements storage.ClientRepository.
func (a *AutomaticClientRepository) ResolveClient(ctx context.Context, id fapi.ClientID) (storage.RegisteredClient, error) {
	if client, err := a.underlying.ResolveClient(ctx, id); err == nil {
		return client, nil
	}
	entry, err := a.resolve(ctx, id)
	if err != nil {
		return storage.RegisteredClient{}, err
	}
	return entry.client, nil
}

// resolveVerificationKeys resolves id's own client authentication keys
// from its cached (or freshly resolved) openid_relying_party metadata —
// the shared implementation behind AutomaticClientKeySource, factored
// here so it can reuse this type's own cache directly instead of each
// resolving the same Trust Chain independently.
func (a *AutomaticClientRepository) resolveVerificationKeys(ctx context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	entry, err := a.resolve(ctx, req.ClientID)
	if err != nil {
		return keys.VerificationKeySet{}, err
	}
	candidates, err := jose.ParseJWKSet(entry.jwks)
	if err != nil {
		return keys.VerificationKeySet{}, fmt.Errorf("federation: parse resolved client jwks: %w", err)
	}
	var matched []keys.VerificationKey
	for _, c := range candidates {
		if c.Algorithm != req.Algorithm {
			continue
		}
		if req.KeyID != "" && c.KeyID != req.KeyID {
			continue
		}
		matched = append(matched, keys.VerificationKey{KeyID: c.KeyID, Algorithm: c.Algorithm, PublicKey: c.PublicKey})
	}
	return keys.VerificationKeySet{Keys: matched}, nil
}

// resolve returns id's cached entry if still fresh, or resolves (via
// Resolver.Resolve) and caches a new one.
func (a *AutomaticClientRepository) resolve(ctx context.Context, id fapi.ClientID) (cachedClient, error) {
	now := a.clock.Now()

	a.mu.Lock()
	entry, ok := a.cache[id]
	a.mu.Unlock()
	if ok && now.Before(entry.expiresAt) {
		return entry, nil
	}

	if err := ValidEntityID(string(id)); err != nil {
		return cachedClient{}, fmt.Errorf("federation: %q is not a registered client and not a valid federation entity ID: %w", id, err)
	}
	resolved, err := a.resolver.Resolve(ctx, string(id))
	if err != nil {
		return cachedClient{}, fmt.Errorf("federation: resolve client %q: %w", id, err)
	}
	raw, ok := resolved.Metadata[relyingPartyEntityType]
	if !ok {
		return cachedClient{}, fmt.Errorf("federation: %q has no %s metadata", id, relyingPartyEntityType)
	}
	clientCfg, jwksSrc, err := registeredClientConfigFromMetadata(id, raw, a.cfg)
	if err != nil {
		return cachedClient{}, fmt.Errorf("federation: %q: %w", id, err)
	}
	client, err := storage.NewRegisteredClient(clientCfg)
	if err != nil {
		return cachedClient{}, fmt.Errorf("federation: %q: %w", id, err)
	}
	jwks := jwksSrc.inline
	if jwksSrc.uri != "" {
		if jwks, err = a.fetchJWKS(ctx, jwksSrc.uri); err != nil {
			return cachedClient{}, fmt.Errorf("federation: %q: %w", id, err)
		}
	}

	expiresAt := resolved.ExpiresAt
	if maxAge := now.Add(a.cfg.MaxCacheAge); maxAge.Before(expiresAt) {
		expiresAt = maxAge
	}
	entry = cachedClient{client: client, jwks: jwks, expiresAt: expiresAt}

	a.mu.Lock()
	a.cache[id] = entry
	a.mu.Unlock()
	return entry, nil
}

// fetchJWKS fetches and parses a client's remote jwks_uri, mirroring
// keys/ephemeral/clientkeysource.go's own refetch convention — the
// same hardened fapihttp.Client applies the SSRF/size-limit/
// content-type protections ARCHITECTURE.md requires for exactly this
// case, so this reuses it rather than issuing its own HTTP request.
func (a *AutomaticClientRepository) fetchJWKS(ctx context.Context, uri string) (json.RawMessage, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parse jwks_uri: %w", err)
	}
	res, err := a.fetcher.Fetch(ctx, fapihttp.FetchRequest{
		URL:                   u,
		ExpectedContentType:   "application/json",
		AlternateContentTypes: []string{"application/jwk-set+json"},
	})
	if err != nil {
		return nil, fmt.Errorf("fetch jwks_uri: %w", err)
	}
	if _, err := jose.ParseJWKSet(res.Body); err != nil {
		return nil, fmt.Errorf("parse fetched jwks: %w", err)
	}
	return json.RawMessage(res.Body), nil
}

// AutomaticClientKeySource implements keys.ClientKeySource by resolving
// a client's verification keys from the SAME cached Trust Chain
// resolution AutomaticClientRepository performs for ResolveClient — an
// automatically-registered client's authentication key comes from its
// own openid_relying_party metadata's "jwks" member (OpenID Federation
// 1.0 §12.1.1.1.2's own "the key material the client published in its
// metadata for the openid_relying_party Entity Type"), never from its
// Entity Configuration's own top-level federation signing key — a
// different key, for a different purpose (federation/doc.go).
//
// Underlying is tried first, exactly mirroring
// AutomaticClientRepository's own "static registration always wins"
// precedence — a statically registered client's real keys must never
// be shadowed by a federation lookup. Unlike ResolveClient's own
// single-value result, a keys.ClientKeySource legitimately returns an
// empty, error-free VerificationKeySet to mean "no matching key" (e.g.
// a real client mid-rotation, or simply a kid Underlying doesn't
// recognize) — so an empty result from Underlying falls through to
// federation resolution exactly like an error would, on the
// expectation that an Underlying implementation unaware of a given
// client ID at all is at least as likely to signal that with an empty
// result as with an error (keys.ClientKeySource's own interface
// documents no requirement either way). This mirrors
// AutomaticClientRepository's own documented "Underlying's interface
// has no way to distinguish these cases" limitation — a statically
// registered client legitimately missing a requested key triggers one
// wasted federation resolution attempt (which then also fails), not a
// silent wrong answer.
type AutomaticClientKeySource struct {
	underlying keys.ClientKeySource
	repo       *AutomaticClientRepository
}

// NewAutomaticClientKeySource validates its arguments and returns an
// AutomaticClientKeySource. repo should typically be the same
// *AutomaticClientRepository passed as Dependencies.Clients, so both
// dependencies share one cache instead of each resolving the same
// chain independently.
func NewAutomaticClientKeySource(underlying keys.ClientKeySource, repo *AutomaticClientRepository) (*AutomaticClientKeySource, error) {
	if underlying == nil {
		return nil, fmt.Errorf("federation: underlying client key source is required")
	}
	if repo == nil {
		return nil, fmt.Errorf("federation: automatic client repository is required")
	}
	return &AutomaticClientKeySource{underlying: underlying, repo: repo}, nil
}

// ResolveVerificationKeys implements keys.ClientKeySource.
func (s *AutomaticClientKeySource) ResolveVerificationKeys(ctx context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	if set, err := s.underlying.ResolveVerificationKeys(ctx, req); err == nil && len(set.Keys) > 0 {
		return set, nil
	}
	return s.repo.resolveVerificationKeys(ctx, req)
}

// relyingPartyMetadata is the subset of OpenID Connect Dynamic Client
// Registration 1.0 / RFC 8705 client metadata this package reads from a
// Resolved openid_relying_party object to build a
// storage.RegisteredClient — see AutomaticClientRepository's own doc
// comment for exactly which registration shapes are (and are not)
// supported in this first version.
type relyingPartyMetadata struct {
	RedirectURIs                          []string        `json:"redirect_uris"`
	TokenEndpointAuthMethod               string          `json:"token_endpoint_auth_method"`
	TokenEndpointAuthSigningAlg           string          `json:"token_endpoint_auth_signing_alg"`
	RequestObjectSigningAlg               string          `json:"request_object_signing_alg"`
	JWKS                                  json.RawMessage `json:"jwks"`
	JWKSURI                               string          `json:"jwks_uri"`
	TLSClientCertificateBoundAccessTokens bool            `json:"tls_client_certificate_bound_access_tokens"`
	IDTokenEncryptedResponseAlg           string          `json:"id_token_encrypted_response_alg"`
	IDTokenEncryptedResponseEnc           string          `json:"id_token_encrypted_response_enc"`
	UserinfoEncryptedResponseAlg          string          `json:"userinfo_encrypted_response_alg"`
	UserinfoEncryptedResponseEnc          string          `json:"userinfo_encrypted_response_enc"`

	// BackchannelAuthenticationRequestSigningAlg/BackchannelTokenDeliveryMode/
	// BackchannelClientNotificationEndpoint are read only when
	// AutomaticRegistrationConfig.AllowsCIBA permits it at all — see its
	// own doc comment for why granting the capability is a config-level
	// decision, while these are just mechanism details once granted.
	BackchannelAuthenticationRequestSigningAlg string `json:"backchannel_authentication_request_signing_alg"`
	BackchannelTokenDeliveryMode               string `json:"backchannel_token_delivery_mode"`
	BackchannelClientNotificationEndpoint      string `json:"backchannel_client_notification_endpoint"`
}

// jwksSource is a client's verification key material as declared by its
// own openid_relying_party metadata — exactly one of inline (already
// resolved, no I/O needed) or uri (fetched live via
// AutomaticClientRepository.fetchJWKS) is set, enforced by
// registeredClientConfigFromMetadata.
type jwksSource struct {
	inline json.RawMessage
	uri    string
}

// registeredClientConfigFromMetadata parses raw (an openid_relying_party
// Resolved Metadata object) and builds the storage.RegisteredClientConfig
// it describes, returning its jwks source separately (needed by
// AutomaticClientKeySource, not stored on storage.RegisteredClient
// itself). automaticCfg supplies the operator-level capability grants
// (AllowedScopes, AllowsClientCredentialsGrant, AllowsCIBA) that must
// never be inferred from raw itself — see AutomaticRegistrationConfig's
// own doc comments for why.
func registeredClientConfigFromMetadata(id fapi.ClientID, raw json.RawMessage, automaticCfg AutomaticRegistrationConfig) (storage.RegisteredClientConfig, jwksSource, error) {
	var m relyingPartyMetadata
	if err := json.Unmarshal(raw, &m); err != nil {
		return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("parse %s metadata: %w", relyingPartyEntityType, err)
	}
	if len(m.RedirectURIs) == 0 {
		return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("%s metadata has no redirect_uris", relyingPartyEntityType)
	}
	if (len(m.JWKS) > 0) == (m.JWKSURI != "") {
		return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("%s metadata must declare exactly one of jwks or jwks_uri", relyingPartyEntityType)
	}

	authMethod, err := storage.ParseClientAuthMethod(m.TokenEndpointAuthMethod)
	if err != nil {
		return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("token_endpoint_auth_method: %w", err)
	}
	if authMethod != storage.ClientAuthMethodPrivateKeyJWT {
		return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("token_endpoint_auth_method %q is not yet supported by automatic registration (only private_key_jwt)", m.TokenEndpointAuthMethod)
	}
	assertionAlg, err := fapi.ParseSignatureAlgorithm(m.TokenEndpointAuthSigningAlg)
	if err != nil {
		return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("token_endpoint_auth_signing_alg: %w", err)
	}

	var requestObjectAlg fapi.SignatureAlgorithm
	if m.RequestObjectSigningAlg != "" {
		requestObjectAlg, err = fapi.ParseSignatureAlgorithm(m.RequestObjectSigningAlg)
		if err != nil {
			return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("request_object_signing_alg: %w", err)
		}
	}

	senderConstrain := storage.SenderConstrainDPoP
	if m.TLSClientCertificateBoundAccessTokens {
		senderConstrain = storage.SenderConstrainMTLS
	}

	redirectURIs := make([]fapi.RegisteredRedirectURI, len(m.RedirectURIs))
	for i, u := range m.RedirectURIs {
		redirectURIs[i] = fapi.RegisteredRedirectURI(u)
	}

	cfg := storage.RegisteredClientConfig{
		ID: id, RedirectURIs: redirectURIs,
		ClientAuthMethod: authMethod, ClientAssertionAlgorithm: assertionAlg,
		RequestObjectAlgorithm:          requestObjectAlg,
		SenderConstrain:                 senderConstrain,
		AllowedScopes:                   automaticCfg.AllowedScopes,
		AutomaticFederationRegistration: true,
		AllowsClientCredentialsGrant:    automaticCfg.AllowsClientCredentialsGrant,
	}

	if automaticCfg.AllowsCIBA && m.BackchannelAuthenticationRequestSigningAlg != "" {
		if cfg.BackchannelAuthenticationRequestAlgorithm, err = fapi.ParseSignatureAlgorithm(m.BackchannelAuthenticationRequestSigningAlg); err != nil {
			return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("backchannel_authentication_request_signing_alg: %w", err)
		}
		deliveryMode := m.BackchannelTokenDeliveryMode
		if deliveryMode == "" {
			deliveryMode = "poll"
		}
		if cfg.BackchannelTokenDeliveryMode, err = storage.ParseBackchannelTokenDeliveryMode(deliveryMode); err != nil {
			return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("backchannel_token_delivery_mode: %w", err)
		}
		if m.BackchannelClientNotificationEndpoint != "" {
			if cfg.BackchannelClientNotificationEndpoint, err = fapi.ParseEndpointURL(m.BackchannelClientNotificationEndpoint); err != nil {
				return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("backchannel_client_notification_endpoint: %w", err)
			}
		}
	}

	idTokenAlgSet := m.IDTokenEncryptedResponseAlg != ""
	idTokenEncSet := m.IDTokenEncryptedResponseEnc != ""
	if idTokenAlgSet != idTokenEncSet {
		return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("id_token_encrypted_response_alg and id_token_encrypted_response_enc must both be set, or neither")
	}
	if idTokenAlgSet {
		if cfg.IDTokenEncryptionKeyManagement, err = fapi.ParseKeyManagementAlgorithm(m.IDTokenEncryptedResponseAlg); err != nil {
			return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("id_token_encrypted_response_alg: %w", err)
		}
		if cfg.IDTokenEncryptionContentEncryption, err = fapi.ParseContentEncryptionAlgorithm(m.IDTokenEncryptedResponseEnc); err != nil {
			return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("id_token_encrypted_response_enc: %w", err)
		}
	}

	userInfoAlgSet := m.UserinfoEncryptedResponseAlg != ""
	userInfoEncSet := m.UserinfoEncryptedResponseEnc != ""
	if userInfoAlgSet != userInfoEncSet {
		return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("userinfo_encrypted_response_alg and userinfo_encrypted_response_enc must both be set, or neither")
	}
	if userInfoAlgSet {
		if cfg.UserInfoEncryptionKeyManagement, err = fapi.ParseKeyManagementAlgorithm(m.UserinfoEncryptedResponseAlg); err != nil {
			return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("userinfo_encrypted_response_alg: %w", err)
		}
		if cfg.UserInfoEncryptionContentEncryption, err = fapi.ParseContentEncryptionAlgorithm(m.UserinfoEncryptedResponseEnc); err != nil {
			return storage.RegisteredClientConfig{}, jwksSource{}, fmt.Errorf("userinfo_encrypted_response_enc: %w", err)
		}
	}

	return cfg, jwksSource{inline: m.JWKS, uri: m.JWKSURI}, nil
}
