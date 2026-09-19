package federation

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/mtls"
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
// something an RP's own self-published metadata can grant itself. Every
// storage.ClientAuthMethod this package's own storage type supports is
// readable from an RP's own token_endpoint_auth_method metadata,
// including every RFC 8705 mTLS method: ClientAuthMethodSelfSignedTLSClientAuth
// reads the RP's own certificate from the "x5c" member of a jwks/jwks_uri
// entry (RFC 8705 §2.2) and computes its expected thumbprint from it;
// ClientAuthMethodTLSClientAuth and its four SAN-typed siblings read
// their own plain-string metadata parameter directly (RFC 8705 §2.1.2:
// tls_client_auth_subject_dn/tls_client_auth_san_dns/_san_uri/_san_ip/
// _san_email) — see registeredClientConfigFromMetadata. PAR/JAR-level
// enforcement of OpenID Federation 1.0 §12.1.1's own
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
	clientCfg, jwks, err := a.registeredClientConfigFromMetadata(ctx, id, raw)
	if err != nil {
		return cachedClient{}, fmt.Errorf("federation: %q: %w", id, err)
	}
	client, err := storage.NewRegisteredClient(clientCfg)
	if err != nil {
		return cachedClient{}, fmt.Errorf("federation: %q: %w", id, err)
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

// Capabilities implements keys.KeySourceAssurance by forwarding
// Underlying's own declaration, if it makes one. This type's own
// federation-derived resolution path is always hardened (it goes
// through AutomaticClientRepository's Resolver, which requires a real
// fapihttp.Client), but that alone doesn't make the whole type safe to
// declare LiveFetchHardened unconditionally: Underlying is tried first
// (see this type's own doc comment), so an Underlying that isn't itself
// hardened — or doesn't declare — must not be silently papered over by
// this type's other, safe path.
func (s *AutomaticClientKeySource) Capabilities() keys.KeySourceCapabilities {
	if asserter, ok := s.underlying.(keys.KeySourceAssurance); ok {
		return asserter.Capabilities()
	}
	return keys.KeySourceCapabilities{}
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

	// TLSClientAuthSubjectDN/TLSClientAuthSANDNS/TLSClientAuthSANURI/
	// TLSClientAuthSANIP/TLSClientAuthSANEmail are RFC 8705 §2.1.2's own
	// PKI mutual-TLS client metadata parameters. Read only when
	// TokenEndpointAuthMethod is tls_client_auth or the matching
	// SAN-typed sibling — §2.1: "A client using the tls_client_auth
	// authentication method MUST use exactly one of the below metadata
	// parameters" — registeredClientConfigFromMetadata enforces exactly
	// which one for the declared method.
	TLSClientAuthSubjectDN string `json:"tls_client_auth_subject_dn"`
	TLSClientAuthSANDNS    string `json:"tls_client_auth_san_dns"`
	TLSClientAuthSANURI    string `json:"tls_client_auth_san_uri"`
	TLSClientAuthSANIP     string `json:"tls_client_auth_san_ip"`
	TLSClientAuthSANEmail  string `json:"tls_client_auth_san_email"`
}

// registeredClientConfigFromMetadata parses raw (an openid_relying_party
// Resolved Metadata object) and builds the storage.RegisteredClientConfig
// it describes, returning the client's actual, resolved jwks bytes
// separately (needed by AutomaticClientKeySource, not stored on
// storage.RegisteredClient itself). jwks_uri, when declared instead of
// an inline jwks, is fetched here — eagerly, before returning — rather
// than left for the caller to resolve afterward the way an earlier
// version of this function did: ClientAuthMethodSelfSignedTLSClientAuth
// needs the jwks content itself (specifically its own "x5c" member) to
// compute ExpectedCertificateThumbprint before storage.NewRegisteredClient
// can even validate the resulting config, so there is no later point at
// which deferring the fetch would still work for every auth method.
//
// a.cfg supplies the operator-level capability grants (AllowedScopes,
// AllowsClientCredentialsGrant, AllowsCIBA) that must never be inferred
// from raw itself — see AutomaticRegistrationConfig's own doc comments
// for why.
func (a *AutomaticClientRepository) registeredClientConfigFromMetadata(ctx context.Context, id fapi.ClientID, raw json.RawMessage) (storage.RegisteredClientConfig, json.RawMessage, error) {
	var m relyingPartyMetadata
	if err := json.Unmarshal(raw, &m); err != nil {
		return storage.RegisteredClientConfig{}, nil, fmt.Errorf("parse %s metadata: %w", relyingPartyEntityType, err)
	}
	if len(m.RedirectURIs) == 0 {
		return storage.RegisteredClientConfig{}, nil, fmt.Errorf("%s metadata has no redirect_uris", relyingPartyEntityType)
	}
	if (len(m.JWKS) > 0) == (m.JWKSURI != "") {
		return storage.RegisteredClientConfig{}, nil, fmt.Errorf("%s metadata must declare exactly one of jwks or jwks_uri", relyingPartyEntityType)
	}

	authMethod, err := storage.ParseClientAuthMethod(m.TokenEndpointAuthMethod)
	if err != nil {
		return storage.RegisteredClientConfig{}, nil, fmt.Errorf("token_endpoint_auth_method: %w", err)
	}

	jwks := m.JWKS
	if m.JWKSURI != "" {
		if jwks, err = a.fetchJWKS(ctx, m.JWKSURI); err != nil {
			return storage.RegisteredClientConfig{}, nil, fmt.Errorf("jwks_uri: %w", err)
		}
	}

	var requestObjectAlg fapi.SignatureAlgorithm
	if m.RequestObjectSigningAlg != "" {
		requestObjectAlg, err = fapi.ParseSignatureAlgorithm(m.RequestObjectSigningAlg)
		if err != nil {
			return storage.RegisteredClientConfig{}, nil, fmt.Errorf("request_object_signing_alg: %w", err)
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
		ClientAuthMethod:                authMethod,
		RequestObjectAlgorithm:          requestObjectAlg,
		SenderConstrain:                 senderConstrain,
		AllowedScopes:                   a.cfg.AllowedScopes,
		AutomaticFederationRegistration: true,
		AllowsClientCredentialsGrant:    a.cfg.AllowsClientCredentialsGrant,
	}

	// storage.NewRegisteredClient's own switch on ClientAuthMethod
	// requires exactly one corresponding field per method (see its own
	// doc comment) — mirrored in applyClientAuthMethodFields, reading
	// each from wherever RFC 8705 actually places it: token_endpoint_auth_signing_alg
	// for private_key_jwt, the client's own published certificate (via
	// jwks/jwks_uri's "x5c") for self_signed_tls_client_auth, and a
	// plain metadata string for tls_client_auth and its four SAN-typed
	// siblings.
	if err := applyClientAuthMethodFields(&cfg, authMethod, m, jwks); err != nil {
		return storage.RegisteredClientConfig{}, nil, err
	}

	if err := a.applyBackchannelAuthenticationFields(&cfg, m); err != nil {
		return storage.RegisteredClientConfig{}, nil, err
	}

	cfg.IDTokenEncryptionKeyManagement, cfg.IDTokenEncryptionContentEncryption, err = parseEncryptionAlgorithmPair(
		m.IDTokenEncryptedResponseAlg, m.IDTokenEncryptedResponseEnc,
		"id_token_encrypted_response_alg", "id_token_encrypted_response_enc")
	if err != nil {
		return storage.RegisteredClientConfig{}, nil, err
	}

	cfg.UserInfoEncryptionKeyManagement, cfg.UserInfoEncryptionContentEncryption, err = parseEncryptionAlgorithmPair(
		m.UserinfoEncryptedResponseAlg, m.UserinfoEncryptedResponseEnc,
		"userinfo_encrypted_response_alg", "userinfo_encrypted_response_enc")
	if err != nil {
		return storage.RegisteredClientConfig{}, nil, err
	}

	return cfg, jwks, nil
}

// applyClientAuthMethodFields sets cfg's authMethod-specific field from
// m/jwks — split out of registeredClientConfigFromMetadata purely to
// keep that method's own cognitive complexity manageable.
func applyClientAuthMethodFields(cfg *storage.RegisteredClientConfig, authMethod storage.ClientAuthMethod, m relyingPartyMetadata, jwks json.RawMessage) error {
	switch authMethod {
	case storage.ClientAuthMethodPrivateKeyJWT:
		alg, err := fapi.ParseSignatureAlgorithm(m.TokenEndpointAuthSigningAlg)
		if err != nil {
			return fmt.Errorf("token_endpoint_auth_signing_alg: %w", err)
		}
		cfg.ClientAssertionAlgorithm = alg
	case storage.ClientAuthMethodSelfSignedTLSClientAuth:
		thumbprint, err := certificateThumbprintFromJWKS(jwks)
		if err != nil {
			return fmt.Errorf("self_signed_tls_client_auth: %w", err)
		}
		cfg.ExpectedCertificateThumbprint = thumbprint
	case storage.ClientAuthMethodTLSClientAuth:
		if m.TLSClientAuthSubjectDN == "" {
			return fmt.Errorf("tls_client_auth_subject_dn is required for tls_client_auth")
		}
		cfg.ExpectedSubjectDN = m.TLSClientAuthSubjectDN
	case storage.ClientAuthMethodTLSClientAuthSANDNS:
		if m.TLSClientAuthSANDNS == "" {
			return fmt.Errorf("tls_client_auth_san_dns is required for tls_client_auth_san_dns")
		}
		cfg.ExpectedSANDNS = m.TLSClientAuthSANDNS
	case storage.ClientAuthMethodTLSClientAuthSANURI:
		if m.TLSClientAuthSANURI == "" {
			return fmt.Errorf("tls_client_auth_san_uri is required for tls_client_auth_san_uri")
		}
		cfg.ExpectedSANURI = m.TLSClientAuthSANURI
	case storage.ClientAuthMethodTLSClientAuthSANIP:
		if m.TLSClientAuthSANIP == "" {
			return fmt.Errorf("tls_client_auth_san_ip is required for tls_client_auth_san_ip")
		}
		cfg.ExpectedSANIP = m.TLSClientAuthSANIP
	case storage.ClientAuthMethodTLSClientAuthSANEmail:
		if m.TLSClientAuthSANEmail == "" {
			return fmt.Errorf("tls_client_auth_san_email is required for tls_client_auth_san_email")
		}
		cfg.ExpectedSANEmail = m.TLSClientAuthSANEmail
	default:
		// Unreachable in practice — storage.ParseClientAuthMethod's own
		// closed set already rejected anything else above — kept for the
		// same defensive-completeness reason a switch over a closed enum
		// gets one elsewhere in this module.
		return fmt.Errorf("token_endpoint_auth_method %q is not supported", m.TokenEndpointAuthMethod)
	}
	return nil
}

// applyBackchannelAuthenticationFields sets cfg's CIBA fields from m
// when this repository allows CIBA and m actually advertises it — a
// no-op otherwise. Split out of registeredClientConfigFromMetadata for
// the same reason applyClientAuthMethodFields is.
func (a *AutomaticClientRepository) applyBackchannelAuthenticationFields(cfg *storage.RegisteredClientConfig, m relyingPartyMetadata) error {
	if !a.cfg.AllowsCIBA || m.BackchannelAuthenticationRequestSigningAlg == "" {
		return nil
	}
	alg, err := fapi.ParseSignatureAlgorithm(m.BackchannelAuthenticationRequestSigningAlg)
	if err != nil {
		return fmt.Errorf("backchannel_authentication_request_signing_alg: %w", err)
	}
	cfg.BackchannelAuthenticationRequestAlgorithm = alg

	deliveryMode := m.BackchannelTokenDeliveryMode
	if deliveryMode == "" {
		deliveryMode = "poll"
	}
	mode, err := storage.ParseBackchannelTokenDeliveryMode(deliveryMode)
	if err != nil {
		return fmt.Errorf("backchannel_token_delivery_mode: %w", err)
	}
	cfg.BackchannelTokenDeliveryMode = mode

	if m.BackchannelClientNotificationEndpoint != "" {
		endpoint, err := fapi.ParseEndpointURL(m.BackchannelClientNotificationEndpoint)
		if err != nil {
			return fmt.Errorf("backchannel_client_notification_endpoint: %w", err)
		}
		cfg.BackchannelClientNotificationEndpoint = endpoint
	}
	return nil
}

// parseEncryptionAlgorithmPair parses a key-management/content-encryption
// metadata pair that must be set together or not at all — algLabel/
// encLabel name the two metadata fields, for error messages. Shared by
// registeredClientConfigFromMetadata's id_token and userinfo encryption
// handling, which are otherwise identical.
func parseEncryptionAlgorithmPair(algValue, encValue, algLabel, encLabel string) (fapi.KeyManagementAlgorithm, fapi.ContentEncryptionAlgorithm, error) {
	algSet := algValue != ""
	encSet := encValue != ""
	if algSet != encSet {
		return 0, 0, fmt.Errorf("%s and %s must both be set, or neither", algLabel, encLabel)
	}
	if !algSet {
		return 0, 0, nil
	}
	alg, err := fapi.ParseKeyManagementAlgorithm(algValue)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", algLabel, err)
	}
	enc, err := fapi.ParseContentEncryptionAlgorithm(encValue)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", encLabel, err)
	}
	return alg, enc, nil
}

// certificateThumbprintFromJWKS extracts and computes the RFC 8705 §3.1
// x5t#S256 thumbprint of the first "x5c"-bearing entry found across
// jwks' own keys (RFC 8705 §2.2: "the existing jwks_uri or jwks
// metadata parameters... are used to convey the client's certificates
// via JWK... A certificate is represented with the x5c parameter").
// AutomaticClientRepository only ever registers one mTLS-authenticating
// identity per client, so the first usable entry is sufficient — unlike
// resource-server-side signature verification, there's no second
// candidate to try if this one doesn't work; a client publishing more
// than one is expected to put its authenticating certificate first.
func certificateThumbprintFromJWKS(jwks json.RawMessage) (string, error) {
	candidates, err := jose.ParseJWKSet(jwks)
	if err != nil {
		return "", fmt.Errorf("parse jwks: %w", err)
	}
	for _, c := range candidates {
		for _, der := range c.Certificates {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				continue
			}
			return mtls.Thumbprint(cert), nil
		}
	}
	return "", fmt.Errorf("jwks has no usable x5c certificate")
}
