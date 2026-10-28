package federation

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/canonical"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/internal/resourceindicator"
	"github.com/idfoundry/fapigo/internal/strictjson"
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

	// AuthorizationDetailsTypes are the Rich Authorization Request types
	// every automatically-registered client may request
	// (storage.RegisteredClientConfig.AuthorizationDetailsTypes) — for
	// the same reason as AllowedScopes, never an RP's own
	// self-published authorization_details_types. Empty means none.
	AuthorizationDetailsTypes []string

	// AllowedResources confines every automatically-registered client to
	// these RFC 8707 resource indicators
	// (storage.RegisteredClientConfig.AllowedResources) — for the same
	// reason as AllowedScopes, never anything an RP publishes about
	// itself: which resource servers a client may get tokens for is the
	// operator's decision. Each an absolute URI without a fragment, none
	// repeated. Empty means unconfined: an RP may name any resource the
	// server accepts, and one naming none gets tokens addressed to the
	// issuer. Set, a request naming none is for its single entry, or,
	// with several, invalid_target (see
	// storage.RegisteredClientConfig.AllowedResources).
	AllowedResources []string

	// MaxCacheAge bounds how long a resolved client's Trust Chain is
	// reused before it is resolved again — the actual cache lifetime
	// for a given client is min(MaxCacheAge, its own Trust Chain's
	// ResolvedEntity.ExpiresAt), never longer than the chain itself
	// remains valid. Required — must be positive. At most 4096
	// registrations are cached at once, and no one federation member
	// can fill that: the Relying Parties under any one immediate
	// superior share at most 512 places (that superior's oldest is
	// evicted for its newest), and those in any one branch of a Trust
	// Anchor (everything under one of its subordinates) at most 2048.
	// Relying Parties directly under a Trust Anchor count only against
	// the 4096. Past a branch's or the whole cache's limit, expired
	// registrations are dropped first; if none has expired a new
	// registration is used but not cached (so it's resolved again on its
	// next use) rather than evicting another superior's still-valid one.
	MaxCacheAge time.Duration

	// FailureCacheAge is how long a failed automatic registration is
	// remembered for the same client_id: until it lapses, another
	// request naming that client_id gets the same error without a new
	// Trust Chain resolution, so a client_id whose resolution fails
	// can't make every request repeat the outbound fetches. Zero means
	// DefaultFailureCacheAge; negative is invalid. Keep it short: a
	// failure can be transient (OpenID Federation 1.0 §10.5), and a
	// client whose Trust Chain starts resolving waits up to this long.
	// At most 4096 failures are remembered at once.
	FailureCacheAge time.Duration

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

	// AllowedClientAuthMethods restricts which client authentication
	// methods an automatically-registered client may register. An RP
	// whose token_endpoint_auth_method is outside this list fails to
	// resolve at all, exactly like one with malformed metadata; methods
	// outside it that the RP only lists in
	// token_endpoint_auth_methods_supported are skipped, and the RP fails
	// only if none of its listed methods remains. Empty (the default)
	// permits every storage.ClientAuthMethod this package can read from
	// metadata — each is a FAPI 2.0-permitted,
	// sender-proving method, so the RP choosing one is a mechanism
	// detail, not a capability grant like AllowsCIBA. Set it when an
	// operator wants federation RPs held to a narrower set than its
	// statically registered clients (e.g. only
	// storage.ClientAuthMethodPrivateKeyJWT, even though some static
	// clients use mTLS). Every entry must be a valid ClientAuthMethod
	// other than storage.ClientAuthMethodAttestation, which binds a
	// client to an attester only an operator can name, so automatic
	// registration never registers it.
	// server.New narrows an empty list to leave out tls_client_auth and
	// its SAN* siblings unless its ClientCertificateTrust verifies
	// certificate chains (see server.AutomaticRegistrationConfig).
	AllowedClientAuthMethods []storage.ClientAuthMethod

	// ClientAssertionAlgorithms is what an automatically registered
	// client using private_key_jwt may sign its assertions with when its
	// metadata names no token_endpoint_auth_signing_alg (or
	// token_endpoint_auth_signing_alg_values_supported) — OpenID Connect
	// Dynamic Client Registration 1.0: "The default, if omitted, is that
	// any algorithm supported by the OP and the RP MAY be used". Typically
	// the server's own allowed client assertion algorithms (server.New
	// sets it so). Empty means an RP must name its algorithm to register
	// for private_key_jwt. A superior's metadata policy restricting
	// token_endpoint_auth_signing_alg (one_of or value) restricts these
	// defaults too, as it does token_endpoint_auth_signing_alg_values_supported.
	ClientAssertionAlgorithms []fapi.SignatureAlgorithm

	// IDTokenSigningAlgorithm is the one algorithm the server signs ID
	// tokens with (server.New sets it from Config.Algorithms.IDToken). An
	// RP whose metadata names an id_token_signed_response_alg other than
	// it isn't registered: OpenID Connect Core §10.1 has the ID token
	// signed with the algorithm the RP registered, and the RP would
	// otherwise get, and refuse, tokens signed with another. Zero, for a
	// server issuing no ID tokens, leaves the parameter unchecked.
	IDTokenSigningAlgorithm fapi.SignatureAlgorithm

	// UserInfoSigningAlgorithm is the one algorithm the server signs
	// UserInfo responses with (server.New sets it from
	// Config.Algorithms.UserInfo), zero when it signs none. An RP whose
	// metadata names a userinfo_signed_response_alg other than it, or
	// any when it is zero, isn't registered, for the reason
	// IDTokenSigningAlgorithm gives.
	UserInfoSigningAlgorithm fapi.SignatureAlgorithm

	// SubjectTypes is the kinds of sub this OP gives an automatically
	// registered client's end users (OpenID Connect Core §8): the
	// subject_types_supported it advertises. A Relying Party whose
	// metadata asks for a subject_type outside it fails to register, as
	// OpenID Connect Dynamic Client Registration 1.0 has an OP refuse
	// metadata it can't honour, rather than being given another kind of
	// sub than it asked for. Empty means public only. server.New sets
	// it from server.Config.Subjects.
	SubjectTypes []fapi.SubjectType

	// DefaultSubjectType is the subject type a Relying Party gets when
	// its metadata names none, one of SubjectTypes. Zero means public.
	// server.New sets it from server.Config.Subjects.
	DefaultSubjectType fapi.SubjectType

	// OnResolutionFailure, if set, is called with the reason whenever a
	// client_id that is a well-formed Entity Identifier, and not
	// statically registered, fails automatic registration: its Trust
	// Chain doesn't resolve to a configured Trust Anchor, it has no
	// openid_relying_party metadata, or that metadata can't be used
	// (e.g. no client authentication method this package implements, or
	// a token_endpoint_auth_method outside AllowedClientAuthMethods).
	// The client itself only ever sees a generic invalid-client error,
	// so this is how an operator finds out why.
	//
	// err can carry text from the RP's own statements and metadata: log
	// it, never return it to the client. It is called synchronously, on
	// the request that triggered the resolution — concurrent requests
	// for the same client_id share that one call — so it must not
	// block. A failure is remembered for FailureCacheAge, so an RP that
	// keeps retrying is reported once per resolution attempted, not once
	// per request; the requests answered from that memory get the
	// failure's message only, cut to its first KiB. Optional.
	OnResolutionFailure func(ctx context.Context, clientID fapi.ClientID, err error)
}

// cachedClient is one Relying Party's resolved registration, cached
// until whichever of AutomaticRegistrationConfig.MaxCacheAge or the
// Trust Chain's own ResolvedEntity.ExpiresAt comes first.
type cachedClient struct {
	client    storage.RegisteredClient
	jwks      json.RawMessage
	expiresAt time.Time
	// superior and branch are where the Relying Party sits in its Trust
	// Chain, which bounds how much of the cache it and its siblings may
	// hold (see registrationCache and chainPosition).
	superior, branch string
}

// DefaultFailureCacheAge is AutomaticRegistrationConfig.FailureCacheAge
// when it is zero. Failure caching can be shortened but not turned off:
// there is no FailureCacheAge value that disables it, since without it
// every request naming a failing client_id repeats the whole Trust Chain
// resolution.
const DefaultFailureCacheAge = 10 * time.Second

// maxFailedResolutions bounds how many failed registrations
// AutomaticClientRepository remembers at once: client_ids cost an
// attacker nothing, so the cache must not grow with them. Once full,
// expired entries are dropped, and if none has expired a new failure
// simply isn't remembered — the same as before failures were cached.
const maxFailedResolutions = 4096

// maxRememberedFailureBytes bounds the message a remembered failure
// keeps. A failed Trust Chain resolution's error names every branch tried
// and echoes the RP's and its superiors' own claims, so its length is
// partly the attacker's choice; the failure cache keeps at most this much
// of it per client_id.
const maxRememberedFailureBytes = 1024

// failedResolution is one remembered registration failure, returned for
// its client_id until expiresAt.
type failedResolution struct {
	err       error
	expiresAt time.Time
}

// rememberedFailure is a failed registration as the failure cache keeps
// it: only its message, cut to maxRememberedFailureBytes and copied, so
// it holds neither the original error's chain nor the rest of its text.
// The full error goes to AutomaticRegistrationConfig.OnResolutionFailure
// and to the request whose resolution failed.
type rememberedFailure struct{ msg string }

func (e *rememberedFailure) Error() string { return e.msg }

// newRememberedFailure returns err's message as a rememberedFailure.
func newRememberedFailure(err error) error {
	msg := err.Error()
	if len(msg) <= maxRememberedFailureBytes {
		return &rememberedFailure{msg: strings.Clone(msg)}
	}
	cut := maxRememberedFailureBytes
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return &rememberedFailure{msg: strings.Clone(msg[:cut]) + " ... (truncated)"}
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
// a well-formed https Entity Identifier (ValidEntityID). An Underlying
// failure wrapping storage.ErrStoreUnavailable is returned as it is;
// any other is read as "not statically registered". The same split
// decides where AutomaticClientKeySource takes a client's keys from, so
// a statically registered client is authenticated with its static keys
// only, never with ones its federation metadata publishes.
//
// A client_id is resolved before its client is authenticated — that is
// how automatic registration finds the keys to authenticate it with —
// so any caller can name one, and Resolver.Resolve then fetches the URLs
// that Entity Identifier's statements name, before any of them is
// trusted (see Resolver.Resolve and Dependencies.HTTP). The fetcher
// bounds which hosts that can reach; a host listed in its
// fapihttp.Config.AllowedPrivateHosts is reachable by unauthenticated
// callers this way.
//
// The client_credentials grant and CIBA are each gated by their own
// config-level switch (AutomaticRegistrationConfig.AllowsClientCredentialsGrant/
// AllowsCIBA) — off by default, since whether an automatically-resolved
// RP may use either is a capability grant an operator makes, never
// something an RP's own self-published metadata can grant itself. Every
// storage.ClientAuthMethod this package's own storage type supports is
// readable from an RP's own token_endpoint_auth_method and/or
// token_endpoint_auth_methods_supported metadata — every declared
// method the RP's metadata supports is registered, and the server
// accepts whichever it uses (see declaredClientAuthMethods) —
// including every RFC 8705 mTLS method: ClientAuthMethodSelfSignedTLSClientAuth
// reads the RP's own certificates from the "x5c" members of its
// jwks/jwks_uri entries (RFC 8705 §2.2) and accepts the certificate of
// any of them; ClientAuthMethodTLSClientAuth and its four SAN-typed
// siblings read their own plain-string metadata parameter directly (RFC
// 8705 §2.1.2: tls_client_auth_subject_dn/tls_client_auth_san_dns/
// _san_uri/_san_ip/_san_email) — see registeredClientConfigFromMetadata
// — unless AutomaticRegistrationConfig.AllowedClientAuthMethods narrows
// that set. A CA-issued certificate must also carry one of the keys of
// the RP's JWK Set (storage.RegisteredClientConfig.CertificateKeyThumbprints):
// OpenID Federation 1.0 §12.1.1.2 requires an RP to prove possession of
// a key in its RP JWK Set, and a matching subject or SAN under a trusted
// CA proves possession only of whatever key that CA certified. The PKI
// requirement itself stays: the certificate must still chain to
// Dependencies.ClientCertificateTrust. PAR/JAR-level
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
	cache *registrationCache
	// failures holds recent registration failures (see
	// AutomaticRegistrationConfig.FailureCacheAge), at most
	// maxFailedResolutions of them.
	failures map[fapi.ClientID]failedResolution
	// inflight holds the resolution currently running for each
	// client_id, so concurrent requests naming the same unknown
	// client_id share one Trust Chain resolution rather than each
	// starting their own.
	inflight map[fapi.ClientID]*inflightResolution
}

// inflightResolution is one in-progress resolution that concurrent
// callers for the same client_id wait on; done is closed once entry and
// err are set.
type inflightResolution struct {
	done  chan struct{}
	entry cachedClient
	err   error
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
// Dependencies.HTTP. In production both must be fapihttp.New over
// fapihttp.NewClient's client (HardenedForProduction): built by hand,
// this repository can't check, while server.New checks the ones it
// builds from server.Dependencies.FederationHTTP.
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
	if cfg.FailureCacheAge < 0 {
		return nil, fmt.Errorf("federation: config: failure_cache_age must not be negative")
	}
	if cfg.FailureCacheAge == 0 {
		cfg.FailureCacheAge = DefaultFailureCacheAge
	}
	for _, method := range cfg.AllowedClientAuthMethods {
		if !method.IsValid() {
			return nil, fmt.Errorf("federation: config: allowed_client_auth_methods: invalid client auth method %v", method)
		}
		if method == storage.ClientAuthMethodAttestation {
			// A client authenticated by attestation is bound to a trusted
			// Attester (RegisteredClientConfig.ExpectedAttesterIssuer), a
			// capability grant no RP metadata can make, so no RP could
			// ever register with it.
			return nil, fmt.Errorf("federation: config: allowed_client_auth_methods: %v can't be registered automatically: its attester is an operator's grant, not RP metadata", method)
		}
	}
	for _, alg := range cfg.ClientAssertionAlgorithms {
		if !alg.IsValid() {
			return nil, fmt.Errorf("federation: config: client_assertion_algorithms: invalid algorithm %v", alg)
		}
	}
	if err := validateSubjectTypes(cfg.SubjectTypes, cfg.DefaultSubjectType); err != nil {
		return nil, err
	}
	if err := validateAllowedResources(cfg.AllowedResources); err != nil {
		return nil, err
	}
	cfg.AllowedResources = slices.Clone(cfg.AllowedResources)
	if clock == nil {
		return nil, fmt.Errorf("federation: clock is required")
	}
	return &AutomaticClientRepository{
		underlying: underlying, resolver: resolver, fetcher: fetcher, cfg: cfg, clock: clock,
		cache:    newRegistrationCache(),
		failures: make(map[fapi.ClientID]failedResolution),
		inflight: make(map[fapi.ClientID]*inflightResolution),
	}, nil
}

// validateAllowedResources checks AutomaticRegistrationConfig.AllowedResources:
// each a resource indicator RFC 8707 §2 allows, none repeated.
func validateAllowedResources(resources []string) error {
	for i, r := range resources {
		if err := resourceindicator.Check(r); err != nil {
			return fmt.Errorf("federation: config: allowed_resources[%d]: %w", i, err)
		}
		if slices.Contains(resources[:i], r) {
			return fmt.Errorf("federation: config: allowed_resources[%d]: %q is repeated", i, r)
		}
	}
	return nil
}

// ResolveClient implements storage.ClientRepository.
func (a *AutomaticClientRepository) ResolveClient(ctx context.Context, id fapi.ClientID) (storage.RegisteredClient, error) {
	client, err := a.underlying.ResolveClient(ctx, id)
	if err == nil {
		return client, nil
	}
	// A store that couldn't answer says nothing about whether id is
	// registered there, so it isn't treated as "not registered": falling
	// back to federation would turn an outage into an unknown client.
	if errors.Is(err, storage.ErrStoreUnavailable) {
		return storage.RegisteredClient{}, err
	}
	entry, err := a.resolve(ctx, id)
	if err != nil {
		return storage.RegisteredClient{}, err
	}
	return entry.client, nil
}

// staticallyRegistered reports whether Underlying resolves id — the
// same test ResolveClient uses to decide that a client is statically
// registered rather than resolved through federation. An unavailable
// store is an error, not a "no".
func (a *AutomaticClientRepository) staticallyRegistered(ctx context.Context, id fapi.ClientID) (bool, error) {
	_, err := a.underlying.ResolveClient(ctx, id)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, storage.ErrStoreUnavailable) {
		return false, err
	}
	return false, nil
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
	if entry, ok := a.cache.get(id, now); ok {
		a.mu.Unlock()
		return entry, nil
	}
	if failed, ok := a.failures[id]; ok && now.Before(failed.expiresAt) {
		a.mu.Unlock()
		return cachedClient{}, failed.err
	}
	call, ok := a.inflight[id]
	if !ok {
		call = &inflightResolution{done: make(chan struct{})}
		a.inflight[id] = call
		// The resolution is shared by every caller for id, so it runs
		// detached from this one's cancellation: one caller giving up
		// (or an attacker cancelling its own request on purpose) must
		// not fail the others. It keeps ctx's values, and the fetcher's
		// own limits bound how long it can take.
		go func() {
			call.entry, call.err = a.resolveUncached(context.WithoutCancel(ctx), id)
			a.mu.Lock()
			delete(a.inflight, id)
			a.mu.Unlock()
			close(call.done)
		}()
	}
	a.mu.Unlock()
	select {
	case <-call.done:
		return call.entry, call.err
	case <-ctx.Done():
		return cachedClient{}, ctx.Err()
	}
}

// resolveUncached resolves id's Trust Chain and builds its registration,
// caching a success and reporting a failure to
// AutomaticRegistrationConfig.OnResolutionFailure. resolve runs at most
// one at a time per client_id.
func (a *AutomaticClientRepository) resolveUncached(ctx context.Context, id fapi.ClientID) (cachedClient, error) {
	if err := ValidEntityID(string(id)); err != nil {
		// Not a federation client_id at all — an ordinary unknown
		// client, so nothing for OnResolutionFailure to report.
		return cachedClient{}, fmt.Errorf("federation: %q is not a registered client and not a valid federation entity ID: %w", id, err)
	}
	entry, err := a.register(ctx, id)
	if err != nil {
		if a.cfg.OnResolutionFailure != nil {
			a.cfg.OnResolutionFailure(ctx, id, err)
		}
		// A request cancelled or timed out by its own caller says nothing
		// about the client_id, so only a resolution that ran its course
		// is remembered — from when it failed, not when it started, so
		// a resolution slower than FailureCacheAge (an RP or superior
		// answering slowly is the RP's own choice) is still remembered.
		if ctx.Err() == nil {
			a.rememberFailure(id, err, a.clock.Now())
		}
		return cachedClient{}, err
	}
	a.mu.Lock()
	a.cacheRegistration(id, entry, a.clock.Now())
	delete(a.failures, id)
	a.mu.Unlock()
	return entry, nil
}

// cacheRegistration caches entry as id's registration, within the
// limits registrationCache's doc comment sets out. a.mu must be held.
func (a *AutomaticClientRepository) cacheRegistration(id fapi.ClientID, entry cachedClient, now time.Time) {
	a.cache.put(id, entry, now)
}

// rememberFailure records err as id's registration failure until
// FailureCacheAge after now, within maxFailedResolutions, keeping only
// its bounded message (see rememberedFailure).
func (a *AutomaticClientRepository) rememberFailure(id fapi.ClientID, err error, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.failures[id]; !ok && len(a.failures) >= maxFailedResolutions {
		for k, f := range a.failures {
			if !now.Before(f.expiresAt) {
				delete(a.failures, k)
			}
		}
		if len(a.failures) >= maxFailedResolutions {
			return
		}
	}
	a.failures[id] = failedResolution{err: newRememberedFailure(err), expiresAt: now.Add(a.cfg.FailureCacheAge)}
}

// register resolves the Entity Identifier id's Trust Chain and builds
// its registration from the resolved openid_relying_party metadata,
// cached for MaxCacheAge from when the registration was built.
func (a *AutomaticClientRepository) register(ctx context.Context, id fapi.ClientID) (cachedClient, error) {
	resolved, err := a.resolver.Resolve(ctx, string(id))
	if err != nil {
		return cachedClient{}, fmt.Errorf("federation: resolve client %q: %w", id, err)
	}
	raw, ok := resolved.Metadata[relyingPartyEntityType]
	if !ok {
		return cachedClient{}, fmt.Errorf("federation: %q has no %s metadata", id, relyingPartyEntityType)
	}
	limits, err := choiceLimitsFromPolicy(resolved.policy[relyingPartyEntityType])
	if err != nil {
		return cachedClient{}, fmt.Errorf("federation: %q: %w", id, err)
	}
	clientCfg, jwks, err := a.registeredClientConfigFromMetadata(ctx, id, raw, limits)
	if err != nil {
		return cachedClient{}, fmt.Errorf("federation: %q: %w", id, err)
	}
	client, err := storage.NewRegisteredClient(clientCfg)
	if err != nil {
		return cachedClient{}, fmt.Errorf("federation: %q: %w", id, err)
	}

	expiresAt := resolved.ExpiresAt
	if maxAge := a.clock.Now().Add(a.cfg.MaxCacheAge); maxAge.Before(expiresAt) {
		expiresAt = maxAge
	}
	superior, branch := chainPosition(resolved.Chain)
	return cachedClient{client: client, jwks: jwks, expiresAt: expiresAt, superior: superior, branch: branch}, nil
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
// Keys come from the same source as the registration they authenticate.
// A client that repo's own underlying client repository (the one passed
// to NewAutomaticClientRepository) resolves is statically registered,
// and its keys come from Underlying (this type's key source) alone:
// whatever Underlying returns, an error or an empty set included, is
// the answer, exactly as it would be without automatic registration.
// Only a client that repository doesn't have is resolved through its
// Trust Chain, and its keys then come from its openid_relying_party
// metadata alone. A
// statically registered client whose client_id is also an Entity
// Identifier resolving under one of the configured Trust Anchors is
// therefore never authenticated with a key its federation metadata
// publishes (which any superior in its Trust Chain can set): that would
// let a federation key act as the static client, with the static
// registration's privileges. An error from that repository other than
// "not registered" — storage.ErrStoreUnavailable — is returned too,
// rather than read as "not statically registered", for the same reason
// ResolveClient does. Each call asks the client repository first, so a
// key resolution costs one more lookup there than it would without
// automatic registration.
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
// declare LiveFetchHardened unconditionally: Underlying answers for every
// statically registered client (see this type's own doc comment), so an
// Underlying that isn't itself hardened — or doesn't declare — must not
// be silently papered over by this type's other, safe path.
func (s *AutomaticClientKeySource) Capabilities() keys.KeySourceCapabilities {
	if asserter, ok := s.underlying.(keys.KeySourceAssurance); ok {
		return asserter.Capabilities()
	}
	return keys.KeySourceCapabilities{}
}

// ResolveVerificationKeys implements keys.ClientKeySource.
func (s *AutomaticClientKeySource) ResolveVerificationKeys(ctx context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	static, err := s.repo.staticallyRegistered(ctx, req.ClientID)
	if err != nil {
		return keys.VerificationKeySet{}, err
	}
	if static {
		return s.underlying.ResolveVerificationKeys(ctx, req)
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
	RedirectURIs                []string `json:"redirect_uris"`
	TokenEndpointAuthMethod     string   `json:"token_endpoint_auth_method"`
	TokenEndpointAuthSigningAlg string   `json:"token_endpoint_auth_signing_alg"`

	// OpenID Connect RP Metadata Choices 1.0's lists of what the RP
	// supports; the singular values above, when present, must be in them.
	TokenEndpointAuthMethodsSupported          []string        `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string        `json:"token_endpoint_auth_signing_alg_values_supported"`
	RequestObjectSigningAlg                    string          `json:"request_object_signing_alg"`
	JWKS                                       json.RawMessage `json:"jwks"`
	JWKSURI                                    string          `json:"jwks_uri"`
	TLSClientCertificateBoundAccessTokens      bool            `json:"tls_client_certificate_bound_access_tokens"`
	IDTokenSignedResponseAlg                   string          `json:"id_token_signed_response_alg"`
	UserinfoSignedResponseAlg                  string          `json:"userinfo_signed_response_alg"`
	IDTokenEncryptedResponseAlg                *string         `json:"id_token_encrypted_response_alg"`
	IDTokenEncryptedResponseEnc                *string         `json:"id_token_encrypted_response_enc"`
	UserinfoEncryptedResponseAlg               *string         `json:"userinfo_encrypted_response_alg"`
	UserinfoEncryptedResponseEnc               *string         `json:"userinfo_encrypted_response_enc"`

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

	// SubjectType and SectorIdentifierURI are OpenID Connect Dynamic
	// Client Registration 1.0 §2's subject_type and
	// sector_identifier_uri; see subjectTypeFromMetadata.
	SubjectType         string `json:"subject_type"`
	SectorIdentifierURI string `json:"sector_identifier_uri"`

	ClientName string `json:"client_name"`
	LogoURI    string `json:"logo_uri"`
	PolicyURI  string `json:"policy_uri"`
	TOSURI     string `json:"tos_uri"`
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
// limits holds the choices taken from token_endpoint_auth_methods_supported
// and token_endpoint_auth_signing_alg_values_supported to what the Trust
// Chain's metadata policy permits for their singular parameters (see
// choiceLimits).
//
// a.cfg supplies the operator-level capability grants (AllowedScopes,
// AllowedResources, AllowsClientCredentialsGrant, AllowsCIBA) that must never be inferred
// from raw itself, plus the AllowedClientAuthMethods restriction raw's
// own token_endpoint_auth_method is checked against — see AutomaticRegistrationConfig's own doc comments
// for why.
func (a *AutomaticClientRepository) registeredClientConfigFromMetadata(ctx context.Context, id fapi.ClientID, raw json.RawMessage, limits choiceLimits) (storage.RegisteredClientConfig, json.RawMessage, error) {
	var m relyingPartyMetadata
	if err := strictjson.Unmarshal(raw, &m); err != nil {
		return storage.RegisteredClientConfig{}, nil, fmt.Errorf("parse %s metadata: %w", relyingPartyEntityType, err)
	}
	if err := refuseEmptyStrings(raw); err != nil {
		return storage.RegisteredClientConfig{}, nil, err
	}
	if len(m.RedirectURIs) == 0 {
		return storage.RegisteredClientConfig{}, nil, fmt.Errorf("%s metadata has no redirect_uris", relyingPartyEntityType)
	}
	if (len(m.JWKS) > 0) == (m.JWKSURI != "") {
		return storage.RegisteredClientConfig{}, nil, fmt.Errorf("%s metadata must declare exactly one of jwks or jwks_uri", relyingPartyEntityType)
	}

	if err := a.checkSignedResponseAlgorithms(m); err != nil {
		return storage.RegisteredClientConfig{}, nil, err
	}

	declared, err := a.declaredClientAuthMethods(m, limits.authMethods)
	if err != nil {
		return storage.RegisteredClientConfig{}, nil, err
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
		RequestObjectAlgorithm:          requestObjectAlg,
		SenderConstrain:                 senderConstrain,
		AllowedScopes:                   a.cfg.AllowedScopes,
		AuthorizationDetailsTypes:       a.cfg.AuthorizationDetailsTypes,
		AllowedResources:                a.cfg.AllowedResources,
		AutomaticFederationRegistration: true,
		AllowsClientCredentialsGrant:    a.cfg.AllowsClientCredentialsGrant,
	}
	if err := a.applyDisplayAndSubjectType(&cfg, id, m); err != nil {
		return storage.RegisteredClientConfig{}, nil, err
	}

	// storage.NewRegisteredClient requires each method's own field —
	// read, per method, from wherever RFC 8705 actually places it:
	// token_endpoint_auth_signing_alg(s) for private_key_jwt, the
	// client's own published certificate (via jwks/jwks_uri's "x5c") for
	// self_signed_tls_client_auth, and a plain metadata string for
	// tls_client_auth and its four SAN-typed siblings.
	if err := a.applyClientAuthMethods(&cfg, declared, m, jwks, limits.signingAlgs); err != nil {
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

// clientDisplayFromMetadata reads what a consent screen can show about
// the client: client_name, logo_uri, policy_uri and tos_uri, each
// optional. Present but unusable values — a name storage rejects, or a
// URL that isn't https — fail the registration like any other malformed
// metadata, rather than being passed on to a consent page.
func clientDisplayFromMetadata(m relyingPartyMetadata) (storage.ClientDisplay, error) {
	if err := storage.ValidateClientName(m.ClientName); err != nil {
		return storage.ClientDisplay{}, fmt.Errorf("client_name: %w", err)
	}
	display := storage.ClientDisplay{Name: m.ClientName}
	for _, field := range []struct {
		name, raw string
		dst       *fapi.URL
	}{
		{"logo_uri", m.LogoURI, &display.LogoURI},
		{"policy_uri", m.PolicyURI, &display.PolicyURI},
		{"tos_uri", m.TOSURI, &display.TermsOfServiceURI},
	} {
		if field.raw == "" {
			continue
		}
		u, err := fapi.ParseEndpointURL(field.raw)
		if err != nil {
			return storage.ClientDisplay{}, fmt.Errorf("%s: %w", field.name, err)
		}
		*field.dst = u
	}
	return display, nil
}

// applyClientAuthMethodFields sets cfg's authMethod-specific field from
// m/jwks — split out of registeredClientConfigFromMetadata purely to
// keep that method's own cognitive complexity manageable.
func applyClientAuthMethodFields(cfg *storage.RegisteredClientConfig, authMethod storage.ClientAuthMethod, m relyingPartyMetadata, jwks json.RawMessage, defaultAlgs []fapi.SignatureAlgorithm, permittedAlgs *permittedValues) error {
	switch authMethod {
	case storage.ClientAuthMethodPrivateKeyJWT:
		algs, err := assertionAlgorithms(m, defaultAlgs, permittedAlgs)
		if err != nil {
			return err
		}
		cfg.ClientAssertionAlgorithm, cfg.ClientAssertionAlgorithms = algs[0], algs
	case storage.ClientAuthMethodSelfSignedTLSClientAuth:
		thumbprints, err := certificateThumbprintsFromJWKS(jwks)
		if err != nil {
			return fmt.Errorf("self_signed_tls_client_auth: %w", err)
		}
		cfg.ExpectedCertificateThumbprint, cfg.AdditionalCertificateThumbprints = thumbprints[0], thumbprints[1:]
	default:
		if err := applyPKIClientAuthFields(cfg, authMethod, m); err != nil {
			return err
		}
		return requireKeyPossession(cfg, authMethod, jwks)
	}
	return nil
}

// requireKeyPossession sets cfg.CertificateKeyThumbprints to the keys
// of the RP JWK Set, for a CA-issued certificate method (tls_client_auth
// and its SAN siblings). OpenID Federation 1.0 §12.1.1.2 has an RP that
// doesn't sign a Request Object authenticate at PAR with a method "that
// proves possession of one of the RP's private keys", and "the
// corresponding public key MUST be in the Entity's RP JWK Set": a
// certificate matching the registered subject or SAN alone proves
// possession of a key the federation never vouched for. The server
// therefore requires the certificate to carry one of these keys as well,
// at every endpoint, whether or not a Request Object is sent.
func requireKeyPossession(cfg *storage.RegisteredClientConfig, authMethod storage.ClientAuthMethod, jwks json.RawMessage) error {
	thumbprints, err := keyThumbprintsFromJWKS(jwks)
	if err != nil {
		return fmt.Errorf("%s: %w", authMethod, err)
	}
	cfg.CertificateKeyThumbprints = thumbprints
	return nil
}

// applyPKIClientAuthFields sets the subject or SAN field a CA-issued
// certificate method authenticates by.
func applyPKIClientAuthFields(cfg *storage.RegisteredClientConfig, authMethod storage.ClientAuthMethod, m relyingPartyMetadata) error {
	switch authMethod {
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

// checkSignedResponseAlgorithms refuses an RP asking for its ID tokens
// or UserInfo responses to be signed with an algorithm the server won't
// use: the server signs each with one algorithm for every client, and
// registering the RP anyway would drop its choice silently (OpenID
// Connect Core §10.1: the ID token is signed "using the algorithm
// specified" at registration; Dynamic Client Registration 1.0 §2:
// userinfo_signed_response_alg makes the response a signed JWT).
func (a *AutomaticClientRepository) checkSignedResponseAlgorithms(m relyingPartyMetadata) error {
	if m.IDTokenSignedResponseAlg != "" && a.cfg.IDTokenSigningAlgorithm.IsValid() && m.IDTokenSignedResponseAlg != a.cfg.IDTokenSigningAlgorithm.String() {
		return fmt.Errorf("id_token_signed_response_alg %q is not %s, the only algorithm this OP signs ID tokens with", m.IDTokenSignedResponseAlg, a.cfg.IDTokenSigningAlgorithm)
	}
	if m.UserinfoSignedResponseAlg == "" {
		return nil
	}
	if !a.cfg.UserInfoSigningAlgorithm.IsValid() {
		return fmt.Errorf("userinfo_signed_response_alg %q is requested, but this OP doesn't sign UserInfo responses", m.UserinfoSignedResponseAlg)
	}
	if m.UserinfoSignedResponseAlg != a.cfg.UserInfoSigningAlgorithm.String() {
		return fmt.Errorf("userinfo_signed_response_alg %q is not %s, the only algorithm this OP signs UserInfo responses with", m.UserinfoSignedResponseAlg, a.cfg.UserInfoSigningAlgorithm)
	}
	return nil
}

// declaredMethod is one client authentication method an RP's metadata
// declares, and whether it declared it as its token_endpoint_auth_method
// (rather than only among token_endpoint_auth_methods_supported).
type declaredMethod struct {
	method   storage.ClientAuthMethod
	explicit bool
}

// declaredClientAuthMethods is every method the RP declares that this
// package implements and AllowedClientAuthMethods permits (OpenID
// Federation 1.0 §12.1.4: declared either with token_endpoint_auth_method
// or with RP Metadata Choices' token_endpoint_auth_methods_supported,
// which, when both are present, must include the former). An RP
// declaring neither is refused: automatic registration has no secret for
// Dynamic Client Registration's client_secret_basic default, and this
// package infers no other. Listed methods it doesn't implement are
// skipped; a token_endpoint_auth_method it doesn't implement, or one
// AllowedClientAuthMethods refuses, fails the registration.
//
// Every method that remains is registered, not only the
// token_endpoint_auth_method: §12.1.4 has the OP accept "any client
// authentication method that is mutually supported", since automatic
// registration never tells it which one the RP will use. permitted, when
// set, is what the metadata policy allows token_endpoint_auth_method to
// be, and listed methods outside it are skipped as well: the policy
// names the singular parameter only, and a superior restricting how its
// subordinates authenticate means the methods they register, whichever
// parameter declares them.
func (a *AutomaticClientRepository) declaredClientAuthMethods(m relyingPartyMetadata, permitted *permittedValues) ([]declaredMethod, error) {
	single := m.TokenEndpointAuthMethod
	list := m.TokenEndpointAuthMethodsSupported
	if single == "" && len(list) == 0 {
		return nil, fmt.Errorf("%s metadata declares no client authentication method (token_endpoint_auth_method or token_endpoint_auth_methods_supported)", relyingPartyEntityType)
	}
	if single != "" && list != nil && !slices.Contains(list, single) {
		return nil, fmt.Errorf("token_endpoint_auth_method %q is not among token_endpoint_auth_methods_supported", single)
	}
	var declared []declaredMethod
	if single != "" {
		method, err := storage.ParseClientAuthMethod(single)
		if err != nil {
			return nil, fmt.Errorf("token_endpoint_auth_method: %w", err)
		}
		if !a.allowsClientAuthMethod(method) {
			return nil, fmt.Errorf("token_endpoint_auth_method %q is not permitted by allowed_client_auth_methods", method)
		}
		declared = append(declared, declaredMethod{method: method, explicit: true})
	}
	for _, name := range list {
		method, err := storage.ParseClientAuthMethod(name)
		if err != nil || !a.allowsClientAuthMethod(method) || !permitted.allows(name) || slices.ContainsFunc(declared, func(d declaredMethod) bool { return d.method == method }) {
			continue
		}
		declared = append(declared, declaredMethod{method: method})
	}
	if len(declared) == 0 {
		return nil, fmt.Errorf("none of token_endpoint_auth_methods_supported %v is supported and permitted by allowed_client_auth_methods and the metadata policy", list)
	}
	return declared, nil
}

// applyClientAuthMethods sets cfg's methods and each one's own fields
// from m/jwks. A method only listed in token_endpoint_auth_methods_supported
// whose metadata can't support it (e.g. tls_client_auth with no
// tls_client_auth_subject_dn) is dropped; the explicitly requested
// token_endpoint_auth_method must be usable. At least one method must
// remain.
func (a *AutomaticClientRepository) applyClientAuthMethods(cfg *storage.RegisteredClientConfig, declared []declaredMethod, m relyingPartyMetadata, jwks json.RawMessage, permittedAlgs *permittedValues) error {
	var lastErr error
	for _, d := range declared {
		if err := applyClientAuthMethodFields(cfg, d.method, m, jwks, a.cfg.ClientAssertionAlgorithms, permittedAlgs); err != nil {
			if d.explicit {
				return err
			}
			lastErr = err
			continue
		}
		cfg.ClientAuthMethods = append(cfg.ClientAuthMethods, d.method)
	}
	if len(cfg.ClientAuthMethods) == 0 {
		return fmt.Errorf("no declared client authentication method is usable: %w", lastErr)
	}
	cfg.ClientAuthMethod = cfg.ClientAuthMethods[0]
	return nil
}

// assertionAlgorithms is what an RP using private_key_jwt may sign its
// assertions with: its token_endpoint_auth_signing_alg if declared (which
// Dynamic Client Registration makes the only one), else its
// token_endpoint_auth_signing_alg_values_supported (skipping algorithms
// this package doesn't implement), else defaultAlgs — "any algorithm
// supported by the OP and the RP".
//
// permitted, when set, is what the metadata policy allows
// token_endpoint_auth_signing_alg to be. The policy already holds a
// declared token_endpoint_auth_signing_alg to it, but not the other two
// sources, so algorithms outside it are left out of those, and an RP left
// with none is refused (RP Metadata Choices 1.0 §4: use a choice that is
// supported, or reject the registration when none is). A superior's
// one_of on token_endpoint_auth_signing_alg then means the algorithms
// the RP registers, however it declares them.
func assertionAlgorithms(m relyingPartyMetadata, defaultAlgs []fapi.SignatureAlgorithm, permitted *permittedValues) ([]fapi.SignatureAlgorithm, error) {
	single := m.TokenEndpointAuthSigningAlg
	list := m.TokenEndpointAuthSigningAlgValuesSupported
	if single != "" {
		return declaredAssertionAlgorithm(single, list)
	}
	if list != nil {
		return supportedAssertionAlgorithms(list, permitted)
	}
	var algs []fapi.SignatureAlgorithm
	for _, alg := range defaultAlgs {
		if permitted.allows(alg.String()) {
			algs = append(algs, alg)
		}
	}
	if len(algs) == 0 {
		return nil, fmt.Errorf("token_endpoint_auth_signing_alg is required for private_key_jwt: no default algorithm is configured that the metadata policy permits")
	}
	return algs, nil
}

// declaredAssertionAlgorithm is assertionAlgorithms' answer when the RP
// declared token_endpoint_auth_signing_alg: that one algorithm, which
// must be among list, its declared supported algorithms, when it
// declared any.
func declaredAssertionAlgorithm(single string, list []string) ([]fapi.SignatureAlgorithm, error) {
	if list != nil && !slices.Contains(list, single) {
		return nil, fmt.Errorf("token_endpoint_auth_signing_alg %q is not among token_endpoint_auth_signing_alg_values_supported", single)
	}
	alg, err := fapi.ParseSignatureAlgorithm(single)
	if err != nil {
		return nil, fmt.Errorf("token_endpoint_auth_signing_alg: %w", err)
	}
	return []fapi.SignatureAlgorithm{alg}, nil
}

// supportedAssertionAlgorithms is list's algorithms this package
// implements and permitted allows, once each, in list's order. An empty
// list (which a superior's subset_of can leave) declares no algorithm,
// so it is refused like one with none usable, never read as absent.
func supportedAssertionAlgorithms(list []string, permitted *permittedValues) ([]fapi.SignatureAlgorithm, error) {
	var algs []fapi.SignatureAlgorithm
	for _, name := range list {
		if !permitted.allows(name) {
			continue
		}
		if alg, err := fapi.ParseSignatureAlgorithm(name); err == nil && !slices.Contains(algs, alg) {
			algs = append(algs, alg)
		}
	}
	if len(algs) == 0 {
		return nil, fmt.Errorf("none of token_endpoint_auth_signing_alg_values_supported %v is supported and permitted by the metadata policy", list)
	}
	return algs, nil
}

// choiceLimits is what a Trust Chain's metadata policy permits for the
// singular parameters automatic registration also reads an OpenID
// Connect RP Metadata Choices 1.0 §2 plural sibling of. Policy
// operators act on the parameter they name only (OpenID Federation 1.0
// §6.1.3.1), and one_of checks a value only "if the metadata parameter
// is present" (§6.1.3.1.4); so an RP leaving out
// token_endpoint_auth_signing_alg under a one_of on it, and declaring
// token_endpoint_auth_signing_alg_values_supported instead, would
// otherwise register a value the policy forbids. Each nil field means
// no policy restricts that parameter.
type choiceLimits struct {
	authMethods *permittedValues // token_endpoint_auth_method
	signingAlgs *permittedValues // token_endpoint_auth_signing_alg
}

// permittedValues is the set of values a metadata policy allows a
// singular parameter; a nil *permittedValues allows any value.
type permittedValues struct{ values []string }

// allows reports whether p permits v.
func (p *permittedValues) allows(v string) bool {
	return p == nil || slices.Contains(p.values, v)
}

// choiceLimitsFromPolicy reads choiceLimits from policy, the merged
// openid_relying_party metadata policy (nil when none applies).
func choiceLimitsFromPolicy(policy map[string]intfed.PolicyOperators) (choiceLimits, error) {
	var limits choiceLimits
	for _, field := range []struct {
		param string
		dst   **permittedValues
	}{
		{"token_endpoint_auth_method", &limits.authMethods},
		{"token_endpoint_auth_signing_alg", &limits.signingAlgs},
	} {
		permitted, constrained, err := intfed.PermittedStrings(policy[field.param])
		if err != nil {
			return choiceLimits{}, fmt.Errorf("metadata policy for %s: %w", field.param, err)
		}
		if constrained {
			*field.dst = &permittedValues{values: permitted}
		}
	}
	return limits, nil
}

// refuseEmptyStrings refuses raw, an openid_relying_party metadata
// object, when a string parameter this package reads from it is the
// empty string. None of them has "" among its values, and each would
// otherwise read as left out while counting as present to a metadata
// policy (OpenID Federation 1.0 §6.1.3.1.7: essential requires only that
// the parameter "MUST be present"), so a superior's essential policy
// would be met by a value that registers the OP's default instead.
func refuseEmptyStrings(raw json.RawMessage) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return fmt.Errorf("parse %s metadata: %w", relyingPartyEntityType, err)
	}
	for _, name := range relyingPartyStringParameters {
		// Unmarshalling null into a string leaves it "" too, so only a
		// JSON string counts: null states nothing, and reads as left out.
		var value string
		if v, ok := members[name]; ok && len(v) > 0 && v[0] == '"' && json.Unmarshal(v, &value) == nil && value == "" {
			return fmt.Errorf("%s must not be empty", name)
		}
	}
	return nil
}

// relyingPartyStringParameters is the name of every string parameter
// relyingPartyMetadata reads, from its json tags, so a parameter added
// there is covered by refuseEmptyStrings without being listed twice.
var relyingPartyStringParameters = func() []string {
	var names []string
	t := reflect.TypeFor[relyingPartyMetadata]()
	for i := range t.NumField() {
		f := t.Field(i)
		kind := f.Type.Kind()
		if kind == reflect.Pointer {
			kind = f.Type.Elem().Kind()
		}
		if kind == reflect.String {
			names = append(names, strings.Split(f.Tag.Get("json"), ",")[0])
		}
	}
	return names
}()

// allowsClientAuthMethod reports whether method is permitted by
// AutomaticRegistrationConfig.AllowedClientAuthMethods — every method
// when that list is empty.
func (a *AutomaticClientRepository) allowsClientAuthMethod(method storage.ClientAuthMethod) bool {
	return len(a.cfg.AllowedClientAuthMethods) == 0 || slices.Contains(a.cfg.AllowedClientAuthMethods, method)
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
//
// Each is nil when the metadata leaves it out; one that is present must
// name an algorithm. An empty string would otherwise read as "no
// encryption" while counting as present, so a superior's "essential"
// policy on the parameter would be met by a value that disables it.
func parseEncryptionAlgorithmPair(algValue, encValue *string, algLabel, encLabel string) (fapi.KeyManagementAlgorithm, fapi.ContentEncryptionAlgorithm, error) {
	if algValue != nil && *algValue == "" {
		return 0, 0, fmt.Errorf("%s must not be empty", algLabel)
	}
	if encValue != nil && *encValue == "" {
		return 0, 0, fmt.Errorf("%s must not be empty", encLabel)
	}
	if (algValue != nil) != (encValue != nil) {
		return 0, 0, fmt.Errorf("%s and %s must both be set, or neither", algLabel, encLabel)
	}
	if algValue == nil {
		return 0, 0, nil
	}
	alg, err := fapi.ParseKeyManagementAlgorithm(*algValue)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", algLabel, err)
	}
	enc, err := fapi.ParseContentEncryptionAlgorithm(*encValue)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", encLabel, err)
	}
	return alg, enc, nil
}

// certificateThumbprintsFromJWKS computes the RFC 8705 §3.1 x5t#S256
// thumbprint of every key's own certificate in jwks — the first entry
// of each key's "x5c", which RFC 7517 §4.7 says contains the key (RFC
// 8705 §2.2: "the existing jwks_uri or jwks metadata parameters... are
// used to convey the client's certificates via JWK... A certificate is
// represented with the x5c parameter"). Every one is registered, so an
// RP may authenticate with the certificate of any key in its RP JWK Set
// (OpenID Federation 1.0 §12.1.1.2: "an x5c Claim for a key in the
// Entity's RP JWK Set"), the second one during a key rollover, say.
func certificateThumbprintsFromJWKS(jwks json.RawMessage) ([]string, error) {
	candidates, err := jose.ParseJWKSet(jwks)
	if err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	var thumbprints []string
	for _, c := range candidates {
		if len(c.Certificates) == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(c.Certificates[0])
		if err != nil {
			continue
		}
		if t := mtls.Thumbprint(cert); !slices.Contains(thumbprints, t) {
			thumbprints = append(thumbprints, t)
		}
	}
	if len(thumbprints) == 0 {
		return nil, fmt.Errorf("jwks has no usable x5c certificate")
	}
	return thumbprints, nil
}

// keyThumbprintsFromJWKS is internal/mtls.PublicKeyThumbprint of every
// key in jwks, the keys a CA-issued certificate must carry one of.
func keyThumbprintsFromJWKS(jwks json.RawMessage) ([]string, error) {
	candidates, err := jose.ParseJWKSet(jwks)
	if err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	var thumbprints []string
	for _, c := range candidates {
		t, err := mtls.PublicKeyThumbprint(c.PublicKey)
		if err != nil || slices.Contains(thumbprints, t) {
			continue
		}
		thumbprints = append(thumbprints, t)
	}
	if len(thumbprints) == 0 {
		return nil, fmt.Errorf("the RP JWK Set has no usable key for the certificate to carry (OpenID Federation 1.0 §12.1.1.2)")
	}
	return thumbprints, nil
}

// applyDisplayAndSubjectType sets cfg's Display and SubjectType from m:
// what a consent screen shows about the client, and the kind of sub its
// end users get.
func (a *AutomaticClientRepository) applyDisplayAndSubjectType(cfg *storage.RegisteredClientConfig, id fapi.ClientID, m relyingPartyMetadata) error {
	display, err := clientDisplayFromMetadata(m)
	if err != nil {
		return err
	}
	subjectType, err := a.subjectTypeFromMetadata(m)
	if err != nil {
		return err
	}
	cfg.Display, cfg.SubjectType = display, subjectType
	if subjectType == fapi.SubjectTypePairwise {
		if cfg.Sector, err = entitySector(id, m.RedirectURIs); err != nil {
			return err
		}
	}
	return nil
}

// entitySector returns the sector a pairwise automatically registered
// client's subjects are derived for: its Entity Identifier's host, which
// the Trust Chain binds to it. A Relying Party's redirect_uris are its
// own claim, so a sector derived from them alone would let it name
// another Relying Party's host and receive that Relying Party's sub
// values wherever no redirect proves the claim (CIBA, say). So every
// redirect URI must be https on that same host (OpenID Connect Core
// §8.1's redirect-host sector, made one the Relying Party is known to
// control), or the registration is refused. This is stricter than §8.1,
// never different: a sector §8.1 would compute from redirect URIs on
// another host is refused rather than used. Relying Parties whose Entity
// Identifiers share a host (path-scoped tenants of one platform, say)
// share a sector, and with it every user's sub; give such tenants
// distinct hosts if they mustn't be linkable. A sector_identifier_uri,
// from the Relying Party or a superior's metadata policy, isn't
// supported with pairwise yet.
func entitySector(id fapi.ClientID, redirectURIs []string) (string, error) {
	entity, err := url.Parse(id.String())
	if err != nil || entity.Hostname() == "" {
		return "", fmt.Errorf("pairwise subject_type: the Entity Identifier %q has no host", id)
	}
	// The sector is the host lowercased in ASCII only: Unicode case
	// mapping would fold a non-ASCII host ("İ.example") onto an ASCII
	// one ("i.example") that is a different DNS name, and so share its
	// sector. Entity Identifiers here are ASCII already (ValidEntityID).
	host := canonical.LowerASCII(entity.Hostname())
	for _, raw := range redirectURIs {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || !canonical.EqualFoldASCII(u.Hostname(), host) {
			return "", fmt.Errorf("pairwise subject_type: redirect_uris must all be https on the Entity Identifier's host %q", host)
		}
	}
	return host, nil
}

// validateSubjectTypes checks AutomaticRegistrationConfig's SubjectTypes
// and DefaultSubjectType.
func validateSubjectTypes(types []fapi.SubjectType, def fapi.SubjectType) error {
	for i, t := range types {
		if !t.IsValid() {
			return fmt.Errorf("federation: config: subject_types: invalid subject type %v", t)
		}
		if slices.Contains(types[:i], t) {
			return fmt.Errorf("federation: config: subject_types: %s is listed twice", t)
		}
	}
	if def != 0 && !slices.Contains(effectiveSubjectTypes(types), def) {
		return fmt.Errorf("federation: config: default_subject_type %v is not one of subject_types", def)
	}
	return nil
}

// effectiveSubjectTypes is types, or public alone when it is empty.
func effectiveSubjectTypes(types []fapi.SubjectType) []fapi.SubjectType {
	if len(types) == 0 {
		return []fapi.SubjectType{fapi.SubjectTypePublic}
	}
	return types
}

// subjectTypeFromMetadata returns the subject type an automatically
// registered client gets: its metadata's subject_type, or
// DefaultSubjectType when it names none. It's recorded on the client
// rather than left to the server's default, so the decision made here,
// against this OP's SubjectTypes, is the one every grant uses.
//
// A subject_type this OP doesn't issue is refused. So is a pairwise one
// with a sector_identifier_uri: that names the sector the Relying Party
// expects its sub values to be shared across (OpenID Connect Core
// §8.1), which this package doesn't fetch, and deriving from its
// redirect URIs' host instead would give it different sub values than
// it asked for, which a later release honouring the URI would then
// change. A public client's sector_identifier_uri changes nothing, and
// is ignored. A pairwise client's sector is its Entity Identifier's host
// (see entitySector).
func (a *AutomaticClientRepository) subjectTypeFromMetadata(m relyingPartyMetadata) (fapi.SubjectType, error) {
	subjectType := a.cfg.DefaultSubjectType
	if subjectType == 0 {
		subjectType = fapi.SubjectTypePublic
	}
	if m.SubjectType != "" {
		parsed, err := fapi.ParseSubjectType(m.SubjectType)
		if err != nil {
			return 0, fmt.Errorf("subject_type: %w", err)
		}
		subjectType = parsed
	}
	if !slices.Contains(effectiveSubjectTypes(a.cfg.SubjectTypes), subjectType) {
		return 0, fmt.Errorf("subject_type %s is not one this OP issues", subjectType)
	}
	if subjectType == fapi.SubjectTypePairwise && m.SectorIdentifierURI != "" {
		return 0, errors.New("sector_identifier_uri is not supported with pairwise subject identifiers")
	}
	return subjectType, nil
}
