package federation

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"runtime/debug"
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
// Federation 1.0 §12.1, "Automatic Registration"). It is copied by
// NewAutomaticClientRepository, the contents of its slices included;
// mutating one after passing it to NewAutomaticClientRepository has no
// effect.
type AutomaticRegistrationConfig struct {
	// AllowedScopes is the scope allowlist granted to every
	// automatically-registered client, uniformly. This deliberately
	// does NOT come from the Relying Party's own self-published
	// metadata: an RP's openid_relying_party metadata is
	// attacker-controlled (any federation member publishes its own), so
	// trusting a self-asserted "these are the scopes I'm allowed" claim
	// would let any RP grant itself unlimited scope. The federation can
	// still narrow it: when the RP's resolved metadata (its own, after
	// every superior's metadata policy) has a scope parameter, the
	// client gets only the AllowedScopes that also lists, and one leaving
	// scope out gets only those a superior's subset_of, one_of or value
	// on scope permits; it fails to register if that leaves none.
	// Required — at least one.
	AllowedScopes []string

	// AuthorizationDetailsTypes are the Rich Authorization Request types
	// every automatically-registered client may request
	// (storage.RegisteredClientConfig.AuthorizationDetailsTypes) — for
	// the same reason as AllowedScopes, never a type only an RP's own
	// self-published authorization_details_types names. Empty means none.
	// The federation can narrow them, never widen them: when the RP's
	// resolved metadata has authorization_details_types, the client gets
	// only the types that also lists (none, when it lists none of them),
	// and a superior's metadata policy on authorization_details_types
	// (subset_of, one_of, or a value) bounds them even when the RP leaves
	// the parameter out, which the policy's operators then leave absent.
	// A value null removes the parameter rather than bounding it, so an
	// RP whose authorization_details_types a superior's value null
	// removes gets every type here that no other operator withholds; a
	// superior meaning to restrict the types uses subset_of or one_of.
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

	// AllowsClientCredentialsGrant permits automatically-registered
	// clients to use the RFC 6749 §4.4 client_credentials grant —
	// uniformly, exactly like AllowedScopes, and for the identical
	// reason: never inferred from the RP's own self-published metadata.
	// Deciding whether a client may mint a token representing itself,
	// with no end user or authorization code involved at all, is a
	// capability grant, not a mechanism detail an RP can safely
	// self-assert. False (the zero value/default) means no
	// automatically-registered client may use client_credentials,
	// regardless of what it publishes. True grants it to each client
	// whose resolved metadata (its own, after every superior's metadata
	// policy) lists client_credentials in grant_types, unless its Trust
	// Chain's metadata policy on grant_types (a superior's subset_of, or
	// a value) leaves client_credentials out: the RP's metadata and the
	// federation can withhold the grant, never add it. A client whose
	// resolved metadata leaves grant_types out doesn't get it, whatever
	// the policy: OpenID Connect Dynamic Client Registration 1.0 §2 and
	// RFC 7591 §2 have a client omitting grant_types use
	// authorization_code alone, so it is registered for the
	// authorization code flow only (see AutomaticClientRepository for
	// its refresh tokens). Also still requires
	// server.Config.ClientCredentialsGrant to be enabled server-wide,
	// exactly as storage.RegisteredClientConfig's own field of the same
	// name does for a statically registered client.
	AllowsClientCredentialsGrant bool

	// AllowsCIBA permits automatically-registered clients to use
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
	// When true, a client gets CIBA only if its resolved grant_types
	// lists urn:openid:params:grant-type:ciba and the metadata policy on
	// grant_types doesn't leave it out, exactly as for
	// AllowsClientCredentialsGrant — so never one leaving grant_types
	// out, whatever CIBA metadata it publishes: CIBA Core 1.0 §4 has a
	// poll or ping client list the CIBA grant. A client getting CIBA must
	// also name its backchannel_token_delivery_mode, which §4 makes
	// REQUIRED: one that doesn't fails to register, as one naming ping
	// without a backchannel_client_notification_endpoint does, rather
	// than being registered for a delivery mode it didn't choose.
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
	// When a superior's metadata policy on subject_type (a one_of, say)
	// forbids it, such a Relying Party gets the first of SubjectTypes
	// the policy permits instead, and fails to register if there is
	// none. server.New sets it from server.Config.Subjects.
	DefaultSubjectType fapi.SubjectType

	// OnResolutionFailure, if set, is called with the reason whenever a
	// client_id that is a well-formed Entity Identifier (at most 2 KiB),
	// and not statically registered, fails automatic registration: its
	// Trust Chain doesn't resolve to a configured Trust Anchor, it has no
	// openid_relying_party metadata, or that metadata can't be used
	// (e.g. no client authentication method this package implements, or
	// a token_endpoint_auth_method outside AllowedClientAuthMethods).
	// The client itself only ever sees a generic invalid-client error
	// (server_error if this hook panics, below), so this is how an
	// operator finds out why.
	//
	// err can carry text from the RP's own statements and metadata: log
	// it, never return it to the client. It runs on the goroutine this
	// package resolves the client_id on, not on a request's: the
	// requests for that client_id made while it resolves share that one
	// resolution and this one call, which can come after the request
	// that started the resolution has returned, while another still
	// waits. ctx keeps that first request's values but not its
	// cancellation, and is cancelled once no request waits on the
	// resolution any more. So it must not block and must not panic. The
	// failure is remembered, as FailureCacheAge sets out, before it is
	// called, and a request for that client_id arriving while it runs
	// gets that failure at once instead of joining the resolution, even
	// once FailureCacheAge has passed or when the failure couldn't be
	// remembered. That includes a ResolveClient (or
	// AutomaticClientKeySource lookup) for the same client_id made from
	// the hook itself, which so never waits on the very resolution
	// calling it; resolving another client_id from it needs a place
	// under MaxConcurrentResolutions of its own while this resolution
	// still holds one. A panic in it is recovered rather than ending
	// the process: every request waiting on the resolution gets
	// an error wrapping storage.ErrStoreUnavailable (the server answers
	// 500 server_error), and the failure it was called for is remembered
	// as if it had returned. A failure is remembered for FailureCacheAge,
	// so an RP that keeps retrying is reported once per resolution
	// attempted, not once per request; the requests answered from that
	// memory get the failure's message only, cut to its first KiB.
	// Optional. A resolution abandoned because every request waiting on
	// it went away (see MaxConcurrentResolutions) isn't reported: it says
	// nothing about the client_id.
	OnResolutionFailure func(ctx context.Context, clientID fapi.ClientID, err error)

	// MaxConcurrentResolutions bounds how many Trust Chain resolutions
	// for distinct client_ids run at once. A client_id is resolved before
	// its client is authenticated, so any caller can start one by naming
	// an Entity Identifier, each costing outbound fetches; past this
	// bound a request needing a new resolution fails at once with an
	// error wrapping ErrTooManyResolutions (and so
	// storage.ErrStoreUnavailable, which the server answers with 500
	// server_error rather than invalid_client), and that failure isn't
	// remembered against the client_id. Cached registrations and requests
	// joining a resolution already running for their client_id don't
	// count. A resolution also stops once every request waiting on it
	// has gone. Zero means DefaultMaxConcurrentResolutions; negative is
	// invalid.
	MaxConcurrentResolutions int
}

// DefaultMaxConcurrentResolutions is
// AutomaticRegistrationConfig.MaxConcurrentResolutions when it is zero.
const DefaultMaxConcurrentResolutions = 128

// ErrTooManyResolutions is wrapped by the error an automatic
// registration returns when AutomaticRegistrationConfig.MaxConcurrentResolutions
// Trust Chain resolutions are already running: the server is
// temporarily too busy to resolve another client_id, which says nothing
// about that client_id. It wraps storage.ErrStoreUnavailable, so a
// caller treating the client repository as unavailable (as the server
// does) does so here too.
var ErrTooManyResolutions = fmt.Errorf("federation: too many Trust Chain resolutions in progress: %w", storage.ErrStoreUnavailable)

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

// maxEntityIDBytes bounds the client_id AutomaticClientRepository
// resolves: 2 KiB, far longer than a real Entity Identifier, a URL naming
// an entity. (None much past 6 KiB could resolve anyway: its Entity
// Configuration names it twice, as iss and sub, and a statement is parsed
// only up to 16 KiB.) A longer client_id is answered like one that isn't
// an Entity Identifier at all, before any cache is consulted or anything
// fetched, so what a client_id makes the caches and error text hold stays
// small whatever its length.
const maxEntityIDBytes = 2048

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
// a well-formed https Entity Identifier (ValidEntityID) of at most 2 KiB;
// any other id is an unknown client, with nothing fetched. An Underlying
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
// callers this way. Each resolution runs on a goroutine of this
// package's own, which the requests naming that client_id wait on,
// except those answered from a registration it has cached or a failure
// it has remembered (see AutomaticRegistrationConfig.FailureCacheAge).
// A panic there, in AutomaticRegistrationConfig.OnResolutionFailure,
// the fetcher's transport or the Clock, is recovered: every request
// waiting on the resolution gets an error wrapping
// storage.ErrStoreUnavailable, and no registration is cached.
//
// The client_credentials grant and CIBA are each gated by their own
// config-level switch (AutomaticRegistrationConfig.AllowsClientCredentialsGrant/
// AllowsCIBA) — off by default, since whether an automatically-resolved
// RP may use either is a capability grant an operator makes, never
// something an RP's own self-published metadata can grant itself. An
// RP gets either only when its resolved grant_types lists it: one
// leaving grant_types out is registered for the authorization code flow
// alone, the default OpenID Connect Dynamic Client Registration 1.0 §2
// and RFC 7591 §2 give an omitted grant_types. Its refresh tokens are
// gated as any client's are, by scope rather than by grant_types: the
// server issues one at the code exchange exactly when the granted scope
// includes offline_access (OpenID Connect Core §11), which takes
// AllowedScopes, narrowed by the RP's resolved scope, to include it.
// That default describes the grants a client uses, and RFC 6749 §1.5
// leaves issuing a refresh token to the server, so neither has the
// server refuse one to such an RP. Every
// storage.ClientAuthMethod this package's own storage type supports is
// readable from an RP's own token_endpoint_auth_method and/or
// token_endpoint_auth_methods_supported metadata — every declared
// method the RP's metadata supports is registered, and the server
// accepts whichever it uses (see declaredClientAuthMethods) —
// including every RFC 8705 mTLS method: ClientAuthMethodSelfSignedTLSClientAuth
// reads the RP's own certificates from the "x5c" members of its
// jwks/jwks_uri entries (RFC 8705 §2.2) and accepts the certificate of
// any of them that holds its entry's own key (RFC 7517 §4.7); ClientAuthMethodTLSClientAuth and its four SAN-typed
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
	// failureSweepDue is when lookupFailure next drops every expired
	// failure.
	failureSweepDue time.Time
	// inflight holds the resolution currently running for each
	// client_id, so concurrent requests naming the same unknown
	// client_id share one Trust Chain resolution rather than each
	// starting their own.
	inflight map[fapi.ClientID]*inflightResolution
	// running counts resolutions whose goroutine hasn't finished, those
	// abandoned by every waiter but still winding down included, at most
	// AutomaticRegistrationConfig.MaxConcurrentResolutions.
	running int
}

// inflightResolution is one in-progress resolution that concurrent
// callers for the same client_id wait on; done is closed once entry and
// err are set. waiters counts the callers waiting on it, and cancel
// stops it once the last of them has gone. failure, once set, is the
// failure the resolution has ended in, while OnResolutionFailure is
// called with it: a caller for its client_id gets that at once instead
// of waiting (see resolveUncached). waiters and failure are guarded by
// AutomaticClientRepository.mu.
type inflightResolution struct {
	done    chan struct{}
	entry   cachedClient
	err     error
	waiters int
	cancel  context.CancelFunc
	failure error
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
//
// NewAutomaticClientRepository copies cfg before validating it, every
// slice it holds included, and the repository keeps only that copy, so
// changing cfg or the contents of its slices afterwards changes no
// client it registers.
func NewAutomaticClientRepository(underlying storage.ClientRepository, resolver *Resolver, fetcher *fapihttp.Client, cfg AutomaticRegistrationConfig, clock Clock) (*AutomaticClientRepository, error) {
	// Copied before anything reads it, so what's validated is what's kept.
	cfg = cfg.clone()
	if underlying == nil {
		return nil, fmt.Errorf("federation: underlying client repository is required")
	}
	if resolver == nil {
		return nil, fmt.Errorf("federation: resolver is required")
	}
	if fetcher == nil {
		return nil, fmt.Errorf("federation: fetcher is required")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.FailureCacheAge == 0 {
		cfg.FailureCacheAge = DefaultFailureCacheAge
	}
	if cfg.MaxConcurrentResolutions == 0 {
		cfg.MaxConcurrentResolutions = DefaultMaxConcurrentResolutions
	}
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

// clone returns c with a copy of each of its slices, nil staying nil.
// OnResolutionFailure, a function, is kept as it is.
func (c AutomaticRegistrationConfig) clone() AutomaticRegistrationConfig {
	c.AllowedScopes = slices.Clone(c.AllowedScopes)
	c.AuthorizationDetailsTypes = slices.Clone(c.AuthorizationDetailsTypes)
	c.AllowedResources = slices.Clone(c.AllowedResources)
	c.AllowedClientAuthMethods = slices.Clone(c.AllowedClientAuthMethods)
	c.ClientAssertionAlgorithms = slices.Clone(c.ClientAssertionAlgorithms)
	c.SubjectTypes = slices.Clone(c.SubjectTypes)
	return c
}

// validate checks c for NewAutomaticClientRepository, before its
// defaults for a zero FailureCacheAge or MaxConcurrentResolutions apply.
func (c AutomaticRegistrationConfig) validate() error {
	if len(c.AllowedScopes) == 0 {
		return fmt.Errorf("federation: config: allowed_scopes is required")
	}
	if c.MaxCacheAge <= 0 {
		return fmt.Errorf("federation: config: max_cache_age must be positive")
	}
	if c.FailureCacheAge < 0 {
		return fmt.Errorf("federation: config: failure_cache_age must not be negative")
	}
	if c.MaxConcurrentResolutions < 0 {
		return fmt.Errorf("federation: config: max_concurrent_resolutions must not be negative")
	}
	if err := validateAllowedClientAuthMethods(c.AllowedClientAuthMethods); err != nil {
		return err
	}
	for _, alg := range c.ClientAssertionAlgorithms {
		if !alg.IsValid() {
			return fmt.Errorf("federation: config: client_assertion_algorithms: invalid algorithm %v", alg)
		}
	}
	if err := validateSubjectTypes(c.SubjectTypes, c.DefaultSubjectType); err != nil {
		return err
	}
	return validateAllowedResources(c.AllowedResources)
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
// resolving the same Trust Chain independently. A key matches a
// requested kid as keys.VerificationKey.KeyID sets out (answersToKeyID).
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
		if req.KeyID != "" && !answersToKeyID(c, req.KeyID) {
			continue
		}
		matched = append(matched, keys.VerificationKey{KeyID: c.KeyID, Algorithm: c.Algorithm, PublicKey: c.PublicKey})
	}
	return keys.VerificationKeySet{Keys: matched}, nil
}

// answersToKeyID reports whether c, a key of an RP's JWK Set, answers
// to kid: its "kid" is kid, or it has none and kid is its RFC 7638
// thumbprint, the kid keys.NewKeyManagerFromSigners derives for such a
// key (jose.AnswersToKeyID). A key whose thumbprint can't be computed
// answers to no kid.
func answersToKeyID(c jose.ParsedJWK, kid string) bool {
	return jose.AnswersToKeyID(c.KeyID, c.PublicKey, c.Algorithm, kid)
}

// resolve returns id's cached entry if still fresh, or resolves (via
// Resolver.Resolve) and caches a new one. An id longer than
// maxEntityIDBytes is refused first, as resolveUncached refuses one that
// isn't an Entity Identifier.
func (a *AutomaticClientRepository) resolve(ctx context.Context, id fapi.ClientID) (cachedClient, error) {
	if len(id) > maxEntityIDBytes {
		return cachedClient{}, fmt.Errorf("federation: %s is not a registered client and, at %d bytes, too long to be a federation entity ID (at most %d)",
			quoteEntityID(string(id)), len(id), maxEntityIDBytes)
	}
	now := a.clock.Now()

	a.mu.Lock()
	if entry, ok := a.cache.get(id, now); ok {
		a.mu.Unlock()
		return entry, nil
	}
	if err := a.lookupFailure(id, now); err != nil {
		a.mu.Unlock()
		return cachedClient{}, err
	}
	call, ok := a.inflight[id]
	if ok && call.failure != nil {
		a.mu.Unlock()
		return cachedClient{}, call.failure
	}
	if !ok {
		if a.running >= a.maxConcurrentResolutions() {
			a.mu.Unlock()
			return cachedClient{}, fmt.Errorf("federation: resolve client %s: %w", quoteEntityID(string(id)), ErrTooManyResolutions)
		}
		call = a.startResolution(ctx, id)
	}
	call.waiters++
	a.mu.Unlock()
	select {
	case <-call.done:
		return call.entry, call.err
	case <-ctx.Done():
		a.leaveResolution(id, call)
		return cachedClient{}, ctx.Err()
	}
}

// maxConcurrentResolutions is AutomaticRegistrationConfig.MaxConcurrentResolutions,
// or its default for a repository not built by NewAutomaticClientRepository.
func (a *AutomaticClientRepository) maxConcurrentResolutions() int {
	if a.cfg.MaxConcurrentResolutions > 0 {
		return a.cfg.MaxConcurrentResolutions
	}
	return DefaultMaxConcurrentResolutions
}

// lookupFailure returns id's remembered registration failure, or nil if
// none is remembered or it has expired at now. It deletes an expired one
// it finds and, at most once per FailureCacheAge, every other expired
// one: a failure is otherwise deleted only when its client_id is
// resolved again or the cache is full, so the failures of client_ids
// never named again would stay until it fills. a.mu must be held.
func (a *AutomaticClientRepository) lookupFailure(id fapi.ClientID, now time.Time) error {
	if !now.Before(a.failureSweepDue) {
		a.dropExpiredFailures(now)
	}
	failed, ok := a.failures[id]
	if !ok {
		return nil
	}
	if !now.Before(failed.expiresAt) {
		delete(a.failures, id)
		return nil
	}
	return failed.err
}

// dropExpiredFailures deletes every failure expired at now, and puts
// lookupFailure's next sweep FailureCacheAge later. a.mu must be held.
func (a *AutomaticClientRepository) dropExpiredFailures(now time.Time) {
	for id, failed := range a.failures {
		if !now.Before(failed.expiresAt) {
			delete(a.failures, id)
		}
	}
	a.failureSweepDue = now.Add(a.cfg.FailureCacheAge)
}

// startResolution starts id's resolution and records it as in flight.
// a.mu must be held.
//
// The resolution is shared by every caller for id, so it runs detached
// from this one's cancellation: one caller giving up (or an attacker
// cancelling its own request on purpose) must not fail the others. It
// keeps ctx's values, and the fetcher's own limits bound how long it can
// take. It is cancelled only once every caller waiting on it has gone
// (leaveResolution), so a caller hanging up doesn't leave outbound
// fetches running on its behalf.
//
// id outlives the caller's request, so the resolution works with its own
// copy of it: a client_id read from a form is a substring of the whole
// request body, which anything sharing its memory keeps alive. That copy
// is a.inflight's key, the registered client's own ID and
// OnResolutionFailure's argument; the failure and registration caches
// each keep a copy of their own as well, so neither depends on its
// caller for one.
func (a *AutomaticClientRepository) startResolution(ctx context.Context, id fapi.ClientID) *inflightResolution {
	id = fapi.ClientID(strings.Clone(string(id)))
	resolveCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	call := &inflightResolution{done: make(chan struct{}), cancel: cancel}
	a.inflight[id] = call
	a.running++
	go a.runResolution(resolveCtx, id, call)
	return call
}

// runResolution resolves id for call, on the goroutine startResolution
// starts for it, then hands the outcome to finishResolution. That
// goroutine is this package's own, so no caller can recover a panic on
// it, and an unrecovered one ends the process: a panic in
// OnResolutionFailure, in the fetcher's transport or the Clock, or in
// this package, any of which a request naming an unresolvable Entity
// Identifier can reach before its client is authenticated. It is
// recovered here instead and fails the resolution. err starts as
// errResolutionUnfinished, so a resolution whose goroutine exits without
// returning or panicking (runtime.Goexit) fails too.
func (a *AutomaticClientRepository) runResolution(ctx context.Context, id fapi.ClientID, call *inflightResolution) {
	entry, err := cachedClient{}, errResolutionUnfinished
	defer func() { a.finishResolution(id, call, entry, err, recover()) }()
	entry, err = a.resolveUncached(ctx, id, call)
}

// finishResolution records call's outcome for every caller waiting on
// it — entry and err as resolveUncached returned them, or, when
// panicked (what a panic in the resolution was recovered with) isn't
// nil, no registration and a resolutionPanicError — forgets call as
// id's resolution in flight, frees its place under
// MaxConcurrentResolutions, wakes its waiters and releases its context.
// It runs deferred, after a panic too, so it calls nothing that could
// panic again.
func (a *AutomaticClientRepository) finishResolution(id fapi.ClientID, call *inflightResolution, entry cachedClient, err error, panicked any) {
	if panicked != nil {
		entry, err = cachedClient{}, newResolutionPanicError(id, panicked)
	}
	a.mu.Lock()
	call.entry, call.err = entry, err
	if a.inflight[id] == call {
		delete(a.inflight, id)
	}
	a.running--
	a.mu.Unlock()
	close(call.done)
	call.cancel()
}

// errResolutionUnfinished is what a resolution's callers get when its
// goroutine ends without the resolution returning or panicking (see
// runResolution). Like resolutionPanicError, it wraps
// storage.ErrStoreUnavailable: the repository couldn't answer.
var errResolutionUnfinished = fmt.Errorf("federation: the client_id resolution ended without a result: %w", storage.ErrStoreUnavailable)

// resolutionPanicError is what every caller waiting on a resolution that
// panicked gets: the panic's value and the stack it was recovered on,
// for the log. It wraps storage.ErrStoreUnavailable, as
// ErrTooManyResolutions does, since the repository couldn't answer and
// that says nothing about the client_id: the server answers 500
// server_error, and the failure isn't remembered against the client_id,
// beyond what the resolution itself remembered before it panicked (see
// resolveUncached).
type resolutionPanicError struct {
	id    fapi.ClientID
	value any
	stack []byte
}

// newResolutionPanicError records value, recovered while resolving id,
// with the stack it was recovered on.
func newResolutionPanicError(id fapi.ClientID, value any) *resolutionPanicError {
	return &resolutionPanicError{id: id, value: value, stack: debug.Stack()}
}

// Error names the client_id and the panic's value, followed by the
// stack the panic was recovered on.
func (e *resolutionPanicError) Error() string {
	return fmt.Sprintf("federation: resolve client %s: the resolution panicked: %v\n\n%s", quoteEntityID(string(e.id)), e.value, e.stack)
}

// Unwrap returns storage.ErrStoreUnavailable.
func (e *resolutionPanicError) Unwrap() error { return storage.ErrStoreUnavailable }

// leaveResolution records that a caller waiting on call (id's
// resolution) has gone. When it was the last, the resolution is
// cancelled and forgotten, so the next request for id starts afresh;
// one that has already finished is left as it is.
func (a *AutomaticClientRepository) leaveResolution(id fapi.ClientID, call *inflightResolution) {
	a.mu.Lock()
	defer a.mu.Unlock()
	call.waiters--
	if call.waiters > 0 || a.inflight[id] != call {
		return
	}
	delete(a.inflight, id)
	call.cancel()
}

// resolveUncached resolves id's Trust Chain and builds its registration,
// caching a success and reporting a failure to
// AutomaticRegistrationConfig.OnResolutionFailure. resolve runs at most
// one at a time per client_id, as call.
func (a *AutomaticClientRepository) resolveUncached(ctx context.Context, id fapi.ClientID, call *inflightResolution) (cachedClient, error) {
	if err := ValidEntityID(string(id)); err != nil {
		// Not a federation client_id at all — an ordinary unknown
		// client, so nothing for OnResolutionFailure to report.
		return cachedClient{}, fmt.Errorf("federation: %s is not a registered client and not a valid federation entity ID: %w", quoteEntityID(string(id)), err)
	}
	entry, err := a.register(ctx, id)
	if err != nil {
		// A resolution abandoned by every caller waiting on it says
		// nothing about the client_id, so only one that ran its course
		// is reported and remembered — from when it failed, not when it
		// started, so a resolution slower than FailureCacheAge (an RP or
		// superior answering slowly is the RP's own choice) is still
		// remembered.
		if ctx.Err() != nil {
			return cachedClient{}, err
		}
		// Remembered before the hook runs, so a hook that panics (see
		// runResolution) still leaves the failure remembered. And
		// published on call, so a request for id while the hook runs,
		// the hook's own included, gets it at once rather than waiting
		// on call, which the hook would keep from finishing: memory
		// alone doesn't do that when it is full or the hook outlasts
		// FailureCacheAge.
		a.rememberFailure(id, err, a.clock.Now())
		a.publishFailure(call, err)
		if a.cfg.OnResolutionFailure != nil {
			a.cfg.OnResolutionFailure(ctx, id, err)
		}
		return cachedClient{}, err
	}
	a.rememberRegistration(id, entry, a.clock.Now())
	return entry, nil
}

// cacheRegistration caches entry as id's registration, within the
// limits registrationCache's doc comment sets out. a.mu must be held.
func (a *AutomaticClientRepository) cacheRegistration(id fapi.ClientID, entry cachedClient, now time.Time) {
	a.cache.put(id, entry, now)
}

// rememberRegistration caches entry as id's registration and forgets
// any failure remembered for id. It holds a.mu only while it updates
// both, and releases it by a deferred call, so a panic can't leave it
// held: the resolution's goroutine recovers one (see runResolution),
// and every later request would otherwise wait on a.mu for ever.
func (a *AutomaticClientRepository) rememberRegistration(id fapi.ClientID, entry cachedClient, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cacheRegistration(id, entry, now)
	delete(a.failures, id)
}

// publishFailure records err, bounded as rememberFailure bounds it, as
// the failure call has ended in, for the callers resolve answers from
// it while OnResolutionFailure runs.
func (a *AutomaticClientRepository) publishFailure(call *inflightResolution, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	call.failure = newRememberedFailure(err)
}

// rememberFailure records err as id's registration failure until
// FailureCacheAge after now, within maxFailedResolutions, keeping only
// its bounded message (see rememberedFailure) and its own copy of id
// (see startResolution).
func (a *AutomaticClientRepository) rememberFailure(id fapi.ClientID, err error, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.failures[id]; !ok && len(a.failures) >= maxFailedResolutions {
		a.dropExpiredFailures(now)
		if len(a.failures) >= maxFailedResolutions {
			return
		}
	}
	key := fapi.ClientID(strings.Clone(string(id)))
	a.failures[key] = failedResolution{err: newRememberedFailure(err), expiresAt: now.Add(a.cfg.FailureCacheAge)}
}

// register resolves the Entity Identifier id's Trust Chain and builds
// its registration from the resolved openid_relying_party metadata,
// cached for MaxCacheAge from when the registration was built.
func (a *AutomaticClientRepository) register(ctx context.Context, id fapi.ClientID) (cachedClient, error) {
	resolved, err := a.resolver.Resolve(ctx, string(id))
	if err != nil {
		return cachedClient{}, fmt.Errorf("federation: resolve client %s: %w", quoteEntityID(string(id)), err)
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

	// Building the registration can fetch (its jwks_uri), so the chain
	// can expire after Resolve has checked it: a registration whose
	// chain has expired by now is never handed out, not even to the
	// requests waiting on this resolution.
	now := a.clock.Now()
	if err := a.resolver.checkChainUnexpired(string(id), resolved.ExpiresAt, now); err != nil {
		return cachedClient{}, err
	}
	expiresAt := resolved.ExpiresAt
	if maxAge := now.Add(a.cfg.MaxCacheAge); maxAge.Before(expiresAt) {
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

	// Scope, GrantTypes and AuthorizationDetailsTypes are RFC 7591 §2's
	// scope and grant_types and RFC 9396 §10's
	// authorization_details_types, as the Trust Chain's metadata policy
	// left them. They never widen what AutomaticRegistrationConfig
	// grants, only narrow it (see narrowedScopes, grantTypePermitted and
	// narrowedAuthorizationDetailsTypes); nil means left out, while an
	// empty array, which a superior's subset_of or value can leave,
	// lists nothing. A scope or authorization_details_types left out
	// narrows nothing but what the policy permits it to hold (see
	// choiceLimits), and a grant_types left out means
	// authorization_code alone, so it lists no grant grantTypePermitted
	// is asked about.
	Scope                     *string  `json:"scope"`
	GrantTypes                []string `json:"grant_types"`
	AuthorizationDetailsTypes []string `json:"authorization_details_types"`
}

// cibaGrantType is the grant_types value for CIBA (OpenID Connect
// Client-Initiated Backchannel Authentication Flow - Core 1.0 §4).
const cibaGrantType = "urn:openid:params:grant-type:ciba"

// clientCredentialsGrantType is RFC 6749 §4.4's grant_types value.
const clientCredentialsGrantType = "client_credentials"

// narrowedScopes returns the operator's allowed scopes that the RP's
// resolved scope metadata also lists, or all of them when it has none,
// less any that permitted, what the Trust Chain's metadata policy lets
// scope hold (choiceLimits.scopes), doesn't allow either way. The
// resolved scope is the RP's own value after every superior's metadata
// policy (OpenID Federation 1.0 §6.1), so it is where the federation
// narrows what a member may ask for; but the policy's operators act only
// on a scope that is present, so permitted is what holds an RP leaving
// scope out to the policy too. It can never add a scope the operator
// didn't grant, and leaving none fails the registration.
func narrowedScopes(allowed []string, resolved *string, permitted *permittedValues) ([]string, error) {
	var listed []string
	if resolved != nil {
		listed = strings.Fields(*resolved)
	}
	var scopes []string
	for _, s := range allowed {
		if (resolved == nil || slices.Contains(listed, s)) && permitted.allows(s) {
			scopes = append(scopes, s)
		}
	}
	if len(scopes) == 0 {
		if resolved == nil {
			return nil, errors.New("the metadata policy on scope permits none of the allowed scopes")
		}
		return nil, fmt.Errorf("scope %q permits none of the allowed scopes", *resolved)
	}
	return scopes, nil
}

// grantTypePermitted reports whether the RP may be registered for grant,
// one beyond the authorization code flow: its resolved grant_types
// metadata lists grant, and permitted, what the Trust Chain's metadata
// policy lets grant_types hold (choiceLimits.grantTypes), allows it. An
// RP leaving grant_types out (nil) gets no such grant: OpenID Connect
// Dynamic Client Registration 1.0 §2 and RFC 7591 §2 have a client
// omitting grant_types use authorization_code alone. The policy's own
// operators have already held a grant_types that is present to what
// permitted allows; checking it again keeps a grant the policy withholds
// out however the parameter came to list it. Like narrowedScopes, it
// only ever narrows an operator's grant.
func grantTypePermitted(grantTypes []string, permitted *permittedValues, grant string) bool {
	return slices.Contains(grantTypes, grant) && permitted.allows(grant)
}

// narrowedAuthorizationDetailsTypes returns the operator's allowed Rich
// Authorization Request types that the RP's resolved
// authorization_details_types metadata also lists, or all of them when it
// is left out (nil), less any that permitted, what the Trust Chain's
// metadata policy lets authorization_details_types hold
// (choiceLimits.authorizationDetailsTypes), doesn't allow either way.
// Like narrowedScopes, it never adds a type the operator didn't allow,
// whatever the RP lists, but leaving none is no error: an RP may be
// registered for no type, as AutomaticRegistrationConfig's own list may
// be empty.
func narrowedAuthorizationDetailsTypes(allowed, resolved []string, permitted *permittedValues) []string {
	var types []string
	for _, typ := range allowed {
		if (resolved == nil || slices.Contains(resolved, typ)) && permitted.allows(typ) {
			types = append(types, typ)
		}
	}
	return types
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
// limits is what the Trust Chain's metadata policy permits for the
// parameters registration takes values of from somewhere the policy
// doesn't act on (see choiceLimits): the choices taken from
// token_endpoint_auth_methods_supported and
// token_endpoint_auth_signing_alg_values_supported, and the Rich
// Authorization Request types an RP leaving authorization_details_types
// out would otherwise get. It bounds the grants grant_types lists too.
//
// a.cfg supplies the operator-level capability grants (AllowedScopes,
// AuthorizationDetailsTypes, AllowedResources,
// AllowsClientCredentialsGrant, AllowsCIBA) that must never be inferred
// from raw itself, which can only narrow some of them (see
// applyGrants), plus the AllowedClientAuthMethods restriction raw's
// own token_endpoint_auth_method is checked against — see
// AutomaticRegistrationConfig's own doc comments for why.
func (a *AutomaticClientRepository) registeredClientConfigFromMetadata(ctx context.Context, id fapi.ClientID, raw json.RawMessage, limits choiceLimits) (storage.RegisteredClientConfig, json.RawMessage, error) {
	m, err := decodeRelyingPartyMetadata(raw)
	if err != nil {
		return storage.RegisteredClientConfig{}, nil, err
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

	requestObjectAlg, err := requestObjectAlgorithm(m)
	if err != nil {
		return storage.RegisteredClientConfig{}, nil, err
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
		AllowedResources:                a.cfg.AllowedResources,
		AutomaticFederationRegistration: true,
	}
	if err := a.applyGrants(&cfg, m, limits); err != nil {
		return storage.RegisteredClientConfig{}, nil, err
	}
	if err := a.applyDisplayAndSubjectType(&cfg, id, m, limits.subjectTypes); err != nil {
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

// decodeRelyingPartyMetadata parses raw, an openid_relying_party Resolved
// Metadata object, refusing one no registration can be built from: a
// member naming a parameter relyingPartyMetadata reads in another case
// (see strictjson), an empty string parameter (see refuseEmptyStrings),
// no redirect_uris, or anything but exactly one of jwks and jwks_uri.
func decodeRelyingPartyMetadata(raw json.RawMessage) (relyingPartyMetadata, error) {
	var m relyingPartyMetadata
	if err := strictjson.Unmarshal(raw, &m); err != nil {
		return relyingPartyMetadata{}, fmt.Errorf("parse %s metadata: %w", relyingPartyEntityType, err)
	}
	if err := refuseEmptyStrings(raw); err != nil {
		return relyingPartyMetadata{}, err
	}
	if len(m.RedirectURIs) == 0 {
		return relyingPartyMetadata{}, fmt.Errorf("%s metadata has no redirect_uris", relyingPartyEntityType)
	}
	if (len(m.JWKS) > 0) == (m.JWKSURI != "") {
		return relyingPartyMetadata{}, fmt.Errorf("%s metadata must declare exactly one of jwks or jwks_uri", relyingPartyEntityType)
	}
	return m, nil
}

// requestObjectAlgorithm is m's request_object_signing_alg, or zero when
// it names none.
func requestObjectAlgorithm(m relyingPartyMetadata) (fapi.SignatureAlgorithm, error) {
	if m.RequestObjectSigningAlg == "" {
		return 0, nil
	}
	alg, err := fapi.ParseSignatureAlgorithm(m.RequestObjectSigningAlg)
	if err != nil {
		return 0, fmt.Errorf("request_object_signing_alg: %w", err)
	}
	return alg, nil
}

// applyGrants sets what cfg's client may do beyond the authorization
// code flow, from AutomaticRegistrationConfig and never beyond it:
// AllowedScopes narrowed by the scope of m, the RP's resolved metadata,
// and limits.scopes;
// AuthorizationDetailsTypes by m's authorization_details_types and
// limits.authorizationDetailsTypes, which also bounds an RP leaving
// authorization_details_types out (see choiceLimits); and
// AllowsClientCredentialsGrant and AllowsCIBA (with the CIBA metadata
// that goes with it) by m's grant_types, which must list each (see
// grantTypePermitted), and limits.grantTypes.
func (a *AutomaticClientRepository) applyGrants(cfg *storage.RegisteredClientConfig, m relyingPartyMetadata, limits choiceLimits) error {
	scopes, err := narrowedScopes(a.cfg.AllowedScopes, m.Scope, limits.scopes)
	if err != nil {
		return err
	}
	cfg.AllowedScopes = scopes
	cfg.AuthorizationDetailsTypes = narrowedAuthorizationDetailsTypes(a.cfg.AuthorizationDetailsTypes, m.AuthorizationDetailsTypes, limits.authorizationDetailsTypes)
	cfg.AllowsClientCredentialsGrant = a.cfg.AllowsClientCredentialsGrant && grantTypePermitted(m.GrantTypes, limits.grantTypes, clientCredentialsGrantType)
	return a.applyBackchannelAuthenticationFields(cfg, m, limits.grantTypes)
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

// validateAllowedClientAuthMethods checks every
// AutomaticRegistrationConfig.AllowedClientAuthMethods entry is a valid
// method automatic registration can register.
func validateAllowedClientAuthMethods(methods []storage.ClientAuthMethod) error {
	for _, method := range methods {
		if !method.IsValid() {
			return fmt.Errorf("federation: config: allowed_client_auth_methods: invalid client auth method %v", method)
		}
		if method == storage.ClientAuthMethodAttestation {
			// A client authenticated by attestation is bound to a trusted
			// Attester (RegisteredClientConfig.ExpectedAttesterIssuer), a
			// capability grant no RP metadata can make, so no RP could
			// ever register with it.
			return fmt.Errorf("federation: config: allowed_client_auth_methods: %v can't be registered automatically: its attester is an operator's grant, not RP metadata", method)
		}
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
		return nil, fmt.Errorf("none of token_endpoint_auth_methods_supported %q is supported and permitted by allowed_client_auth_methods and the metadata policy", list)
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
		return nil, fmt.Errorf("none of token_endpoint_auth_signing_alg_values_supported %q is supported and permitted by the metadata policy", list)
	}
	return algs, nil
}

// choiceLimits is what a Trust Chain's metadata policy permits for the
// parameters automatic registration takes values of from somewhere the
// policy doesn't act on. Policy operators act on the parameter they name
// only (OpenID Federation 1.0 §6.1.3.1), and then only "if the metadata
// parameter is present" (§6.1.3.1.4, §6.1.3.1.5), so without these:
//
//   - an RP leaving out token_endpoint_auth_signing_alg under a one_of
//     on it, and declaring its OpenID Connect RP Metadata Choices 1.0 §2
//     plural sibling token_endpoint_auth_signing_alg_values_supported
//     instead, would register a value the policy forbids, and likewise
//     for token_endpoint_auth_method;
//   - an RP leaving out authorization_details_types under a subset_of or
//     one_of on it would keep it absent, which registration reads as every type
//     the operator allows, so the policy would withhold nothing, and
//     likewise for scope (every AllowedScopes) under a subset_of or
//     one_of on it;
//   - an RP leaving out subject_type under a one_of on it would get
//     DefaultSubjectType, a kind of sub the policy may forbid.
//
// An RP leaving out grant_types is registered for no grant beyond the
// authorization code flow, whatever the policy (see grantTypePermitted),
// so grantTypes, read the same way (subset_of, value and one_of), bounds
// only the grants a grant_types that is present lists, which the
// policy's operators have already bounded too.
//
// Each nil field means no policy restricts that parameter.
type choiceLimits struct {
	authMethods               *permittedValues // token_endpoint_auth_method
	signingAlgs               *permittedValues // token_endpoint_auth_signing_alg
	grantTypes                *permittedValues // grant_types' values
	authorizationDetailsTypes *permittedValues // authorization_details_types' values
	scopes                    *permittedValues // scope's values
	subjectTypes              *permittedValues // subject_type
}

// permittedValues is the set of values a metadata policy allows a
// singular parameter, or an array parameter's elements; a nil
// *permittedValues allows any value.
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
		param     string
		permitted func(intfed.PolicyOperators) ([]string, bool, error)
		dst       **permittedValues
	}{
		{"token_endpoint_auth_method", intfed.PermittedStrings, &limits.authMethods},
		{"token_endpoint_auth_signing_alg", intfed.PermittedStrings, &limits.signingAlgs},
		{"grant_types", intfed.PermittedArrayStrings, &limits.grantTypes},
		{"authorization_details_types", intfed.PermittedArrayStrings, &limits.authorizationDetailsTypes},
		{"scope", intfed.PermittedSpaceDelimitedStrings, &limits.scopes},
		{"subject_type", intfed.PermittedStrings, &limits.subjectTypes},
	} {
		permitted, constrained, err := field.permitted(policy[field.param])
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
// when this repository allows CIBA, m actually advertises it, and the
// CIBA grant is permitted by m's grant_types and permittedGrants, what
// the metadata policy lets grant_types hold (see grantTypePermitted) —
// a no-op otherwise. An RP getting CIBA must name its
// backchannel_token_delivery_mode, REQUIRED by CIBA Core 1.0 §4: one
// that doesn't is refused, like one naming ping without the
// notification endpoint ping needs (which storage.NewRegisteredClient
// refuses), rather than registered for a mode it never chose. Split out
// of registeredClientConfigFromMetadata for the same reason
// applyClientAuthMethodFields is.
func (a *AutomaticClientRepository) applyBackchannelAuthenticationFields(cfg *storage.RegisteredClientConfig, m relyingPartyMetadata, permittedGrants *permittedValues) error {
	if !a.cfg.AllowsCIBA || m.BackchannelAuthenticationRequestSigningAlg == "" || !grantTypePermitted(m.GrantTypes, permittedGrants, cibaGrantType) {
		return nil
	}
	alg, err := fapi.ParseSignatureAlgorithm(m.BackchannelAuthenticationRequestSigningAlg)
	if err != nil {
		return fmt.Errorf("backchannel_authentication_request_signing_alg: %w", err)
	}
	cfg.BackchannelAuthenticationRequestAlgorithm = alg

	if m.BackchannelTokenDeliveryMode == "" {
		return errors.New("backchannel_token_delivery_mode is required to register for CIBA")
	}
	mode, err := storage.ParseBackchannelTokenDeliveryMode(m.BackchannelTokenDeliveryMode)
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
//
// RFC 7517 §4.7 says the key in that first certificate "MUST match the
// public key represented by other members of the JWK". An entry whose
// certificate doesn't parse, or holds a different key, contributes no
// thumbprint, and is named among the skipped entries when none is
// left: the certificate registered is always one for a key in the RP
// JWK Set, never one the entry merely carries.
func certificateThumbprintsFromJWKS(jwks json.RawMessage) ([]string, error) {
	candidates, skipped, err := jose.ParseJWKSetWithSkips(jwks)
	if err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	var thumbprints []string
	for _, c := range candidates {
		if len(c.Certificates) == 0 {
			continue
		}
		cert, err := entryCertificate(c)
		if err != nil {
			skipped = append(skipped, jose.SkippedJWK{KeyID: c.KeyID, Reason: err})
			continue
		}
		if t := mtls.Thumbprint(cert); !slices.Contains(thumbprints, t) {
			thumbprints = append(thumbprints, t)
		}
	}
	if len(thumbprints) == 0 {
		return nil, fmt.Errorf("jwks has no usable x5c certificate%s", jose.SkippedKeysReason(skipped))
	}
	return thumbprints, nil
}

// entryCertificate parses c's first "x5c" certificate, refusing one
// whose public key isn't c's own key (RFC 7517 §4.7).
func entryCertificate(c jose.ParsedJWK) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(c.Certificates[0])
	if err != nil {
		return nil, fmt.Errorf("its x5c certificate doesn't parse: %w", err)
	}
	pub, ok := c.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return nil, errors.New("its x5c certificate holds a different key from the JWK's own (RFC 7517 §4.7)")
	}
	return cert, nil
}

// keyThumbprintsFromJWKS is internal/mtls.PublicKeyThumbprint of every
// key in jwks, the keys a CA-issued certificate must carry one of.
func keyThumbprintsFromJWKS(jwks json.RawMessage) ([]string, error) {
	candidates, skipped, err := jose.ParseJWKSetWithSkips(jwks)
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
		return nil, fmt.Errorf("the RP JWK Set has no usable key for the certificate to carry (OpenID Federation 1.0 §12.1.1.2)%s", jose.SkippedKeysReason(skipped))
	}
	return thumbprints, nil
}

// applyDisplayAndSubjectType sets cfg's Display and SubjectType from m:
// what a consent screen shows about the client, and the kind of sub its
// end users get, within permitted (see subjectTypeFromMetadata).
func (a *AutomaticClientRepository) applyDisplayAndSubjectType(cfg *storage.RegisteredClientConfig, id fapi.ClientID, m relyingPartyMetadata, permitted *permittedValues) error {
	display, err := clientDisplayFromMetadata(m)
	if err != nil {
		return err
	}
	subjectType, err := a.subjectTypeFromMetadata(m, permitted)
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

// defaultSubjectType is the subject type an RP naming none gets:
// DefaultSubjectType (public when zero) if permitted allows it, else the
// first of the OP's subject types that permitted does.
func (a *AutomaticClientRepository) defaultSubjectType(permitted *permittedValues) (fapi.SubjectType, error) {
	def := a.cfg.DefaultSubjectType
	if def == 0 {
		def = fapi.SubjectTypePublic
	}
	for _, t := range append([]fapi.SubjectType{def}, effectiveSubjectTypes(a.cfg.SubjectTypes)...) {
		if permitted.allows(t.String()) {
			return t, nil
		}
	}
	return 0, errors.New("the metadata policy on subject_type permits none of the subject types this OP issues")
}

// effectiveSubjectTypes is types, or public alone when it is empty.
func effectiveSubjectTypes(types []fapi.SubjectType) []fapi.SubjectType {
	if len(types) == 0 {
		return []fapi.SubjectType{fapi.SubjectTypePublic}
	}
	return types
}

// subjectTypeFromMetadata returns the subject type an automatically
// registered client gets: its metadata's subject_type, or, when it names
// none, DefaultSubjectType if permitted (what the Trust Chain's metadata
// policy lets subject_type be, choiceLimits.subjectTypes) allows it, else
// the first of SubjectTypes that permitted does. A policy's one_of acts
// only on a subject_type that is present (OpenID Federation 1.0
// §6.1.3.1.4), so without this an RP leaving it out would get a default
// the policy forbids; when no type this OP issues is permitted, the
// registration fails. It's recorded on the client rather than left to the
// server's default, so the decision made here, against this OP's
// SubjectTypes, is the one every grant uses.
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
func (a *AutomaticClientRepository) subjectTypeFromMetadata(m relyingPartyMetadata, permitted *permittedValues) (fapi.SubjectType, error) {
	subjectType, err := a.defaultSubjectType(permitted)
	if m.SubjectType != "" {
		subjectType, err = fapi.ParseSubjectType(m.SubjectType)
		if err != nil {
			err = fmt.Errorf("subject_type: %w", err)
		}
	}
	if err != nil {
		return 0, err
	}
	if !slices.Contains(effectiveSubjectTypes(a.cfg.SubjectTypes), subjectType) {
		return 0, fmt.Errorf("subject_type %s is not one this OP issues", subjectType)
	}
	if subjectType == fapi.SubjectTypePairwise && m.SectorIdentifierURI != "" {
		return 0, errors.New("sector_identifier_uri is not supported with pairwise subject identifiers")
	}
	return subjectType, nil
}
