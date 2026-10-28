package keys

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
)

// defaultClientJWKSCacheTTL is how long ClientJWKSSource trusts a
// client's fetched JWK Set before fetching it again, unless
// WithClientJWKSCacheTTL overrides it.
const defaultClientJWKSCacheTTL = 5 * time.Minute

// defaultClientJWKSMaxClients bounds how many clients' key sets
// ClientJWKSSource keeps at once, unless WithClientJWKSMaxClients
// overrides it.
const defaultClientJWKSMaxClients = 10000

// ClientJWKSLookup returns a registered client's key registration: its
// jwks_uri, or its inline "jwks" JWK Set document (RFC 7591 §2 forbids
// registering both). It must return an error for a client ID that
// isn't registered. A client registered with neither (one that signs
// nothing, such as a client authenticating with a TLS client
// certificate) returns a zero URL and nil inline, and has no keys.
//
// It is called on every resolution, so it should be the application's
// client registry lookup (typically already cached); that is how a
// client whose registered jwks_uri or jwks changes stops being served
// the old one's keys at once.
type ClientJWKSLookup func(ctx context.Context, id fapi.ClientID) (jwksURI fapi.URL, inline []byte, err error)

// ClientJWKSSource is a ClientKeySource and ClientEncryptionKeySource
// that resolves each client's keys from its registration, as
// ClientJWKSLookup reports it: an inline JWK Set is parsed once and
// kept, and a jwks_uri is fetched live through a fapihttp.Client and
// cached per client, with the same stale-key handling as
// JWKSIssuerKeySource — a fresh set is served for the cache TTL, a kid
// the cached set lacks (the client may have rotated keys) forces at
// most one refetch of that client's set per minimum refresh interval,
// concurrent fetches of one client's set are single-flighted, and a
// failed fetch isn't retried before the refresh backoff.
//
// Each cached set belongs to one client and the registration it came
// from: a kid is only ever looked up within the requesting client's
// own set, so a kid another client publishes never resolves for this
// one, and a client whose registered jwks_uri (or jwks) changes is
// never served the old registration's keys. A client ClientJWKSLookup
// doesn't know is an error. A client's keys are held to the limits of
// a key a caller supplies (an RSA key over 4096 bits is skipped), and a
// JWK Set with no usable key is an error.
//
// Per ARCHITECTURE.md design rule 5, prefer StaticClientKeys, with no
// fetch in the request path, where a deployment can register its
// clients' keys up front.
type ClientJWKSSource struct {
	fetcher    *fapihttp.Client
	lookup     ClientJWKSLookup
	timing     jwksCacheTiming
	maxClients int
	now        func() time.Time

	mu      sync.Mutex
	entries map[fapi.ClientID]*clientJWKSEntry
}

// clientJWKSEntry is one client's keys from one registration: parsed
// from its inline JWK Set (static), or fetched from its jwks_uri and
// cached (cache).
type clientJWKSEntry struct {
	origin string // the registration it came from: its jwks_uri, or its inline jwks' digest
	static *clientKeySet
	cache  *jwksCache[clientKeySet]
}

// ClientJWKSOption configures a ClientJWKSSource.
type ClientJWKSOption func(*ClientJWKSSource)

// WithClientJWKSCacheTTL overrides how long a client's fetched JWK Set
// is trusted before it is fetched again. Defaults to 5 minutes;
// NewClientJWKSSource refuses a zero or negative duration.
func WithClientJWKSCacheTTL(d time.Duration) ClientJWKSOption {
	return func(s *ClientJWKSSource) { s.timing.cacheTTL = d }
}

// WithClientJWKSMinRefreshInterval bounds how often a request naming a
// kid a client's cached set lacks may force a refetch of that client's
// set, as WithMinRefreshInterval does for JWKSIssuerKeySource. Defaults
// to the cache TTL; a zero or negative duration means that default.
func WithClientJWKSMinRefreshInterval(d time.Duration) ClientJWKSOption {
	return func(s *ClientJWKSSource) { s.timing.minRefreshInterval = d }
}

// WithClientJWKSRefreshBackoff bounds how soon a failed fetch of a
// client's set is retried, as WithRefreshBackoff does for
// JWKSIssuerKeySource. Defaults to min(cache TTL, 5s); a zero or
// negative duration means that default.
func WithClientJWKSRefreshBackoff(d time.Duration) ClientJWKSOption {
	return func(s *ClientJWKSSource) { s.timing.refreshBackoff = d }
}

// WithClientJWKSMaxClients bounds how many clients' key sets are kept
// at once. When the bound is reached, expired sets are dropped first,
// then an arbitrary one; a dropped set is simply fetched (or parsed)
// again when next needed. Defaults to 10000; NewClientJWKSSource
// refuses a zero or negative bound.
func WithClientJWKSMaxClients(n int) ClientJWKSOption {
	return func(s *ClientJWKSSource) { s.maxClients = n }
}

// NewClientJWKSSource returns a ClientJWKSSource resolving clients'
// registrations through lookup and fetching jwks_uris through fetcher.
// fetcher may be nil when every client registers an inline JWK Set: a
// client whose lookup then returns a jwks_uri is an error at
// resolution.
func NewClientJWKSSource(fetcher *fapihttp.Client, lookup ClientJWKSLookup, opts ...ClientJWKSOption) (*ClientJWKSSource, error) {
	if lookup == nil {
		return nil, fmt.Errorf("keys: NewClientJWKSSource: lookup is required")
	}
	s := &ClientJWKSSource{
		fetcher:    fetcher,
		lookup:     lookup,
		timing:     jwksCacheTiming{cacheTTL: defaultClientJWKSCacheTTL},
		maxClients: defaultClientJWKSMaxClients,
		now:        time.Now,
		entries:    make(map[fapi.ClientID]*clientJWKSEntry),
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.timing.cacheTTL <= 0 {
		return nil, fmt.Errorf("keys: NewClientJWKSSource: cache TTL must be positive")
	}
	if s.maxClients <= 0 {
		return nil, fmt.Errorf("keys: NewClientJWKSSource: max clients must be positive")
	}
	s.timing = s.timing.withDefaults()
	return s, nil
}

// Capabilities implements KeySourceAssurance. It declares
// LiveFetchHardened when fetcher is fapihttp.Client.HardenedForProduction
// (see JWKSIssuerKeySource.Capabilities), or when there is no fetcher,
// so nothing is ever fetched.
func (s *ClientJWKSSource) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: s.fetcher == nil || s.fetcher.HardenedForProduction()}
}

// ResolveVerificationKeys implements ClientKeySource: req.ClientID's own
// keys for req.Algorithm (and req.KeyID, if set). A KeyID the client's
// cached set lacks forces one refetch of that set, rate-limited as the
// type's doc comment describes.
func (s *ClientJWKSSource) ResolveVerificationKeys(ctx context.Context, req ClientKeyRequest) (VerificationKeySet, error) {
	matched, err := resolveClientJWKS(ctx, s, req.ClientID, req.KeyID, func(set clientKeySet) []VerificationKey {
		return matchVerificationKeys(set, req.Algorithm, req.KeyID)
	})
	if err != nil {
		return VerificationKeySet{}, err
	}
	return VerificationKeySet{Keys: matched}, nil
}

// ResolveEncryptionKeys implements ClientEncryptionKeySource:
// req.ClientID's own encryption keys for req.Algorithm (and req.KeyID,
// if set). As with StaticClientKeys, req.Purpose doesn't narrow the
// result.
func (s *ClientJWKSSource) ResolveEncryptionKeys(ctx context.Context, req ClientEncryptionKeyRequest) (ClientEncryptionKeySet, error) {
	matched, err := resolveClientJWKS(ctx, s, req.ClientID, req.KeyID, func(set clientKeySet) []ClientEncryptionKey {
		return matchEncryptionKeys(set, req.Algorithm, req.KeyID)
	})
	if err != nil {
		return ClientEncryptionKeySet{}, err
	}
	return ClientEncryptionKeySet{Keys: matched}, nil
}

// resolveClientJWKS is match's keys from id's current set.
func resolveClientJWKS[K any](ctx context.Context, s *ClientJWKSSource, id fapi.ClientID, kid string, match func(clientKeySet) []K) ([]K, error) {
	entry, err := s.entry(ctx, id)
	if err != nil {
		return nil, err
	}
	if entry.cache == nil {
		return match(*entry.static), nil
	}
	matched, err := resolveFromJWKSCache(ctx, entry.cache, kid, match)
	if err != nil {
		return nil, fmt.Errorf("keys: ClientJWKSSource: client %q: %w", id, err)
	}
	return matched, nil
}

// entry is id's entry for its current registration: the one kept, if
// it came from that same registration, or a new one replacing it.
func (s *ClientJWKSSource) entry(ctx context.Context, id fapi.ClientID) (*clientJWKSEntry, error) {
	jwksURI, inline, err := s.lookup(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("keys: ClientJWKSSource: client %q: %w", id, err)
	}
	origin, err := registrationOrigin(jwksURI, inline)
	if err != nil {
		return nil, fmt.Errorf("keys: ClientJWKSSource: client %q: %w", id, err)
	}
	if origin == "" {
		return &clientJWKSEntry{static: &clientKeySet{}}, nil // no keys registered
	}

	s.mu.Lock()
	kept, ok := s.entries[id]
	s.mu.Unlock()
	if ok && kept.origin == origin {
		return kept, nil
	}

	fresh, err := s.newEntry(origin, jwksURI, inline)
	if err != nil {
		return nil, fmt.Errorf("keys: ClientJWKSSource: client %q: %w", id, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if kept, ok := s.entries[id]; ok && kept.origin == origin {
		return kept, nil // another caller got here first
	}
	s.makeRoomLocked(id)
	s.entries[id] = fresh
	return fresh, nil
}

// registrationOrigin identifies a client's key registration — its
// jwks_uri, or its inline JWK Set's digest — so a cached set is only
// ever served for the registration it came from. Registering both is
// an error (RFC 7591 §2), and registering neither is "".
func registrationOrigin(jwksURI fapi.URL, inline []byte) (string, error) {
	switch {
	case !jwksURI.IsZero() && len(inline) > 0:
		return "", fmt.Errorf("registers both jwks_uri and jwks")
	case !jwksURI.IsZero():
		return "jwks_uri " + jwksURI.String(), nil
	case len(inline) > 0:
		digest := sha256.Sum256(inline)
		return "jwks " + hex.EncodeToString(digest[:]), nil
	default:
		return "", nil
	}
}

// newEntry builds the entry for one registration: inline's parsed keys,
// or a cache fetching jwksURI.
func (s *ClientJWKSSource) newEntry(origin string, jwksURI fapi.URL, inline []byte) (*clientJWKSEntry, error) {
	if len(inline) > 0 {
		set, err := parseClientJWKS(inline)
		if err != nil {
			return nil, fmt.Errorf("parse jwks: %w", err)
		}
		return &clientJWKSEntry{origin: origin, static: &set}, nil
	}
	if s.fetcher == nil {
		return nil, fmt.Errorf("registers a jwks_uri, but the source has no fetcher")
	}
	u := jwksURI.URL()
	fetch := func(ctx context.Context) (clientKeySet, error) { return s.fetch(ctx, &u) }
	// now is read through s, so a test may still swap s.now after New.
	cache := newJWKSCache(s.timing, func() time.Time { return s.now() }, fetch)
	return &clientJWKSEntry{origin: origin, cache: cache}, nil
}

// makeRoomLocked drops entries, other than id's, until there is room
// for one more: expired ones first, then arbitrary ones. s.mu must be
// held.
func (s *ClientJWKSSource) makeRoomLocked(id fapi.ClientID) {
	if len(s.entries) < s.maxClients {
		return
	}
	for other, e := range s.entries {
		if other != id && (e.cache == nil || e.cache.isExpired()) {
			delete(s.entries, other)
		}
	}
	for other := range s.entries {
		if len(s.entries) < s.maxClients {
			return
		}
		if other != id {
			delete(s.entries, other)
		}
	}
}

// fetch fetches and parses a client's JWK Set from jwksURI.
func (s *ClientJWKSSource) fetch(ctx context.Context, jwksURI *url.URL) (clientKeySet, error) {
	res, err := s.fetcher.Fetch(ctx, fapihttp.FetchRequest{
		URL:                   jwksURI,
		ExpectedContentType:   jwksContentType,
		AlternateContentTypes: []string{jwksAlternateContentType},
	})
	if err != nil {
		return clientKeySet{}, fmt.Errorf("fetch jwks: %w", err)
	}
	set, err := parseClientJWKS(res.Body)
	if err != nil {
		return clientKeySet{}, fmt.Errorf("parse jwks: %w", err)
	}
	return set, nil
}
