package ephemeral

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/keys"
)

// defaultClientJWKSCacheTTL bounds how long a fetched client JWKS is
// trusted before ClientKeySource re-fetches it, unless overridden via
// WithCacheTTL.
const defaultClientJWKSCacheTTL = 5 * time.Minute

// ClientKeySpec is one registered client's key material —
// either an inline static JWKS or a JWKS URI to fetch live. Deliberately
// carries only what ClientKeySource needs (not a storage.RegisteredClient
// or anything client-repository-shaped): whether a client is registered
// at all is storage's concern, not this one's.
type ClientKeySpec struct {
	ClientID fapi.ClientID

	// JWKS is an inline, already-known JWK Set. Takes priority over
	// JWKSURI when both are set.
	JWKS []byte

	// JWKSURI is fetched live (and cached) when JWKS is empty.
	JWKSURI string
}

// Option configures a ClientKeySource.
type Option func(*ClientKeySource)

// WithCacheTTL overrides how long a fetched client JWKS is trusted
// before being re-fetched. Defaults to 5 minutes; NewClientKeySource
// refuses a zero or negative duration.
func WithCacheTTL(d time.Duration) Option {
	return func(s *ClientKeySource) { s.cacheTTL = d }
}

// WithMinRefreshInterval bounds how often a request naming a kid the
// cached JWKS doesn't have may force a live refetch of that client's
// JWKS. Defaults to the cache TTL, as keys.JWKSIssuerKeySource's own
// option does: a rotated key is still picked up within one TTL, while a
// caller sending distinct unknown kids (taken from an unverified JWT
// header, so attacker-controlled) forces at most one fetch per client
// per interval. A zero or negative duration means that default.
func WithMinRefreshInterval(d time.Duration) Option {
	return func(s *ClientKeySource) { s.minRefreshInterval = d }
}

// refreshBackoff bounds how soon a failed fetch of a client's JWKS is
// retried, so requests against a failing jwks_uri don't each issue an
// outbound fetch: min(cache TTL, 5s), keys.JWKSIssuerKeySource's own
// default.
func (s *ClientKeySource) refreshBackoff() time.Duration {
	return min(s.cacheTTL, 5*time.Second)
}

// clientKeys is one client's keys from its JWK Set: those that verify
// its signatures and those to encrypt to it.
type clientKeys struct {
	verification []keys.VerificationKey
	encryption   []keys.ClientEncryptionKey
}

// clientKeyEntry is one registered client's key source: either a fixed,
// already-parsed static set (no I/O, no cache) or a remote JWKS URL
// fetched and cached live.
type clientKeyEntry struct {
	static  clientKeys // zero if this client's keys are fetched instead, or it has none
	jwksURL *url.URL   // nil unless this client's keys are fetched

	mu          sync.Mutex
	cached      *clientKeys
	cachedAt    time.Time
	lastAttempt time.Time // the last fetch, successful or not
	lastErr     error     // the last fetch's error, nil if it succeeded

	// fetchMu serializes fetches, so concurrent callers that all need
	// one wait for the first instead of each fetching.
	fetchMu sync.Mutex
}

// ClientKeySource resolves each registered client's keys — those that
// verify its signatures (keys.ClientKeySource) and those to encrypt ID
// tokens and UserInfo responses to (keys.ClientEncryptionKeySource) —
// either from an inline static JWKS or by fetching one live via
// fapihttp.Client — which already applies the SSRF/size-limit/
// content-type hardening ARCHITECTURE.md design rule 6 requires for
// exactly this case, so this type reuses it rather than issuing its own
// HTTP requests. See the package doc comment for why this is
// development/testing only.
type ClientKeySource struct {
	fetcher            *fapihttp.Client
	cacheTTL           time.Duration
	minRefreshInterval time.Duration
	now                func() time.Time
	clients            map[fapi.ClientID]*clientKeyEntry
}

// NewClientKeySource builds a ClientKeySource from specs, parsing every
// inline static JWKS up front so a malformed one fails at construction
// rather than on the first request that needs it.
//
// A spec with neither JWKS nor JWKSURI is a client with no verification
// keys — one that does no JWS signing, e.g. one authenticating with a
// TLS client certificate: its lookups return an empty set, and nothing
// is fetched for it.
//
// fetcher may be nil unless some spec relies on its JWKSURI; such a spec
// fails construction without one, rather than at that client's first
// request. So does a spec with no ClientID, a ClientID already used by
// an earlier spec, or a JWKSURI that isn't an absolute URL.
func NewClientKeySource(fetcher *fapihttp.Client, specs []ClientKeySpec, opts ...Option) (*ClientKeySource, error) {
	s := &ClientKeySource{
		fetcher:  fetcher,
		cacheTTL: defaultClientJWKSCacheTTL,
		now:      time.Now,
		clients:  make(map[fapi.ClientID]*clientKeyEntry, len(specs)),
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.cacheTTL <= 0 {
		return nil, fmt.Errorf("ephemeral: cache TTL must be positive")
	}
	if s.minRefreshInterval <= 0 {
		s.minRefreshInterval = s.cacheTTL
	}
	for _, spec := range specs {
		if spec.ClientID == "" {
			return nil, fmt.Errorf("ephemeral: client key spec has no client ID")
		}
		if _, dup := s.clients[spec.ClientID]; dup {
			return nil, fmt.Errorf("ephemeral: client %q has more than one key spec", spec.ClientID)
		}
		entry, err := newClientKeyEntry(spec, fetcher != nil)
		if err != nil {
			return nil, fmt.Errorf("ephemeral: client %q: %w", spec.ClientID, err)
		}
		s.clients[spec.ClientID] = entry
	}
	return s, nil
}

// newClientKeyEntry builds spec's entry: its parsed inline JWKS, its
// JWKS URI to fetch (which needs a fetcher), or no keys at all.
func newClientKeyEntry(spec ClientKeySpec, haveFetcher bool) (*clientKeyEntry, error) {
	if len(spec.JWKS) > 0 {
		parsed, err := parseClientKeys(spec.JWKS)
		if err != nil {
			return nil, fmt.Errorf("parse inline jwks: %w", err)
		}
		return &clientKeyEntry{static: parsed}, nil
	}
	if spec.JWKSURI == "" {
		return &clientKeyEntry{}, nil // no keys
	}
	u, err := url.Parse(spec.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("parse jwks_uri: %w", err)
	}
	if !u.IsAbs() || u.Host == "" {
		return nil, fmt.Errorf("jwks_uri %q is not an absolute URL", spec.JWKSURI)
	}
	if !haveFetcher {
		return nil, fmt.Errorf("jwks_uri needs a fetcher, and none was given")
	}
	return &clientKeyEntry{jwksURL: u}, nil
}

// ResolveVerificationKeys implements keys.ClientKeySource.
func (s *ClientKeySource) ResolveVerificationKeys(ctx context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	entry, ok := s.clients[req.ClientID]
	if !ok {
		return keys.VerificationKeySet{}, fmt.Errorf("ephemeral: unknown client %q", req.ClientID)
	}

	current, err := s.current(ctx, entry, req.KeyID, func(k clientKeys) []string { return verificationKeyIDs(k.verification) })
	if err != nil {
		return keys.VerificationKeySet{}, err
	}

	var matched []keys.VerificationKey
	for _, k := range current.verification {
		if k.Algorithm != req.Algorithm {
			continue
		}
		if req.KeyID != "" && k.KeyID != req.KeyID {
			continue
		}
		matched = append(matched, k)
	}
	return keys.VerificationKeySet{Keys: matched}, nil
}

// ResolveEncryptionKeys implements keys.ClientEncryptionKeySource: the
// client's JWK Set entries for req.Algorithm (and req.KeyID, if set) —
// "use":"enc" keys, or ones whose "alg" is a key management algorithm.
// A JWK Set doesn't say whether a key is for ID tokens or UserInfo
// responses, so req.Purpose doesn't narrow the result: a client
// registering for both with the same algorithm should publish one key
// for it, since the server encrypts to the first one returned.
func (s *ClientKeySource) ResolveEncryptionKeys(ctx context.Context, req keys.ClientEncryptionKeyRequest) (keys.ClientEncryptionKeySet, error) {
	entry, ok := s.clients[req.ClientID]
	if !ok {
		return keys.ClientEncryptionKeySet{}, fmt.Errorf("ephemeral: unknown client %q", req.ClientID)
	}
	current, err := s.current(ctx, entry, req.KeyID, func(k clientKeys) []string { return encryptionKeyIDs(k.encryption) })
	if err != nil {
		return keys.ClientEncryptionKeySet{}, err
	}
	var matched []keys.ClientEncryptionKey
	for _, k := range current.encryption {
		if k.Algorithm != req.Algorithm {
			continue
		}
		if req.KeyID != "" && k.KeyID != req.KeyID {
			continue
		}
		matched = append(matched, k)
	}
	return keys.ClientEncryptionKeySet{Keys: matched}, nil
}

// current is entry's keys: its static set, or its fetched set — cached
// while fresh, refetched once stale, with the same stale-key handling
// keys.JWKSIssuerKeySource applies: a fresh set without wantKeyID (a
// client that may have rotated keys since the last fetch) is refetched
// too, but at most once per minRefreshInterval, since wantKeyID comes
// from an unverified JWT header. Fetches are serialized per client, and
// a failed one isn't retried for refreshBackoff — its error is
// returned instead, or the cached set while it is still fresh.
func (s *ClientKeySource) current(ctx context.Context, entry *clientKeyEntry, wantKeyID string, kids func(clientKeys) []string) (clientKeys, error) {
	if entry.jwksURL == nil {
		return entry.static, nil
	}
	if keys, done, err := s.cachedOrRateLimited(entry, wantKeyID, kids); done {
		return keys, err
	}
	entry.fetchMu.Lock()
	defer entry.fetchMu.Unlock()
	// Another caller may have fetched while this one waited.
	if keys, done, err := s.cachedOrRateLimited(entry, wantKeyID, kids); done {
		return keys, err
	}
	return s.refetch(ctx, entry)
}

// cachedOrRateLimited reports (done=true) the answer current gives
// without fetching: the cached set when it is fresh and has wantKeyID
// (or none was asked for), or when a fetch for a missing kid isn't
// allowed yet; the last fetch's error while it is within
// refreshBackoff. done=false means current should fetch now.
func (s *ClientKeySource) cachedOrRateLimited(entry *clientKeyEntry, wantKeyID string, kids func(clientKeys) []string) (clientKeys, bool, error) {
	entry.mu.Lock()
	defer entry.mu.Unlock()
	now := s.now()
	fresh := entry.cached != nil && now.Sub(entry.cachedAt) < s.cacheTTL
	if fresh && (wantKeyID == "" || slices.Contains(kids(*entry.cached), wantKeyID)) {
		return *entry.cached, true, nil
	}
	sinceAttempt := now.Sub(entry.lastAttempt)
	if entry.lastErr != nil && !entry.lastAttempt.IsZero() && sinceAttempt < s.refreshBackoff() {
		if fresh {
			return *entry.cached, true, nil
		}
		return clientKeys{}, true, entry.lastErr
	}
	if fresh && sinceAttempt < s.minRefreshInterval {
		return *entry.cached, true, nil
	}
	return clientKeys{}, false, nil
}

// refetch fetches entry's JWKS and records the outcome for every caller
// of that client. The fetch is detached from ctx's cancellation, as
// keys.JWKSIssuerKeySource's is: fapihttp.Client.Fetch applies its own
// RequestTimeout, so it still can't hang, but one caller giving up (a
// client disconnecting mid-request) can't be recorded as the client's
// fetch failure and refuse everyone else's requests for refreshBackoff.
// The caller still gets its own ctx's error once the fetch is done.
func (s *ClientKeySource) refetch(ctx context.Context, entry *clientKeyEntry) (clientKeys, error) {
	parsed, err := s.fetch(context.WithoutCancel(ctx), entry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	entry.lastAttempt = s.now()
	entry.lastErr = err
	if err != nil {
		return clientKeys{}, err
	}
	entry.cached = &parsed
	entry.cachedAt = entry.lastAttempt
	if ctxErr := ctx.Err(); ctxErr != nil {
		return clientKeys{}, ctxErr
	}
	return parsed, nil
}

func (s *ClientKeySource) fetch(ctx context.Context, entry *clientKeyEntry) (clientKeys, error) {
	res, err := s.fetcher.Fetch(ctx, fapihttp.FetchRequest{
		URL:                   entry.jwksURL,
		ExpectedContentType:   "application/json",
		AlternateContentTypes: []string{"application/jwk-set+json"},
	})
	if err != nil {
		return clientKeys{}, fmt.Errorf("ephemeral: fetch client jwks: %w", err)
	}
	parsed, err := parseClientKeys(res.Body)
	if err != nil {
		return clientKeys{}, fmt.Errorf("ephemeral: parse client jwks: %w", err)
	}
	return parsed, nil
}

func verificationKeyIDs(ks []keys.VerificationKey) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = k.KeyID
	}
	return out
}

func encryptionKeyIDs(ks []keys.ClientEncryptionKey) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = k.KeyID
	}
	return out
}

// parseClientKeys parses a JWK Set's verification keys (via the shared
// internal/jose.ParseJWKSet) and encryption keys (via
// internal/jose.ParseEncryptionJWKSet) into this package's keys types.
func parseClientKeys(body []byte) (clientKeys, error) {
	verification, err := jose.ParseJWKSet(body)
	if err != nil {
		return clientKeys{}, err
	}
	encryption, err := jose.ParseEncryptionJWKSet(body)
	if err != nil {
		return clientKeys{}, err
	}
	var out clientKeys
	for _, k := range verification {
		out.verification = append(out.verification, keys.VerificationKey{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey})
	}
	for _, k := range encryption {
		out.encryption = append(out.encryption, keys.ClientEncryptionKey{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey})
	}
	return out, nil
}
