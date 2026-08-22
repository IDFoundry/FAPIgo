package keys

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/jose"
)

// jwksContentType is the content type this package requires a JWKS
// fetch to declare. RFC 7517 §5 registers "application/jwk-set+json",
// but the large majority of real-world authorization servers serve
// their jwks_uri as plain "application/json" — this package follows
// that practice rather than the registered value, to interoperate with
// what deployments actually do.
const jwksContentType = "application/json"

// JWKSIssuerKeySource resolves an authorization server's verification
// keys by fetching its published JWKS document live over fapihttp — the
// hardened building block ARCHITECTURE.md design rule 6 describes for
// exactly this case — and caching the result for CacheTTL so a
// verification-heavy workload doesn't refetch on every call.
//
// Per design rule 5, a live JWKS fetch in the request-handling path is a
// last resort; prefer an administratively pre-resolved or cached
// IssuerKeySource where a deployment can arrange one. This type exists
// for the common case where that isn't practical, and implements
// IssuerKeySource so both client and resource can use it.
type JWKSIssuerKeySource struct {
	fetcher            *fapihttp.Client
	jwksURI            *url.URL
	cacheTTL           time.Duration
	minRefreshInterval time.Duration
	now                func() time.Time

	mu           sync.Mutex
	cached       []IssuerKey
	cachedAt     time.Time
	lastAttempt  time.Time
	inflight     *refreshCall
	negativeKIDs map[string]time.Time
}

// refreshCall is an in-flight refresh shared by every caller that
// arrives while it is running, so a burst of concurrent unknown-kid
// misses collapses into a single upstream fetch.
type refreshCall struct {
	done chan struct{}
	keys []IssuerKey
	err  error
}

// maxNegativeKIDs bounds the negative-cache map so an attacker sending
// an unbounded number of distinct unknown kids cannot grow it without
// limit. When full, expired entries are evicted first; if it is still
// full, new misses simply aren't remembered — the worst case is an
// occasional extra refresh, which minRefreshInterval already bounds.
const maxNegativeKIDs = 1024

// JWKSOption configures a JWKSIssuerKeySource.
type JWKSOption func(*JWKSIssuerKeySource)

// WithMinRefreshInterval bounds how often an unknown-kid miss may force
// a live refetch, independent of CacheTTL. Defaults to CacheTTL, which
// means an unknown kid can force at most one extra fetch per TTL
// window — a real key rotation is still picked up within one TTL, the
// same worst case as plain TTL expiry, while an attacker sending
// requests with distinct unknown kids cannot force more than one
// upstream fetch per interval.
func WithMinRefreshInterval(d time.Duration) JWKSOption {
	return func(s *JWKSIssuerKeySource) { s.minRefreshInterval = d }
}

// NewJWKSIssuerKeySource returns a JWKSIssuerKeySource fetching from
// jwksURI via fetcher, caching the result for cacheTTL.
func NewJWKSIssuerKeySource(fetcher *fapihttp.Client, jwksURI fapi.URL, cacheTTL time.Duration, opts ...JWKSOption) (*JWKSIssuerKeySource, error) {
	if fetcher == nil {
		return nil, fmt.Errorf("keys: fetcher is required")
	}
	if jwksURI.IsZero() {
		return nil, fmt.Errorf("keys: jwks URI is required")
	}
	if cacheTTL <= 0 {
		return nil, fmt.Errorf("keys: cache TTL must be positive")
	}
	u := jwksURI.URL()
	s := &JWKSIssuerKeySource{
		fetcher:      fetcher,
		jwksURI:      &u,
		cacheTTL:     cacheTTL,
		now:          time.Now,
		negativeKIDs: make(map[string]time.Time),
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.minRefreshInterval <= 0 {
		s.minRefreshInterval = cacheTTL
	}
	return s, nil
}

// ResolveIssuerKeys returns every cached key matching req.Algorithm
// (and req.KeyID, if set). If a specific KeyID was requested and isn't
// found in the cache, it forces one refresh before giving up — the
// stale-key handling design rule 5 requires, covering the case where
// the authorization server has rotated keys since the last fetch. That
// forced refresh is rate-limited to at most one per
// minRefreshInterval and single-flighted, so an unauthenticated caller
// cannot force unbounded concurrent upstream fetches by sending
// requests with unknown kids (req.KeyID is taken from the unverified
// token header, so it is attacker-controlled).
func (s *JWKSIssuerKeySource) ResolveIssuerKeys(ctx context.Context, req IssuerKeyRequest) (IssuerKeySet, error) {
	current, err := s.currentKeys(ctx)
	if err != nil {
		return IssuerKeySet{}, err
	}
	matched := matchIssuerKeys(current, req)
	if len(matched) > 0 || req.KeyID == "" {
		return IssuerKeySet{Keys: matched}, nil
	}

	if !s.shouldForceRefresh(req.KeyID) {
		return IssuerKeySet{Keys: nil}, nil
	}
	fresh, err := s.refreshSingleflight(ctx)
	if err != nil {
		return IssuerKeySet{}, err
	}
	matched = matchIssuerKeys(fresh, req)
	if len(matched) == 0 {
		s.rememberMiss(req.KeyID)
	}
	return IssuerKeySet{Keys: matched}, nil
}

// shouldForceRefresh reports whether an unknown-kid miss on kid may
// force a live refresh right now: it may not if kid is still
// negative-cached, or if the last refresh attempt was within
// minRefreshInterval.
func (s *JWKSIssuerKeySource) shouldForceRefresh(kid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if retryAt, ok := s.negativeKIDs[kid]; ok && now.Before(retryAt) {
		return false
	}
	if !s.lastAttempt.IsZero() && now.Sub(s.lastAttempt) < s.minRefreshInterval {
		return false
	}
	return true
}

// rememberMiss negative-caches kid until minRefreshInterval has passed,
// so a repeated request for the same unknown kid doesn't force another
// refresh before then. It also opportunistically evicts expired
// entries so the map stays bounded under maxNegativeKIDs.
func (s *JWKSIssuerKeySource) rememberMiss(kid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.negativeKIDs) >= maxNegativeKIDs {
		for k, retryAt := range s.negativeKIDs {
			if !now.Before(retryAt) {
				delete(s.negativeKIDs, k)
			}
		}
	}
	if len(s.negativeKIDs) < maxNegativeKIDs {
		s.negativeKIDs[kid] = now.Add(s.minRefreshInterval)
	}
}

// refreshSingleflight coalesces concurrent refresh attempts: the first
// caller performs the fetch outside the lock, and every caller that
// arrives while it's in flight waits on the same result instead of
// starting its own.
func (s *JWKSIssuerKeySource) refreshSingleflight(ctx context.Context) ([]IssuerKey, error) {
	s.mu.Lock()
	if s.inflight != nil {
		call := s.inflight
		s.mu.Unlock()
		select {
		case <-call.done:
			return call.keys, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &refreshCall{done: make(chan struct{})}
	s.inflight = call
	s.lastAttempt = s.now()
	s.mu.Unlock()

	call.keys, call.err = s.refresh(ctx)

	s.mu.Lock()
	s.inflight = nil
	s.mu.Unlock()
	close(call.done)
	return call.keys, call.err
}

func matchIssuerKeys(keys []IssuerKey, req IssuerKeyRequest) []IssuerKey {
	var matched []IssuerKey
	for _, k := range keys {
		if k.Algorithm != req.Algorithm {
			continue
		}
		if req.KeyID != "" && k.KeyID != req.KeyID {
			continue
		}
		matched = append(matched, k)
	}
	return matched
}

func (s *JWKSIssuerKeySource) currentKeys(ctx context.Context) ([]IssuerKey, error) {
	s.mu.Lock()
	fresh := s.cached != nil && s.now().Sub(s.cachedAt) < s.cacheTTL
	cached := s.cached
	s.mu.Unlock()
	if fresh {
		return cached, nil
	}
	return s.refreshSingleflight(ctx)
}

func (s *JWKSIssuerKeySource) refresh(ctx context.Context) ([]IssuerKey, error) {
	res, err := s.fetcher.Fetch(ctx, fapihttp.FetchRequest{URL: s.jwksURI, ExpectedContentType: jwksContentType})
	if err != nil {
		return nil, fmt.Errorf("keys: fetch jwks: %w", err)
	}
	parsed, err := parseJWKSDocument(res.Body)
	if err != nil {
		return nil, fmt.Errorf("keys: parse jwks: %w", err)
	}
	if len(parsed) == 0 {
		return nil, fmt.Errorf("keys: jwks document contains no usable keys")
	}

	s.mu.Lock()
	s.cached = parsed
	s.cachedAt = s.now()
	s.mu.Unlock()
	return parsed, nil
}

// parseJWKSDocument parses a JWK Set (RFC 7517 §5) via the shared
// internal/jose.ParseJWKSet (an authorization server may publish keys
// for algorithms other clients use; that helper already skips any entry
// this module doesn't support or that doesn't parse) and maps the
// result into this package's own IssuerKey type.
func parseJWKSDocument(body []byte) ([]IssuerKey, error) {
	parsed, err := jose.ParseJWKSet(body)
	if err != nil {
		return nil, err
	}
	out := make([]IssuerKey, len(parsed))
	for i, k := range parsed {
		out[i] = IssuerKey{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey}
	}
	return out, nil
}
