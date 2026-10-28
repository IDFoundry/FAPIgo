package keys

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// jwksCache is one JWK Set's parsed keys, fetched live and cached, with
// the stale-key handling ARCHITECTURE.md design rule 5 asks for: a fresh
// copy is served for cacheTTL; a failed fetch isn't retried for
// refreshBackoff; and a request naming a kid the cached set lacks (the
// key may have been rotated in since the last fetch) may force one
// refetch, at most once per minRefreshInterval, with a miss for that
// kid negative-cached for as long, since the kid comes from an
// unverified JWT header and so is attacker-controlled. Concurrent
// fetches are single-flighted.
//
// It is shared by JWKSIssuerKeySource (one cache per source) and
// ClientJWKSSource (one per client), and stays unexported: each source
// holds one as a named field, never embedded, so none of its methods
// become part of an exported type.
type jwksCache[V any] struct {
	fetch              func(ctx context.Context) (V, error)
	cacheTTL           time.Duration
	minRefreshInterval time.Duration
	refreshBackoff     time.Duration
	now                func() time.Time

	mu               sync.Mutex
	cached           V
	haveCached       bool
	cachedAt         time.Time
	lastAttempt      time.Time
	lastRefreshErr   error
	lastRefreshErrAt time.Time
	inflight         *refreshCall[V]
	negativeKIDs     map[string]time.Time
}

// refreshCall is an in-flight refresh shared by every caller that
// arrives while it is running, so a burst of concurrent unknown-kid
// misses collapses into a single upstream fetch.
type refreshCall[V any] struct {
	done chan struct{}
	keys V
	err  error
}

// maxNegativeKIDs bounds the negative-cache map so an attacker sending
// an unbounded number of distinct unknown kids cannot grow it without
// limit. When full, expired entries are evicted first; if it is still
// full, new misses simply aren't remembered — the worst case is an
// occasional extra refresh, which minRefreshInterval already bounds.
const maxNegativeKIDs = 1024

// jwksCacheTiming is a jwksCache's three intervals.
type jwksCacheTiming struct {
	cacheTTL           time.Duration
	minRefreshInterval time.Duration
	refreshBackoff     time.Duration
}

// withDefaults fills t's unset intervals: minRefreshInterval defaults to
// cacheTTL, refreshBackoff to min(cacheTTL, 5s).
func (t jwksCacheTiming) withDefaults() jwksCacheTiming {
	if t.minRefreshInterval <= 0 {
		t.minRefreshInterval = t.cacheTTL
	}
	if t.refreshBackoff <= 0 {
		t.refreshBackoff = min(t.cacheTTL, 5*time.Second)
	}
	return t
}

func newJWKSCache[V any](timing jwksCacheTiming, now func() time.Time, fetch func(ctx context.Context) (V, error)) *jwksCache[V] {
	return &jwksCache[V]{
		fetch:              fetch,
		cacheTTL:           timing.cacheTTL,
		minRefreshInterval: timing.minRefreshInterval,
		refreshBackoff:     timing.refreshBackoff,
		now:                now,
		negativeKIDs:       make(map[string]time.Time),
	}
}

// resolveFromJWKSCache returns match's keys from c's current set. If kid
// is set and matches nothing, it forces one refresh (rate-limited and
// single-flighted, see jwksCache) before giving up with an empty result.
func resolveFromJWKSCache[V, K any](ctx context.Context, c *jwksCache[V], kid string, match func(V) []K) ([]K, error) {
	current, err := c.current(ctx)
	if err != nil {
		return nil, err
	}
	matched := match(current)
	if len(matched) > 0 || kid == "" {
		return matched, nil
	}
	if !c.shouldForceRefresh(kid) {
		return nil, nil
	}
	fresh, err := c.refreshSingleflight(ctx)
	if err != nil {
		return nil, err
	}
	matched = match(fresh)
	if len(matched) == 0 {
		c.rememberMiss(kid)
	}
	return matched, nil
}

// current is c's cached set while it is fresh, the last fetch's error
// while it is within refreshBackoff, and otherwise a new fetch.
func (c *jwksCache[V]) current(ctx context.Context) (V, error) {
	c.mu.Lock()
	now := c.now()
	fresh := c.haveCached && now.Sub(c.cachedAt) < c.cacheTTL
	cached := c.cached
	inBackoff := c.lastRefreshErr != nil && now.Sub(c.lastRefreshErrAt) < c.refreshBackoff
	backoffErr := c.lastRefreshErr
	c.mu.Unlock()
	if fresh {
		return cached, nil
	}
	if inBackoff {
		// Serve the remembered failure rather than issuing another
		// outbound fetch — a sequential request stream against a down
		// JWKS endpoint would otherwise produce one fetch per request.
		// Fail closed: the stale set isn't returned.
		var zero V
		return zero, fmt.Errorf("keys: jwks refresh in backoff after recent failure: %w", backoffErr)
	}
	return c.refreshSingleflight(ctx)
}

// shouldForceRefresh reports whether an unknown-kid miss on kid may
// force a live refresh right now: it may not if kid is still
// negative-cached, or if the last refresh attempt was within
// minRefreshInterval.
func (c *jwksCache[V]) shouldForceRefresh(kid string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if retryAt, ok := c.negativeKIDs[kid]; ok && now.Before(retryAt) {
		return false
	}
	if !c.lastAttempt.IsZero() && now.Sub(c.lastAttempt) < c.minRefreshInterval {
		return false
	}
	return true
}

// rememberMiss negative-caches kid until minRefreshInterval has passed,
// so a repeated request for the same unknown kid doesn't force another
// refresh before then. It also opportunistically evicts expired
// entries so the map stays bounded under maxNegativeKIDs.
func (c *jwksCache[V]) rememberMiss(kid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.negativeKIDs) >= maxNegativeKIDs {
		for k, retryAt := range c.negativeKIDs {
			if !now.Before(retryAt) {
				delete(c.negativeKIDs, k)
			}
		}
	}
	if len(c.negativeKIDs) < maxNegativeKIDs {
		c.negativeKIDs[kid] = now.Add(c.minRefreshInterval)
	}
}

// refreshSingleflight coalesces concurrent refresh attempts: the first
// caller performs the fetch outside the lock, and every caller that
// arrives while it's in flight waits on the same result instead of
// starting its own.
func (c *jwksCache[V]) refreshSingleflight(ctx context.Context) (V, error) {
	c.mu.Lock()
	if c.inflight != nil {
		call := c.inflight
		c.mu.Unlock()
		return waitRefresh(ctx, call)
	}
	call := &refreshCall[V]{done: make(chan struct{})}
	c.inflight = call
	c.lastAttempt = c.now()
	c.mu.Unlock()

	go func() {
		// Detached: fapihttp.Client.Fetch applies its own RequestTimeout,
		// so the fetch still cannot hang forever; WithoutCancel only
		// stops one caller's cancellation from aborting a fetch shared
		// by others.
		call.keys, call.err = c.refresh(context.WithoutCancel(ctx))
		c.mu.Lock()
		c.inflight = nil
		c.mu.Unlock()
		close(call.done)
	}()
	return waitRefresh(ctx, call)
}

// waitRefresh waits for call, or for ctx to be done first.
func waitRefresh[V any](ctx context.Context, call *refreshCall[V]) (V, error) {
	select {
	case <-call.done:
		return call.keys, call.err
	case <-ctx.Done():
		var zero V
		return zero, ctx.Err()
	}
}

// refresh fetches the set and records the outcome for every later
// caller.
func (c *jwksCache[V]) refresh(ctx context.Context) (V, error) {
	parsed, err := c.fetch(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.lastRefreshErr = err
		c.lastRefreshErrAt = c.now()
	} else {
		c.cached = parsed
		c.haveCached = true
		c.cachedAt = c.now()
		c.lastRefreshErr = nil
	}
	return parsed, err
}

// isExpired reports whether c's cached set, if any, is past cacheTTL
// and no fetch is in flight — an entry a bounded cache of jwksCaches
// may evict without losing anything fresh.
func (c *jwksCache[V]) isExpired() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inflight == nil && (!c.haveCached || c.now().Sub(c.cachedAt) >= c.cacheTTL)
}
