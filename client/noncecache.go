package client

import (
	"context"
	"net/url"
	"sync"
)

// asNonceScope is the DPoPNonceCache key shared by the token endpoint
// and PAR — a Client is already bound to exactly one issuer, and
// server's own Dependencies.Nonces treats PAR and the token endpoint as
// one shared nonce space (RFC 9449 §8), so a nonce obtained from either
// is valid to present to either.
const asNonceScope = "as"

// resourceNonceScope is a ResourceClient.Do call's DPoPNonceCache key:
// per resource-server origin, since RFC 9449 §9 nonces are scoped to
// the resource server that issued them and Do can be pointed at any
// resource URL, not just one fixed endpoint.
func resourceNonceScope(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

// DPoPNonceCache remembers the most recent DPoP nonce a server handed
// this client for a given scope, so the next call can present it
// proactively instead of always paying the initial challenge round
// trip RFC 9449 §8/§9 otherwise requires. It is a hint, not a ledger —
// losing it, or a stale/wrong value, only costs one extra
// challenge/retry round trip on the next call, recovered by the
// existing retry logic exactly as if this cache didn't exist at all.
// Dependencies.DPoPNonceCache being nil disables the optimization
// entirely — every call behaves exactly as it always has.
type DPoPNonceCache interface {
	// Get returns the nonce last cached for scope, and whether one was
	// found at all.
	Get(ctx context.Context, scope string) (nonce string, ok bool)

	// Set replaces the cached nonce for scope. Called with whatever a
	// response's own "DPoP-Nonce" header carried, regardless of that
	// response's status — a server may send one on an unrelated error,
	// or on success, purely to pre-seed the caller's next request.
	Set(ctx context.Context, scope string, nonce string)
}

// InMemoryDPoPNonceCache is a DPoPNonceCache backed by a plain map, safe
// for concurrent use. It is a ready-made implementation a caller can
// wire in explicitly — supplying it is as deliberate a choice as
// Clock: SystemClock{} is; New never installs one on its own.
type InMemoryDPoPNonceCache struct {
	mu     sync.Mutex
	nonces map[string]string
}

// NewInMemoryDPoPNonceCache builds an empty InMemoryDPoPNonceCache.
func NewInMemoryDPoPNonceCache() *InMemoryDPoPNonceCache {
	return &InMemoryDPoPNonceCache{nonces: make(map[string]string)}
}

// Get implements DPoPNonceCache.
func (c *InMemoryDPoPNonceCache) Get(_ context.Context, scope string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	nonce, ok := c.nonces[scope]
	return nonce, ok
}

// Set implements DPoPNonceCache.
func (c *InMemoryDPoPNonceCache) Set(_ context.Context, scope string, nonce string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nonces[scope] = nonce
}

// cachedDPoPNonce returns the nonce cached for scope, or "" if
// Dependencies.DPoPNonceCache is nil or has none — the same value every
// nonce-aware call site used unconditionally before this cache existed.
func (c *Client) cachedDPoPNonce(ctx context.Context, scope string) string {
	if c.deps.DPoPNonceCache == nil {
		return ""
	}
	nonce, ok := c.deps.DPoPNonceCache.Get(ctx, scope)
	if !ok {
		return ""
	}
	return nonce
}

// cacheDPoPNonce records nonce for scope, if both a cache is configured
// and nonce is non-empty — a response with no "DPoP-Nonce" header
// leaves whatever was cached before untouched, rather than overwriting
// it with an empty value.
func (c *Client) cacheDPoPNonce(ctx context.Context, scope, nonce string) {
	if c.deps.DPoPNonceCache == nil || nonce == "" {
		return
	}
	c.deps.DPoPNonceCache.Set(ctx, scope, nonce)
}
