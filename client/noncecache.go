package client

import (
	"context"
	"net/http"
	"net/url"
	"sync"
)

// asNonceScope is the DPoPNonceCache key shared by the token endpoint,
// PAR and the backchannel authentication endpoint: server's own
// Dependencies.Nonces treats them as one shared nonce space (RFC 9449
// §8), so a nonce obtained from one is valid to present to another. It
// names this client's issuer, so one cache shared by clients for
// different issuers keeps their nonces apart.
func (c *Client) asNonceScope() string {
	return "as " + c.cfg.Issuer.String()
}

// dpopNonceHeader is RFC 9449 §8's "DPoP-Nonce" response header —
// shared by every call site that reads or writes it (a typo here would
// silently break nonce caching, not fail loudly).
const dpopNonceHeader = "DPoP-Nonce"

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
// A resource server's nonces are cached per origin (scheme and host),
// so resource servers sharing an origin share one slot: a nonce one of
// them sends is presented to the other, which costs at most that retry.
// New installs a NewInMemoryDPoPNonceCache when
// Dependencies.DPoPNonceCache is nil.
type DPoPNonceCache interface {
	// Get returns the nonce last cached for scope, and whether one was
	// found at all.
	Get(ctx context.Context, scope string) (nonce string, ok bool)

	// Set replaces the cached nonce for scope, or, given "", forgets
	// it. It's called with the "DPoP-Nonce" header of a successful
	// response, which a server may send to pre-seed the caller's next
	// request, or of a use_dpop_nonce challenge, and with a nonce passed
	// to ResourceClient.UseDPoPNonce: only ever one of RFC 9449 §8.1's
	// syntax (1*NQCHAR), at most 1024 bytes. It's called with "" after
	// an error response that wasn't a challenge, so a nonce the server
	// refused, or one that made the request too large to accept, isn't
	// presented again.
	Set(ctx context.Context, scope string, nonce string)
}

// InMemoryDPoPNonceCache is a DPoPNonceCache backed by a plain map, safe
// for concurrent use. New installs one when Dependencies.DPoPNonceCache
// is nil.
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
	if nonce == "" {
		delete(c.nonces, scope)
		return
	}
	c.nonces[scope] = nonce
}

// maxDPoPNonceLength bounds a DPoP nonce this client caches or presents.
// RFC 9449 sets no limit; package server issues 43 characters (32 random bytes,
// base64url), and anything near this bound is already an unusual
// header. Without one, a server could hand out a nonce large enough that
// every later request to its origin is refused as too large (431),
// never answered with the challenge that would replace it.
const maxDPoPNonceLength = 1024

// validDPoPNonce reports whether nonce has RFC 9449 §8.1's syntax,
// 1*NQCHAR (NQCHAR = %x21 / %x23-5B / %x5D-7E), and is at most
// maxDPoPNonceLength bytes.
func validDPoPNonce(nonce string) bool {
	if nonce == "" || len(nonce) > maxDPoPNonceLength {
		return false
	}
	for i := 0; i < len(nonce); i++ {
		if c := nonce[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// cachedDPoPNonce returns the nonce cached for scope, or "" if
// Dependencies.DPoPNonceCache is nil or has none — the same value every
// nonce-aware call site used unconditionally before this cache existed.
// A cached value that isn't a valid nonce (validDPoPNonce), from a cache
// other clients write too, counts as none.
func (c *Client) cachedDPoPNonce(ctx context.Context, scope string) string {
	if c.deps.DPoPNonceCache == nil {
		return ""
	}
	nonce, ok := c.deps.DPoPNonceCache.Get(ctx, scope)
	if !ok || !validDPoPNonce(nonce) {
		return ""
	}
	return nonce
}

// cacheDPoPNonce records nonce for scope, if a cache is configured and
// nonce is a valid one (validDPoPNonce): an empty or malformed value
// leaves whatever was cached before untouched.
func (c *Client) cacheDPoPNonce(ctx context.Context, scope, nonce string) {
	if c.deps.DPoPNonceCache == nil || !validDPoPNonce(nonce) {
		return
	}
	c.deps.DPoPNonceCache.Set(ctx, scope, nonce)
}

// recordDPoPNonce updates scope's cached nonce from a response: it
// caches the response's nonce when the response succeeded (2xx) or is a
// use_dpop_nonce challenge, and forgets scope's nonce after any other
// 4xx, so a nonce that got a request refused — too large (431), or one
// the server no longer accepts — isn't presented again. Any other
// response, a challenge-less error from another path on the same origin
// included, can't plant a nonce.
func (c *Client) recordDPoPNonce(ctx context.Context, scope string, status int, header http.Header, challenge bool) {
	if c.deps.DPoPNonceCache == nil {
		return
	}
	switch {
	case challenge || (status >= 200 && status < 300):
		c.cacheDPoPNonce(ctx, scope, header.Get(dpopNonceHeader))
	case status >= 400 && status < 500:
		c.deps.DPoPNonceCache.Set(ctx, scope, "")
	}
}

// recordASDPoPNonce is recordDPoPNonce for a response from the
// authorization server's token, PAR or backchannel authentication
// endpoint, whose nonce challenge is a use_dpop_nonce error (RFC 9449
// §8).
func (c *Client) recordASDPoPNonce(ctx context.Context, status int, header http.Header, body []byte) {
	c.recordDPoPNonce(ctx, c.asNonceScope(), status, header, isASDPoPNonceChallenge(header, body))
}

// isASDPoPNonceChallenge reports whether an authorization server's
// response is a nonce challenge: a use_dpop_nonce error with a valid
// DPoP-Nonce header (RFC 9449 §8). The header alone isn't one: a server
// may send it on any response.
func isASDPoPNonceChallenge(header http.Header, body []byte) bool {
	return validDPoPNonce(header.Get(dpopNonceHeader)) && isDPoPNonceError(body)
}
