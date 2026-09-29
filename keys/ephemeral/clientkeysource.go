package ephemeral

import (
	"context"
	"fmt"
	"net/url"
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

// ClientKeySpec is one registered client's verification key material —
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
// before being re-fetched. Defaults to 5 minutes.
func WithCacheTTL(d time.Duration) Option {
	return func(s *ClientKeySource) { s.cacheTTL = d }
}

// clientKeyEntry is one registered client's verification key source:
// either a fixed, already-parsed static set (no I/O, no cache) or a
// remote JWKS URL fetched and cached live.
type clientKeyEntry struct {
	static  []keys.VerificationKey // nil if this client's keys are fetched instead
	jwksURL *url.URL

	mu       sync.Mutex
	cached   []keys.VerificationKey
	cachedAt time.Time
}

// ClientKeySource resolves each registered client's verification keys,
// either from an inline static JWKS or by fetching one live via
// fapihttp.Client — which already applies the SSRF/size-limit/
// content-type hardening ARCHITECTURE.md design rule 6 requires for
// exactly this case, so this type reuses it rather than issuing its own
// HTTP requests. See the package doc comment for why this is
// development/testing only.
type ClientKeySource struct {
	fetcher  *fapihttp.Client
	cacheTTL time.Duration
	clients  map[fapi.ClientID]*clientKeyEntry
}

// NewClientKeySource builds a ClientKeySource from specs, parsing every
// inline static JWKS up front so a malformed one fails at construction
// rather than on the first request that needs it.
//
// fetcher may be nil when every spec carries an inline JWKS: nothing is
// ever fetched then. A spec that relies on its JWKSURI needs a fetcher,
// and construction fails without one rather than at that client's first
// request. So does a spec with no ClientID, a ClientID already used by
// an earlier spec, neither JWKS nor JWKSURI, or a JWKSURI that isn't an
// absolute URL.
func NewClientKeySource(fetcher *fapihttp.Client, specs []ClientKeySpec, opts ...Option) (*ClientKeySource, error) {
	s := &ClientKeySource{
		fetcher:  fetcher,
		cacheTTL: defaultClientJWKSCacheTTL,
		clients:  make(map[fapi.ClientID]*clientKeyEntry, len(specs)),
	}
	for _, opt := range opts {
		opt(s)
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

// newClientKeyEntry builds spec's entry: its parsed inline JWKS, or its
// JWKS URI to fetch, which needs a fetcher.
func newClientKeyEntry(spec ClientKeySpec, haveFetcher bool) (*clientKeyEntry, error) {
	if len(spec.JWKS) > 0 {
		parsed, err := parseVerificationKeys(spec.JWKS)
		if err != nil {
			return nil, fmt.Errorf("parse inline jwks: %w", err)
		}
		return &clientKeyEntry{static: parsed}, nil
	}
	if spec.JWKSURI == "" {
		return nil, fmt.Errorf("neither jwks nor jwks_uri is set")
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

	candidates := entry.static
	if candidates == nil {
		fresh, err := s.currentFetchedKeys(ctx, entry, req.KeyID)
		if err != nil {
			return keys.VerificationKeySet{}, err
		}
		candidates = fresh
	}

	var matched []keys.VerificationKey
	for _, k := range candidates {
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

// currentFetchedKeys returns entry's cached keys if fresh and (when a
// specific KeyID was requested) already present, forcing one refetch
// otherwise — the same stale-key handling keys.JWKSIssuerKeySource
// applies, covering a client that has rotated keys since the last fetch.
func (s *ClientKeySource) currentFetchedKeys(ctx context.Context, entry *clientKeyEntry, wantKeyID string) ([]keys.VerificationKey, error) {
	entry.mu.Lock()
	fresh := entry.cached != nil && time.Since(entry.cachedAt) < s.cacheTTL
	cached := entry.cached
	entry.mu.Unlock()

	if fresh {
		if wantKeyID == "" {
			return cached, nil
		}
		for _, k := range cached {
			if k.KeyID == wantKeyID {
				return cached, nil
			}
		}
	}
	return s.refetch(ctx, entry)
}

func (s *ClientKeySource) refetch(ctx context.Context, entry *clientKeyEntry) ([]keys.VerificationKey, error) {
	res, err := s.fetcher.Fetch(ctx, fapihttp.FetchRequest{
		URL:                   entry.jwksURL,
		ExpectedContentType:   "application/json",
		AlternateContentTypes: []string{"application/jwk-set+json"},
	})
	if err != nil {
		return nil, fmt.Errorf("ephemeral: fetch client jwks: %w", err)
	}
	parsed, err := parseVerificationKeys(res.Body)
	if err != nil {
		return nil, fmt.Errorf("ephemeral: parse client jwks: %w", err)
	}
	entry.mu.Lock()
	entry.cached = parsed
	entry.cachedAt = time.Now()
	entry.mu.Unlock()
	return parsed, nil
}

// parseVerificationKeys parses a JWK Set via the shared
// internal/jose.ParseJWKSet and maps the result into this package's own
// keys.VerificationKey type.
func parseVerificationKeys(body []byte) ([]keys.VerificationKey, error) {
	parsed, err := jose.ParseJWKSet(body)
	if err != nil {
		return nil, err
	}
	out := make([]keys.VerificationKey, len(parsed))
	for i, k := range parsed {
		out[i] = keys.VerificationKey{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey}
	}
	return out, nil
}
