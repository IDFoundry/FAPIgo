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
	fetcher  *fapihttp.Client
	jwksURI  *url.URL
	cacheTTL time.Duration
	now      func() time.Time

	mu       sync.Mutex
	cached   []IssuerKey
	cachedAt time.Time
}

// NewJWKSIssuerKeySource returns a JWKSIssuerKeySource fetching from
// jwksURI via fetcher, caching the result for cacheTTL.
func NewJWKSIssuerKeySource(fetcher *fapihttp.Client, jwksURI fapi.URL, cacheTTL time.Duration) (*JWKSIssuerKeySource, error) {
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
	return &JWKSIssuerKeySource{fetcher: fetcher, jwksURI: &u, cacheTTL: cacheTTL, now: time.Now}, nil
}

// ResolveIssuerKeys returns every cached key matching req.Algorithm
// (and req.KeyID, if set). If a specific KeyID was requested and isn't
// found in the cache, it forces one refresh before giving up — the
// stale-key handling design rule 5 requires, covering the case where
// the authorization server has rotated keys since the last fetch.
func (s *JWKSIssuerKeySource) ResolveIssuerKeys(ctx context.Context, req IssuerKeyRequest) (IssuerKeySet, error) {
	current, err := s.currentKeys(ctx)
	if err != nil {
		return IssuerKeySet{}, err
	}
	matched := matchIssuerKeys(current, req)

	if len(matched) == 0 && req.KeyID != "" {
		fresh, err := s.refresh(ctx)
		if err != nil {
			return IssuerKeySet{}, err
		}
		matched = matchIssuerKeys(fresh, req)
	}
	return IssuerKeySet{Keys: matched}, nil
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
	return s.refresh(ctx)
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
