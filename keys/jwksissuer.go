package keys

import (
	"context"
	"fmt"
	"net/url"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/jose"
)

// jwksContentType is the content type this package primarily expects a
// JWKS fetch to declare. The large majority of real-world authorization
// servers serve their jwks_uri as plain "application/json", so that is
// the default here — but jwksAlternateContentType is also accepted, for
// the servers that instead use RFC 7517 §8.5.1's registered
// "application/jwk-set+json".
const jwksContentType = "application/json"

// jwksAlternateContentType is RFC 7517 §8.5.1's registered media type
// for a JWK Set document, accepted alongside jwksContentType.
const jwksAlternateContentType = "application/jwk-set+json"

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
	fetcher *fapihttp.Client
	jwksURI *url.URL
	timing  jwksCacheTiming
	issuer  string // "" when no WithIssuer
	now     func() time.Time
	cache   *jwksCache[[]IssuerKey]
}

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
	return func(s *JWKSIssuerKeySource) { s.timing.minRefreshInterval = d }
}

// WithRefreshBackoff bounds how soon the base TTL-refresh path (a
// request arriving once the cache has expired) will re-attempt a fetch
// after one fails, so a sequential request stream against a failing
// upstream doesn't issue one outbound fetch per request. Defaults to min(cacheTTL, 5s) —
// short relative to a long cacheTTL, but never longer than it — so a
// cold-start recovery isn't blocked for a full TTL window. This is
// distinct from minRefreshInterval, which rate-limits only the
// unknown-kid forced-refresh path.
func WithRefreshBackoff(d time.Duration) JWKSOption {
	return func(s *JWKSIssuerKeySource) { s.timing.refreshBackoff = d }
}

// WithIssuer binds the source to the issuer whose JWKS it fetches:
// ResolveIssuerKeys then refuses a request naming any other issuer,
// before fetching, as LocalIssuerKeys does, so one source shared by
// mistake between clients (or verifiers) of different issuers can't
// hand one issuer's keys to a check of another's. Without it the source
// can't tell, and serves whatever its JWKS URI holds for any issuer.
// DiscoveredMetadata.IssuerKeySource in package client sets it.
func WithIssuer(issuer fapi.URL) JWKSOption {
	return func(s *JWKSIssuerKeySource) { s.issuer = issuer.String() }
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
		fetcher: fetcher,
		jwksURI: &u,
		timing:  jwksCacheTiming{cacheTTL: cacheTTL},
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.timing = s.timing.withDefaults()
	// now is read through s, so a test may still swap s.now after New.
	s.cache = newJWKSCache(s.timing, func() time.Time { return s.now() }, s.doFetch)
	return s, nil
}

// Capabilities implements KeySourceAssurance. fetcher is required and
// non-nil (enforced by NewJWKSIssuerKeySource), so every live fetch
// goes through fapihttp's checks. It declares LiveFetchHardened only when
// fetcher is fapihttp.Client.HardenedForProduction: built over
// fapihttp.NewClient's client, with that transport still intact, and
// with no loopback exception on either. A fetcher over any other
// HTTPClient, http.DefaultClient included, keeps Fetch's pre-dial
// checks but isn't protected against DNS rebinding, so it isn't
// declared hardened and AssuranceProduction refuses the source.
func (s *JWKSIssuerKeySource) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: s.fetcher.HardenedForProduction()}
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
// token header, so it is attacker-controlled). With WithIssuer, a
// request for another issuer is refused.
func (s *JWKSIssuerKeySource) ResolveIssuerKeys(ctx context.Context, req IssuerKeyRequest) (IssuerKeySet, error) {
	if s.issuer != "" && req.Issuer != s.issuer {
		return IssuerKeySet{}, fmt.Errorf("keys: JWKSIssuerKeySource for %q cannot resolve keys for issuer %q", s.issuer, req.Issuer)
	}
	matched, err := resolveFromJWKSCache(ctx, s.cache, req.KeyID, func(current []IssuerKey) []IssuerKey {
		return matchIssuerKeys(current, req)
	})
	if err != nil {
		return IssuerKeySet{}, err
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

func (s *JWKSIssuerKeySource) doFetch(ctx context.Context) ([]IssuerKey, error) {
	res, err := s.fetcher.Fetch(ctx, fapihttp.FetchRequest{
		URL:                   s.jwksURI,
		ExpectedContentType:   jwksContentType,
		AlternateContentTypes: []string{jwksAlternateContentType},
	})
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
	return parsed, nil
}

// parseJWKSDocument parses a JWK Set (RFC 7517 §5) via the shared
// internal/jose.ParseTrustedJWKSet (an authorization server may publish
// keys for algorithms other clients use; that helper already skips any
// entry this module doesn't support or that doesn't parse) and maps the
// result into this package's own IssuerKey type. The trusted variant is
// used because the operator chose this authorization server, so its RSA
// keys may be up to 8192 bits rather than the 4096 a caller-supplied
// key is held to.
func parseJWKSDocument(body []byte) ([]IssuerKey, error) {
	parsed, err := jose.ParseTrustedJWKSet(body)
	if err != nil {
		return nil, err
	}
	out := make([]IssuerKey, len(parsed))
	for i, k := range parsed {
		out[i] = IssuerKey{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey}
	}
	return out, nil
}
