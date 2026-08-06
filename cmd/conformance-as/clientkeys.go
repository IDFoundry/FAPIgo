package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/fapihttp"
	"github.com/osanderson/go-fapi/internal/jose"
	"github.com/osanderson/go-fapi/keys"
)

// clientJWKSCacheTTL bounds how long a fetched client JWKS is trusted
// before clientKeySource re-fetches it.
const clientJWKSCacheTTL = 5 * time.Minute

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

// clientKeySource resolves each registered conformance-suite client's
// verification keys, either from an inline static JWKS (config-supplied)
// or by fetching one live via fapihttp.Client — which already applies
// the SSRF/size-limit/content-type hardening ARCHITECTURE.md design rule
// 6 requires for exactly this case, so this type reuses it rather than
// issuing its own HTTP requests.
type clientKeySource struct {
	fetcher *fapihttp.Client
	clients map[fapi.ClientID]*clientKeyEntry
}

// newClientKeySource builds a clientKeySource from specs, parsing every
// inline static JWKS up front so a malformed one fails at startup rather
// than on the first request that needs it.
func newClientKeySource(fetcher *fapihttp.Client, specs []ClientKeySpec) (*clientKeySource, error) {
	s := &clientKeySource{fetcher: fetcher, clients: make(map[fapi.ClientID]*clientKeyEntry, len(specs))}
	for _, spec := range specs {
		entry := &clientKeyEntry{}
		if len(spec.JWKS) > 0 {
			parsed, err := parseJWKSDocument(spec.JWKS)
			if err != nil {
				return nil, fmt.Errorf("client %q: parse inline jwks: %w", spec.Registered.ID(), err)
			}
			entry.static = parsed
		} else {
			u, err := url.Parse(spec.JWKSURI)
			if err != nil {
				return nil, fmt.Errorf("client %q: parse jwks_uri: %w", spec.Registered.ID(), err)
			}
			entry.jwksURL = u
		}
		s.clients[spec.Registered.ID()] = entry
	}
	return s, nil
}

// ResolveVerificationKeys implements keys.ClientKeySource.
func (s *clientKeySource) ResolveVerificationKeys(ctx context.Context, req keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	entry, ok := s.clients[req.ClientID]
	if !ok {
		return keys.VerificationKeySet{}, fmt.Errorf("conformance-as: unknown client %q", req.ClientID)
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
func (s *clientKeySource) currentFetchedKeys(ctx context.Context, entry *clientKeyEntry, wantKeyID string) ([]keys.VerificationKey, error) {
	entry.mu.Lock()
	fresh := entry.cached != nil && time.Since(entry.cachedAt) < clientJWKSCacheTTL
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

func (s *clientKeySource) refetch(ctx context.Context, entry *clientKeyEntry) ([]keys.VerificationKey, error) {
	res, err := s.fetcher.Fetch(ctx, fapihttp.FetchRequest{URL: entry.jwksURL, ExpectedContentType: "application/json"})
	if err != nil {
		return nil, fmt.Errorf("conformance-as: fetch client jwks: %w", err)
	}
	parsed, err := parseJWKSDocument(res.Body)
	if err != nil {
		return nil, fmt.Errorf("conformance-as: parse client jwks: %w", err)
	}
	entry.mu.Lock()
	entry.cached = parsed
	entry.cachedAt = time.Now()
	entry.mu.Unlock()
	return parsed, nil
}

type rawJWKSet struct {
	Keys []json.RawMessage `json:"keys"`
}

// jwkAlgHint reads just enough of a JWK Set entry to decide which
// fapi.SignatureAlgorithm to validate the rest of it against — the same
// two-step decode keys.JWKSIssuerKeySource uses internally (unexported
// there, so reimplemented here rather than imported).
type jwkAlgHint struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// parseJWKSDocument parses a JWK Set (RFC 7517 §5) into this module's
// closed algorithm set, skipping any entry whose algorithm isn't
// supported or whose shape doesn't parse — one malformed or unsupported
// entry does not invalidate an otherwise usable key set.
func parseJWKSDocument(body []byte) ([]keys.VerificationKey, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var set rawJWKSet
	if err := dec.Decode(&set); err != nil {
		return nil, fmt.Errorf("malformed jwks: %w", err)
	}

	var out []keys.VerificationKey
	for _, raw := range set.Keys {
		var hint jwkAlgHint
		if err := json.Unmarshal(raw, &hint); err != nil {
			continue
		}
		alg, ok := algorithmForHint(hint)
		if !ok {
			continue
		}
		jwk, err := jose.ParseJWK(raw, alg)
		if err != nil {
			continue
		}
		out = append(out, keys.VerificationKey{KeyID: hint.Kid, Algorithm: alg, PublicKey: jwk.PublicKey()})
	}
	return out, nil
}

func algorithmForHint(h jwkAlgHint) (fapi.SignatureAlgorithm, bool) {
	if h.Alg != "" {
		alg, err := fapi.ParseSignatureAlgorithm(h.Alg)
		if err != nil {
			return 0, false
		}
		return alg, true
	}
	switch h.Kty {
	case "EC":
		if h.Crv == "P-256" {
			return fapi.ES256, true
		}
		return 0, false
	case "RSA":
		return fapi.PS256, true
	default:
		return 0, false
	}
}
