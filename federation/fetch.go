package federation

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/idfoundry/fapigo/fapihttp"
	intfed "github.com/idfoundry/fapigo/internal/federation"
)

// EntityStatementContentType is the content type every successful
// Entity Statement response MUST declare (OpenID Federation 1.0
// §8.1.2/§9.2) — distinct from a JSON error response, which uses
// "application/json" instead. Exported so an embedder serving
// SelfIssuer's own output over HTTP sets the same value this package's
// own fetch side requires of a peer.
const EntityStatementContentType = "application/entity-statement+jwt"

// WellKnownPath is the path (OpenID Federation 1.0 §9) an embedder
// should serve SelfIssuer's own EntityConfiguration output under,
// relative to SelfIssueConfig.EntityID's own origin — the same suffix
// wellKnownURL concatenates when this package fetches a peer's Entity
// Configuration.
const WellKnownPath = "/.well-known/openid-federation"

// WriteEntityStatement writes jwt — either SelfIssuer.EntityConfiguration's
// own return value, or SubordinateIssuer.SubordinateStatement's — to w
// as a complete, correctly-typed Entity Statement response (OpenID
// Federation 1.0 §3: both are Entity Statements, self-signed or not,
// and share the identical EntityStatementContentType regardless): the
// Content-Type header, then jwt verbatim as the body. This package
// still owns no transport of its own (ARCHITECTURE.md design rule 6;
// the caller's own http.Server is what's actually listening at
// WellKnownPath or its own fetch endpoint) — this is the same category
// of helper as resource.Error.WriteJSON/server.TokenResult.WriteJSON:
// it writes to an http.ResponseWriter the caller already has, nothing
// more.
//
// Must be called before anything else writes to w — like every
// http.ResponseWriter header/status call, it has no effect once a
// prior write has already sent the response's status line.
func WriteEntityStatement(w http.ResponseWriter, jwt string) {
	w.Header().Set("Content-Type", EntityStatementContentType)
	_, _ = w.Write([]byte(jwt))
}

// wellKnownURL builds entityID's Federation Entity Configuration
// endpoint (OpenID Federation 1.0 §9): "/.well-known/openid-federation"
// concatenated onto entityID, after removing a trailing "/" if present.
// Unlike client.Discover's own well-known URL (OIDC Discovery 1.0
// §4.1's own insertion point), this is a plain suffix concatenation —
// the two specs genuinely differ here, not a copy-paste of one rule for
// the other; see doc.go for why Entity Identifiers are plain strings in
// this package rather than fapi.URL (whose own parsing rules were
// tuned for OAuth/OIDC issuer identifiers, not Entity Identifiers).
func wellKnownURL(entityID string) (*url.URL, error) {
	u, err := url.Parse(entityID)
	if err != nil {
		return nil, fmt.Errorf("federation: invalid entity identifier %q: %w", entityID, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("federation: entity identifier %q must be an https URL with a host", entityID)
	}
	if u.Fragment != "" {
		return nil, fmt.Errorf("federation: entity identifier %q must not have a fragment", entityID)
	}
	out := *u
	out.Path = strings.TrimSuffix(u.Path, "/") + WellKnownPath
	return &out, nil
}

// ValidEntityID reports whether id is a well-formed OpenID Federation
// 1.0 §1.2 Entity Identifier — an https URL with a host and no
// fragment. NewSelfIssuer and Resolver.Resolve both enforce this same
// rule on every entity ID they're given; exported so a caller
// validating its own configured entity ID eagerly (e.g. client.Config's
// or server.Config's own construction-time validation) can reuse the
// identical check rather than duplicating it.
func ValidEntityID(id string) error {
	_, err := wellKnownURL(id)
	return err
}

// fetchEntityConfiguration fetches and parses (but does not verify)
// entityID's own Entity Configuration, returning the raw compact-
// serialized token alongside the parsed Statement — Resolve's own
// ResolvedEntity.Tokens needs the exact raw bytes each hop was
// published as (OpenID Federation 1.0 §4's own Trust Chain, ES[0..i]),
// not a re-serialization of the parsed claims, which is not guaranteed
// to be byte-identical (canonicalization, member order) and would
// break the signature a verifier checks it against.
func fetchEntityConfiguration(ctx context.Context, fetcher *fapihttp.Client, entityID string) (intfed.Statement, string, error) {
	target, err := wellKnownURL(entityID)
	if err != nil {
		return intfed.Statement{}, "", err
	}
	res, err := fetcher.Fetch(ctx, fapihttp.FetchRequest{URL: target, ExpectedContentType: EntityStatementContentType})
	if err != nil {
		return intfed.Statement{}, "", fmt.Errorf("federation: fetch entity configuration for %q: %w", entityID, err)
	}
	token := string(res.Body)
	stmt, err := intfed.Parse(token)
	if err != nil {
		return intfed.Statement{}, "", fmt.Errorf("federation: parse entity configuration for %q: %w", entityID, err)
	}
	return stmt, token, nil
}

// fetchSubordinateStatement fetches and parses (but does not verify)
// the Subordinate Statement issuerFetchEndpoint's own issuer publishes
// about subjectID (OpenID Federation 1.0 §8.1), returning the raw
// compact-serialized token alongside the parsed Statement — see
// fetchEntityConfiguration's own doc comment for why the raw token,
// specifically, is needed.
func fetchSubordinateStatement(ctx context.Context, fetcher *fapihttp.Client, issuerFetchEndpoint, subjectID string) (intfed.Statement, string, error) {
	target, err := url.Parse(issuerFetchEndpoint)
	if err != nil {
		return intfed.Statement{}, "", fmt.Errorf("federation: invalid federation_fetch_endpoint %q: %w", issuerFetchEndpoint, err)
	}
	if target.Scheme != "https" {
		return intfed.Statement{}, "", fmt.Errorf("federation: federation_fetch_endpoint %q must use https", issuerFetchEndpoint)
	}
	q := target.Query()
	q.Set("sub", subjectID)
	target.RawQuery = q.Encode()

	res, err := fetcher.Fetch(ctx, fapihttp.FetchRequest{URL: target, ExpectedContentType: EntityStatementContentType})
	if err != nil {
		return intfed.Statement{}, "", fmt.Errorf("federation: fetch subordinate statement for %q from %q: %w", subjectID, issuerFetchEndpoint, err)
	}
	token := string(res.Body)
	stmt, err := intfed.Parse(token)
	if err != nil {
		return intfed.Statement{}, "", fmt.Errorf("federation: parse subordinate statement for %q from %q: %w", subjectID, issuerFetchEndpoint, err)
	}
	return stmt, token, nil
}
