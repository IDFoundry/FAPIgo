package federation

import (
	"context"
	"fmt"
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

// fetchEntityConfiguration fetches and parses (but does not verify)
// entityID's own Entity Configuration.
func fetchEntityConfiguration(ctx context.Context, fetcher *fapihttp.Client, entityID string) (intfed.Statement, error) {
	target, err := wellKnownURL(entityID)
	if err != nil {
		return intfed.Statement{}, err
	}
	res, err := fetcher.Fetch(ctx, fapihttp.FetchRequest{URL: target, ExpectedContentType: EntityStatementContentType})
	if err != nil {
		return intfed.Statement{}, fmt.Errorf("federation: fetch entity configuration for %q: %w", entityID, err)
	}
	stmt, err := intfed.Parse(string(res.Body))
	if err != nil {
		return intfed.Statement{}, fmt.Errorf("federation: parse entity configuration for %q: %w", entityID, err)
	}
	return stmt, nil
}

// fetchSubordinateStatement fetches and parses (but does not verify)
// the Subordinate Statement issuerFetchEndpoint's own issuer publishes
// about subjectID (OpenID Federation 1.0 §8.1).
func fetchSubordinateStatement(ctx context.Context, fetcher *fapihttp.Client, issuerFetchEndpoint, subjectID string) (intfed.Statement, error) {
	target, err := url.Parse(issuerFetchEndpoint)
	if err != nil {
		return intfed.Statement{}, fmt.Errorf("federation: invalid federation_fetch_endpoint %q: %w", issuerFetchEndpoint, err)
	}
	if target.Scheme != "https" {
		return intfed.Statement{}, fmt.Errorf("federation: federation_fetch_endpoint %q must use https", issuerFetchEndpoint)
	}
	q := target.Query()
	q.Set("sub", subjectID)
	target.RawQuery = q.Encode()

	res, err := fetcher.Fetch(ctx, fapihttp.FetchRequest{URL: target, ExpectedContentType: EntityStatementContentType})
	if err != nil {
		return intfed.Statement{}, fmt.Errorf("federation: fetch subordinate statement for %q from %q: %w", subjectID, issuerFetchEndpoint, err)
	}
	stmt, err := intfed.Parse(string(res.Body))
	if err != nil {
		return intfed.Statement{}, fmt.Errorf("federation: parse subordinate statement for %q from %q: %w", subjectID, issuerFetchEndpoint, err)
	}
	return stmt, nil
}
