package client

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/metadata"
)

// discoveryContentType is the content type RFC 8414 §3.2 requires an
// authorization server metadata response to declare.
const discoveryContentType = "application/json"

// DiscoveredMetadata is what Discover returns: the endpoints and
// published algorithm support a caller needs to build a Config, already
// checked against the issuer identifier the caller asked for. It has no
// public constructor — only Discover produces one — so a caller can't
// assemble one from untrusted data and mistake it for something that
// already went through the anti-spoofing issuer check RFC 8414 §3.3 and
// OpenID Connect Discovery 1.0 §4.3 require.
//
// Discover never picks an algorithm on the caller's behalf — each
// Algorithms slice is every value this module's closed
// fapi.SignatureAlgorithm set recognizes among what the server
// advertised (an authorization server may advertise algorithms this
// module doesn't implement, e.g. RS256; those are silently omitted, not
// treated as an error). Choosing which one to actually use for Config is
// a caller decision.
type DiscoveredMetadata struct {
	Endpoints Endpoints
	JWKSURI   fapi.URL

	IDTokenAlgorithms       []fapi.SignatureAlgorithm
	RequestObjectAlgorithms []fapi.SignatureAlgorithm
	JARMAlgorithms          []fapi.SignatureAlgorithm

	// RequireSignedRequestObject reflects the server's own
	// require_signed_request_object metadata value — a caller targeting
	// that server should set Config.Profile to
	// ProfileFAPISecurityWithMessageSigning accordingly.
	RequireSignedRequestObject bool

	// AuthorizationResponseIssSupported reflects the server's own
	// authorization_response_iss_parameter_supported metadata value — a
	// caller targeting that server should set
	// Config.RequireAuthorizationResponseIss accordingly (RFC 9207 §2.4:
	// "Clients MUST reject authorization responses without the iss
	// parameter from authorization servers that do support the
	// parameter").
	AuthorizationResponseIssSupported bool
}

// Discover fetches and validates issuer's OpenID Connect Discovery
// document (".well-known/openid-configuration" appended after any path
// component issuer itself carries — OIDC Discovery 1.0 §4.1's own
// worked example: issuer "https://example.com/issuer1" resolves to
// "GET /issuer1/.well-known/openid-configuration". This is deliberately
// not RFC 8414 §3.1's insert-before-path algorithm — RFC 8414 §5 itself
// acknowledges "openid-configuration... differs from OpenID Connect
// Discovery 1.0's approach", and real OIDC deployments (this module's
// own conformance suite included) serve the "openid-configuration"
// suffix at the §4.1 location, not the RFC 8414 one) via fetcher, and
// returns the endpoints and algorithm support a caller needs to build a
// Config. It does not construct a Client itself: the caller still
// supplies its own ClientID, RedirectURI, chosen algorithms and
// Dependencies — Discover only ever removes the need to hand-copy an
// authorization server's published endpoints and algorithm list.
//
// opts is forwarded to the fapi.URL parse of every discovered endpoint —
// pass fapi.AllowLoopbackHTTP() for a local development authorization
// server, exactly as when parsing an endpoint URL by hand.
func Discover(ctx context.Context, fetcher *fapihttp.Client, issuer fapi.URL, opts ...fapi.URLOption) (DiscoveredMetadata, error) {
	if fetcher == nil {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover: fetcher is required")
	}
	if issuer.IsZero() {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover: issuer is required")
	}

	issuerURL := issuer.URL()
	target := wellKnownURL(&issuerURL)

	res, err := fetcher.Fetch(ctx, fapihttp.FetchRequest{URL: target, ExpectedContentType: discoveryContentType})
	if err != nil {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover: fetch metadata: %w", err)
	}

	doc, err := metadata.ParseAndValidate(res.Body, issuer.String())
	if err != nil {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover: %w", err)
	}

	authz, err := fapi.ParseEndpointURL(doc.AuthorizationEndpoint, opts...)
	if err != nil {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover: authorization_endpoint: %w", err)
	}
	tok, err := fapi.ParseEndpointURL(doc.TokenEndpoint, opts...)
	if err != nil {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover: token_endpoint: %w", err)
	}
	par, err := fapi.ParseEndpointURL(doc.PushedAuthorizationRequestEndpoint, opts...)
	if err != nil {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover: pushed_authorization_request_endpoint: %w", err)
	}
	jwksURI, err := fapi.ParseEndpointURL(doc.JWKSURI, opts...)
	if err != nil {
		return DiscoveredMetadata{}, fmt.Errorf("client: discover: jwks_uri: %w", err)
	}

	return DiscoveredMetadata{
		Endpoints: Endpoints{
			Authorization:              authz,
			Token:                      tok,
			PushedAuthorizationRequest: par,
		},
		JWKSURI:                           jwksURI,
		IDTokenAlgorithms:                 supportedAlgorithms(doc.IDTokenSigningAlgValuesSupported),
		RequestObjectAlgorithms:           supportedAlgorithms(doc.RequestObjectSigningAlgValuesSupported),
		JARMAlgorithms:                    supportedAlgorithms(doc.AuthorizationSigningAlgValuesSupported),
		RequireSignedRequestObject:        doc.RequireSignedRequestObject,
		AuthorizationResponseIssSupported: doc.AuthorizationResponseIssParameterSupported,
	}, nil
}

// wellKnownURL builds the OpenID Connect Discovery 1.0 §4.1 well-known
// URL for issuer: ".well-known/openid-configuration" is appended after
// any path component issuer itself carries (its terminating "/" removed
// first, per §4.1), not inserted between the host and that path — see
// Discover's doc comment for why this, and not RFC 8414 §3.1's
// insert-before-path algorithm, is correct for this specific suffix.
func wellKnownURL(issuer *url.URL) *url.URL {
	out := *issuer
	issuerPath := strings.TrimSuffix(issuer.Path, "/")
	out.Path = issuerPath + "/.well-known/openid-configuration"
	out.RawQuery = ""
	out.Fragment = ""
	return &out
}

func supportedAlgorithms(values []string) []fapi.SignatureAlgorithm {
	var out []fapi.SignatureAlgorithm
	for _, v := range values {
		alg, err := fapi.ParseSignatureAlgorithm(v)
		if err != nil {
			continue
		}
		out = append(out, alg)
	}
	return out
}
