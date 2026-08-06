package client

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	fapi "github.com/osanderson/go-fapi"
	"github.com/osanderson/go-fapi/fapihttp"
	"github.com/osanderson/go-fapi/internal/metadata"
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
}

// Discover fetches and validates issuer's OAuth 2.0 Authorization Server
// Metadata / OpenID Connect Discovery document
// (issuer + "/.well-known/openid-configuration", inserted before any
// path component issuer itself carries — RFC 8414 §3.1) via fetcher, and
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
		JWKSURI:                    jwksURI,
		IDTokenAlgorithms:          supportedAlgorithms(doc.IDTokenSigningAlgValuesSupported),
		RequestObjectAlgorithms:    supportedAlgorithms(doc.RequestObjectSigningAlgValuesSupported),
		JARMAlgorithms:             supportedAlgorithms(doc.AuthorizationSigningAlgValuesSupported),
		RequireSignedRequestObject: doc.RequireSignedRequestObject,
	}, nil
}

// wellKnownURL builds the OpenID Connect Discovery 1.0 §4.1 well-known
// URL for issuer: ".well-known/openid-configuration" is inserted
// immediately after the host, before any path component issuer itself
// carries — not simply appended to issuer's own path.
func wellKnownURL(issuer *url.URL) *url.URL {
	out := *issuer
	issuerPath := strings.TrimSuffix(issuer.Path, "/")
	out.Path = "/.well-known/openid-configuration" + issuerPath
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
