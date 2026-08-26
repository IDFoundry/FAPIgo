package client

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/internal/metadata"
	"github.com/idfoundry/fapigo/keys"
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
	// Endpoints.UserInfo is the server's advertised UserInfo Endpoint
	// (OpenID Connect Discovery 1.0 §3), if any — OPTIONAL, so a zero
	// fapi.URL means the server didn't advertise one; FetchUserInfo is
	// then unavailable until a caller sets it from its own out-of-band
	// knowledge of the server. Populated here, alongside every other
	// endpoint, precisely so assigning this whole struct to Config's own
	// Endpoints field (the pattern every other endpoint already expects)
	// is enough on its own — a caller doesn't need to separately notice
	// and hand-copy a UserInfo-specific field the way an earlier version
	// of this struct required.
	Endpoints Endpoints
	JWKSURI   fapi.URL

	IDTokenAlgorithms       []fapi.SignatureAlgorithm
	RequestObjectAlgorithms []fapi.SignatureAlgorithm
	JARMAlgorithms          []fapi.SignatureAlgorithm

	// IDTokenEncryptionAlgorithms/IDTokenEncryptionEncValues are every
	// key-management/content-encryption algorithm this module
	// recognizes among what the server advertised for encrypted ID
	// tokens (OIDC Core §10.2). Both empty means the server never
	// advertised encryption support at all — most servers. Populating
	// Config.Algorithms.IDTokenKeyManagement/IDTokenContentEncryption
	// from a value not present here would mean registering for
	// encryption the server never said it could do; this module leaves
	// that check to the caller; it does not enforce it here.
	IDTokenEncryptionAlgorithms []fapi.KeyManagementAlgorithm
	IDTokenEncryptionEncValues  []fapi.ContentEncryptionAlgorithm

	// UserInfoAlgorithms/UserInfoEncryptionAlgorithms/UserInfoEncryptionEncValues
	// mirror the ID-token triple above, for a UserInfo response instead.
	// All three empty means the server never advertised JWT UserInfo
	// support at all — most servers, and consistent with plain-JSON
	// UserInfo needing none of this.
	UserInfoAlgorithms           []fapi.SignatureAlgorithm
	UserInfoEncryptionAlgorithms []fapi.KeyManagementAlgorithm
	UserInfoEncryptionEncValues  []fapi.ContentEncryptionAlgorithm

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

// SupportsAlgorithms reports whether every algorithm algs actually
// requires is among what this server advertised, returning a
// descriptive error naming the first unsupported one it finds rather
// than a bare bool — Discover itself never picks an algorithm or
// enforces this on a caller's behalf (see this type's own doc
// comment), so a caller wanting a clear, specific startup failure
// instead of discovering a mismatch downstream — at whatever point a
// signature or JWE actually fails to verify — checks it explicitly
// with this method before building Config.
//
// Only the fields this type actually has discovered data for are
// checked:
//
//   - IDToken, against IDTokenAlgorithms, unconditionally — an ID
//     token is always expected, regardless of Profile.
//   - RequestObject, against RequestObjectAlgorithms, only if algs.RequestObject
//     is non-zero (Config only requires it under
//     ProfileFAPISecurityWithMessageSigning).
//   - JARM, against JARMAlgorithms, only if algs.JARM is non-zero (same
//     reasoning).
//   - IDTokenKeyManagement/IDTokenContentEncryption, against
//     IDTokenEncryptionAlgorithms/IDTokenEncryptionEncValues, only if
//     algs.IDTokenKeyManagement is non-zero — encrypted ID token
//     support is opt-in, and Config already requires the pair set
//     together, so checking one non-zero value is enough to trigger
//     checking both.
//   - UserInfo, against UserInfoAlgorithms, only if algs.UserInfo is
//     non-zero — a caller expecting only a plain-JSON UserInfo response
//     leaves this zero, and has nothing to check here at all, exactly
//     like RequestObject/JARM above.
//   - UserInfoKeyManagement/UserInfoContentEncryption, against
//     UserInfoEncryptionAlgorithms/UserInfoEncryptionEncValues, only if
//     algs.UserInfoKeyManagement is non-zero, for the same reason
//     IDTokenKeyManagement is conditional above.
//
// ClientAuthentication and DPoP are never checked: those are this
// client's own signing choice, verified by the server against a
// registered key it resolves itself, not something a server advertises
// as "supported" the way it does for what it produces or accepts as an
// encryption target.
func (d DiscoveredMetadata) SupportsAlgorithms(algs Algorithms) error {
	if !slices.Contains(d.IDTokenAlgorithms, algs.IDToken) {
		return fmt.Errorf("client: issuer does not support %v for id_token; advertises: %v", algs.IDToken, d.IDTokenAlgorithms)
	}
	if algs.RequestObject != 0 && !slices.Contains(d.RequestObjectAlgorithms, algs.RequestObject) {
		return fmt.Errorf("client: issuer does not support %v for request objects; advertises: %v", algs.RequestObject, d.RequestObjectAlgorithms)
	}
	if algs.JARM != 0 && !slices.Contains(d.JARMAlgorithms, algs.JARM) {
		return fmt.Errorf("client: issuer does not support %v for JARM; advertises: %v", algs.JARM, d.JARMAlgorithms)
	}
	if algs.IDTokenKeyManagement != 0 {
		if !slices.Contains(d.IDTokenEncryptionAlgorithms, algs.IDTokenKeyManagement) {
			return fmt.Errorf("client: issuer does not support %v for id_token encryption; advertises: %v", algs.IDTokenKeyManagement, d.IDTokenEncryptionAlgorithms)
		}
		if !slices.Contains(d.IDTokenEncryptionEncValues, algs.IDTokenContentEncryption) {
			return fmt.Errorf("client: issuer does not support %v content encryption for id_token; advertises: %v", algs.IDTokenContentEncryption, d.IDTokenEncryptionEncValues)
		}
	}
	if algs.UserInfo != 0 && !slices.Contains(d.UserInfoAlgorithms, algs.UserInfo) {
		return fmt.Errorf("client: issuer does not support %v for userinfo; advertises: %v", algs.UserInfo, d.UserInfoAlgorithms)
	}
	if algs.UserInfoKeyManagement != 0 {
		if !slices.Contains(d.UserInfoEncryptionAlgorithms, algs.UserInfoKeyManagement) {
			return fmt.Errorf("client: issuer does not support %v for userinfo encryption; advertises: %v", algs.UserInfoKeyManagement, d.UserInfoEncryptionAlgorithms)
		}
		if !slices.Contains(d.UserInfoEncryptionEncValues, algs.UserInfoContentEncryption) {
			return fmt.Errorf("client: issuer does not support %v content encryption for userinfo; advertises: %v", algs.UserInfoContentEncryption, d.UserInfoEncryptionEncValues)
		}
	}
	return nil
}

// IssuerKeySource builds a keys.JWKSIssuerKeySource from this metadata's
// own JWKSURI, using fetcher — typically the same *fapihttp.Client
// already passed to Discover. A thin convenience over
// keys.NewJWKSIssuerKeySource: there's no other JWKS URI a caller would
// sensibly use for this issuer's own verification keys, so this removes
// a line every caller of Discover otherwise writes identically, not a
// new decision the caller has to make.
func (d DiscoveredMetadata) IssuerKeySource(fetcher *fapihttp.Client, cacheTTL time.Duration, opts ...keys.JWKSOption) (*keys.JWKSIssuerKeySource, error) {
	return keys.NewJWKSIssuerKeySource(fetcher, d.JWKSURI, cacheTTL, opts...)
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
	var userinfo fapi.URL
	if doc.UserinfoEndpoint != "" {
		userinfo, err = fapi.ParseEndpointURL(doc.UserinfoEndpoint, opts...)
		if err != nil {
			return DiscoveredMetadata{}, fmt.Errorf("client: discover: userinfo_endpoint: %w", err)
		}
	}

	return DiscoveredMetadata{
		Endpoints: Endpoints{
			Authorization:              authz,
			Token:                      tok,
			PushedAuthorizationRequest: par,
			UserInfo:                   userinfo,
		},
		JWKSURI:                           jwksURI,
		IDTokenAlgorithms:                 supportedAlgorithms(doc.IDTokenSigningAlgValuesSupported),
		RequestObjectAlgorithms:           supportedAlgorithms(doc.RequestObjectSigningAlgValuesSupported),
		JARMAlgorithms:                    supportedAlgorithms(doc.AuthorizationSigningAlgValuesSupported),
		IDTokenEncryptionAlgorithms:       supportedKeyManagementAlgorithms(doc.IDTokenEncryptionAlgValuesSupported),
		IDTokenEncryptionEncValues:        supportedContentEncryptionAlgorithms(doc.IDTokenEncryptionEncValuesSupported),
		UserInfoAlgorithms:                supportedAlgorithms(doc.UserinfoSigningAlgValuesSupported),
		UserInfoEncryptionAlgorithms:      supportedKeyManagementAlgorithms(doc.UserinfoEncryptionAlgValuesSupported),
		UserInfoEncryptionEncValues:       supportedContentEncryptionAlgorithms(doc.UserinfoEncryptionEncValuesSupported),
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

func supportedKeyManagementAlgorithms(values []string) []fapi.KeyManagementAlgorithm {
	var out []fapi.KeyManagementAlgorithm
	for _, v := range values {
		alg, err := fapi.ParseKeyManagementAlgorithm(v)
		if err != nil {
			continue
		}
		out = append(out, alg)
	}
	return out
}

func supportedContentEncryptionAlgorithms(values []string) []fapi.ContentEncryptionAlgorithm {
	var out []fapi.ContentEncryptionAlgorithm
	for _, v := range values {
		alg, err := fapi.ParseContentEncryptionAlgorithm(v)
		if err != nil {
			continue
		}
		out = append(out, alg)
	}
	return out
}
