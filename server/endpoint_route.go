package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/dpop"
)

// EndpointRoute is the public route a request to one of this server's
// endpoints was received at: the endpoint's URL in Config.Endpoints, or
// its RFC 8705 §5 alias in Config.MTLSEndpoints. A DPoP proof names the
// URL of the request it is sent with (RFC 9449 §4.3), so the route
// decides which of the two its htu must name; it never matters for a
// request without a proof.
//
// Set it from the listener or trusted proxy route that received the
// request, never from anything the client sends (the Host header, the
// proof itself): FormRequest.EndpointRoute, or
// TokenEndpointRequest.SetEndpointRoute, or for every request a
// listener receives, WithEndpointRoute. The zero route (unset) is
// PrimaryEndpoint, so a server without mTLS aliases needs none of this.
type EndpointRoute uint8

const (
	// PrimaryEndpoint is the endpoint's URL in Config.Endpoints.
	PrimaryEndpoint EndpointRoute = iota + 1
	// MTLSEndpointAlias is the endpoint's alias in Config.MTLSEndpoints.
	MTLSEndpointAlias
)

// String is the route's name: "primary", "mtls_alias", "unset" for the
// zero route, or EndpointRoute(n) for a value this package doesn't
// define.
func (r EndpointRoute) String() string {
	switch r {
	case 0:
		return "unset"
	case PrimaryEndpoint:
		return "primary"
	case MTLSEndpointAlias:
		return "mtls_alias"
	default:
		return fmt.Sprintf("EndpointRoute(%d)", uint8(r))
	}
}

// endpointRouteKey is the context key WithEndpointRoute marks a
// request's route under.
type endpointRouteKey struct{}

// WithEndpointRoute returns a handler that serves each request with
// next, marked as received at route. FormRequestFromHTTP, and so each
// of this package's *FromHTTP request constructors, takes
// FormRequest.EndpointRoute from the mark, so wrapping the handler of
// the listener serving Config.MTLSEndpoints is all a deployment with
// mTLS aliases needs:
//
//	mtlsListener := &http.Server{
//		Handler:   server.WithEndpointRoute(server.MTLSEndpointAlias, mux),
//		TLSConfig: ..., // asks for a client certificate
//	}
//
// The listener serving Config.Endpoints needs no mark, since an unset
// route is PrimaryEndpoint, though WithEndpointRoute(PrimaryEndpoint,
// mux) says so explicitly. A route set on a request after it is read
// (FormRequest.EndpointRoute, TokenEndpointRequest.SetEndpointRoute)
// takes precedence, and the innermost WithEndpointRoute wins. Mark only
// what the listener or a trusted front end knows: one listener serving
// both routes, told apart by the Host header the client sends, can't
// use this.
func WithEndpointRoute(route EndpointRoute, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), endpointRouteKey{}, route)))
	})
}

// endpointRouteOf is the route WithEndpointRoute marked r with, or the
// zero route.
func endpointRouteOf(r *http.Request) EndpointRoute {
	route, _ := r.Context().Value(endpointRouteKey{}).(EndpointRoute)
	return route
}

// endpointRouteSetters names everything that sets a request's
// EndpointRoute, for the errors a route this server can't serve gets.
const endpointRouteSetters = "server.WithEndpointRoute on the listener, FormRequest.EndpointRoute or TokenEndpointRequest.SetEndpointRoute"

// verifyEndpointDPoP verifies req's proof for the one URL of an
// endpoint that received it — primary, or alias, its mTLS alias, by
// route — never for either (RFC 9449 §4.3): where the two routes keep
// separate replay records, a proof accepted at both could be used once
// at each. See endpointDPoPTarget for the URL each route names.
//
// A proof refused is a 400 invalid_dpop_proof, or a 500 when the
// replay store couldn't answer.
func (s *Server) verifyEndpointDPoP(ctx context.Context, req dpop.VerifyRequest, primary, alias fapi.URL, route EndpointRoute) (dpop.VerifiedProof, *Error) {
	target, targetErr := s.endpointDPoPTarget(primary, alias, route)
	if targetErr != nil {
		return dpop.VerifiedProof{}, targetErr
	}
	req.URL = &target
	verified, err := dpop.Verify(ctx, req)
	if err != nil {
		return dpop.VerifiedProof{}, storeFailure(ctx, err, "failed to check DPoP proof replay", newError(ErrorInvalidDPoPProof, 400, "DPoP proof verification failed", unroutedMismatch(err, primary, alias, route)))
	}
	return verified, nil
}

// endpointDPoPTarget is the URL a DPoP proof received at route must
// name:
//   - PrimaryEndpoint, or no route at all: primary. A proof naming the
//     alias, sent without a route, is refused as any other proof for
//     another URL is (see unroutedMismatch).
//   - MTLSEndpointAlias: alias. An endpoint with none, on a server
//     advertising aliases for others, was called at a URL this server
//     doesn't advertise: the client's mistake, 400 invalid_dpop_proof.
//     On a server advertising no alias at all, no request can arrive
//     at one, so the route is the deployment's mistake: 500.
//   - any other value: the deployment's mistake, 500.
func (s *Server) endpointDPoPTarget(primary, alias fapi.URL, route EndpointRoute) (url.URL, *Error) {
	switch route {
	case 0, PrimaryEndpoint:
		return primary.URL(), nil
	case MTLSEndpointAlias:
		if !alias.IsZero() {
			return alias.URL(), nil
		}
		if s.cfg.MTLSEndpoints.IsZero() {
			return url.URL{}, newError(ErrorServerError, 500, "cannot determine DPoP request target", errors.New("the request's endpoint route is MTLSEndpointAlias, but Config.MTLSEndpoints configures no alias: set that route, with "+endpointRouteSetters+", only for requests received at an mTLS alias"))
		}
		return url.URL{}, newError(ErrorInvalidDPoPProof, 400, "DPoP proof verification failed", errors.New("the request was received at the mTLS alias route, but Config.MTLSEndpoints configures no alias for this endpoint, so no URL there is one a DPoP proof can name"))
	default:
		return url.URL{}, newError(ErrorServerError, 500, "cannot determine DPoP request target", fmt.Errorf("the request's endpoint route %v is not one this package defines: set PrimaryEndpoint or MTLSEndpointAlias with %s", route, endpointRouteSetters))
	}
}

// unroutedMismatch is err, the reason dpop.Verify refused a proof,
// with a hint for the deployment when the request carried no route,
// the proof named another URL, and the endpoint has a distinct mTLS
// alias: a proof for the alias fails so when the listener serving it
// doesn't mark its requests. The hint is in the error's cause only,
// which the response doesn't carry.
func unroutedMismatch(err error, primary, alias fapi.URL, route EndpointRoute) error {
	if route != 0 || !errors.Is(err, dpop.ErrURIMismatch) || alias.IsZero() || alias.String() == primary.String() {
		return err
	}
	return fmt.Errorf("%w (the request had no endpoint route, so the proof was checked against %s; if it was received at the mTLS alias %s, set its route with %s)", err, primary.String(), alias.String(), endpointRouteSetters)
}
