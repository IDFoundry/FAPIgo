package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/idfoundry/fapigo/internal/resourceindicator"
	"github.com/idfoundry/fapigo/storage"
)

// resourceParameter is RFC 8707's "resource" parameter: a resource
// indicator, repeatable.
const resourceParameter = "resource"

// ResourcePolicy decides RFC 8707 resource indicators beyond
// Config.Resources, for a deployment whose resources aren't a fixed
// list — an authorization server shared by OpenID4VCI Credential
// Issuers that admits each issuer naming it in its metadata, say. It is
// asked only about resources Config.Resources doesn't list, and only
// once they've passed the client's own
// storage.RegisteredClientConfig.AllowedResources.
//
// AllowResources returns nil to accept every resource in resources for
// client, an error wrapping ErrResourceNotAllowed to refuse the request
// with invalid_target, and any other error when it couldn't decide (a
// store or network failure), which is server_error: never read as a
// refusal, so a client isn't told its request is wrong when the policy
// couldn't answer.
//
// It's asked at every access token a grant issues, not only when the
// grant is made: at the authorization code exchange, at each refresh and
// at each CIBA token request, for the resources that token would be
// restricted to, so a resource it no longer allows stops being issued
// for. Keep it cheap — cache what it looks up. A client chooses what
// it's asked about, up to 16 resources a request, each up to 2048
// bytes, so don't fetch from a resource indicator without first
// checking it's one you might serve.
//
// Resources are compared exactly, as strings, here and at the resource
// server: a policy that accepts a resource by normalizing it (host case,
// a trailing slash, a default port) still gets a token addressed to the
// client's own spelling, which a resource server expecting another
// spelling refuses. Accept only the spelling your resource servers
// verify with.
type ResourcePolicy interface {
	AllowResources(ctx context.Context, client storage.RegisteredClient, resources []string) error
}

// ErrResourceNotAllowed is what a ResourcePolicy's error wraps to refuse
// a resource: invalid_target.
var ErrResourceNotAllowed = errors.New("server: resource not allowed")

// resourceIndicatorsEnabled reports whether this server accepts RFC
// 8707 resource indicators: when Config.Resources or a ResourcePolicy is
// configured. Otherwise the "resource" parameter is ignored entirely, as
// any unregistered parameter is, and every access token's audience is
// the issuer.
func (s *Server) resourceIndicatorsEnabled() bool {
	return len(s.cfg.Resources) > 0 || s.deps.ResourcePolicy != nil
}

// takeResourceParameters splits a form request's "resource" parameters
// (RFC 8707 §2: repeatable) from the rest, which then go through the
// usual duplicate-refusing parsing. With resource indicators disabled
// it returns params unchanged, so "resource" stays an ordinary,
// ignored parameter.
func (s *Server) takeResourceParameters(params []FormParameter) ([]FormParameter, []string) {
	if !s.resourceIndicatorsEnabled() {
		return params, nil
	}
	return splitResourceParameters(params)
}

// splitResourceParameters separates params' "resource" parameters from
// the rest. Too many parameters are returned unsplit, for
// formParametersToMap to refuse, so the resources don't escape its
// bound.
func splitResourceParameters(params []FormParameter) ([]FormParameter, []string) {
	if len(params) > maxFormParameters {
		return params, nil
	}
	rest := make([]FormParameter, 0, len(params))
	var resources []string
	for _, p := range params {
		if p.Name == resourceParameter {
			resources = append(resources, p.Value)
			continue
		}
		rest = append(rest, p)
	}
	return rest, resources
}

// resourcesFromParameters reads a request object's (or CIBA request's)
// "resource" member: a JSON string, or an array of strings for several
// (RFC 8707 §2.1). Nil when absent or when resource indicators are
// disabled. The member itself is left for the extension check, which
// drops it as an unregistered parameter, so it isn't stored with the
// others.
func (s *Server) resourcesFromParameters(params map[string]json.RawMessage) ([]string, *Error) {
	if !s.resourceIndicatorsEnabled() {
		return nil, nil
	}
	raw, ok := params[resourceParameter]
	if !ok {
		return nil, nil
	}
	if !decodesLosslessly(raw) {
		return nil, newError(ErrorInvalidTarget, 400, "resource must be valid UTF-8, without unpaired surrogate escapes", nil)
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil || len(many) == 0 {
		return nil, newError(ErrorInvalidTarget, 400, "resource must be a string or a non-empty array of strings", err)
	}
	return many, nil
}

// decodesLosslessly reports whether raw, a JSON value, decodes without
// encoding/json altering any string in it. encoding/json doesn't refuse
// invalid UTF-8 or a \u escape of an unpaired UTF-16 surrogate: it
// replaces each with U+FFFD. A resource decoded that way isn't the one
// the client signed, and a token issued for it wouldn't name the
// resource the client asked for, so it's refused instead. raw must
// already be valid JSON.
func decodesLosslessly(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++ // the escaped character
		if i >= len(raw) || raw[i] != 'u' {
			continue
		}
		n, ok := unicodeEscapeLength(raw, i-1)
		if !ok {
			return false
		}
		i += n - 2 // past the escape (or surrogate pair); the loop adds one
	}
	return true
}

// unicodeEscapeLength returns the length of the \u escape starting at
// raw[i] (its backslash), or of the surrogate pair it starts, and
// whether it decodes as written: a high surrogate must be followed
// directly by an escaped low one, and a low one can't stand alone.
func unicodeEscapeLength(raw []byte, i int) (int, bool) {
	r, ok := hexRune(raw, i+2)
	switch {
	case !ok:
		return 0, false
	case !utf16.IsSurrogate(r):
		return 6, true
	case r >= 0xdc00:
		return 0, false // a low surrogate on its own
	}
	low, ok := hexRune(raw, i+8)
	if !ok || raw[i+6] != '\\' || raw[i+7] != 'u' || low < 0xdc00 || low > 0xdfff {
		return 0, false
	}
	return 12, true
}

// hexRune reads the four hex digits of a \u escape starting at raw[i].
func hexRune(raw []byte, i int) (rune, bool) {
	if i < 0 || i+4 > len(raw) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(raw[i:i+4]), 16, 16)
	if err != nil {
		return 0, false
	}
	return rune(n), true
}

// checkRequestedResources validates the resource indicators client
// named: each an absolute URI without a fragment (RFC 8707 §2), within
// the client's AllowedResources, and listed in Config.Resources or
// accepted by the ResourcePolicy. It returns them de-duplicated in the
// order given. A request naming none is first given the client's
// default (defaultResources), which is then checked the same way; nil
// when there is none.
func (s *Server) checkRequestedResources(ctx context.Context, client storage.RegisteredClient, requested []string) ([]string, *Error) {
	if len(requested) == 0 {
		var err *Error
		if requested, err = s.defaultResources(client); err != nil || len(requested) == 0 {
			return nil, err
		}
	}
	if len(requested) > resourceindicator.MaxPerRequest {
		return nil, newError(ErrorInvalidTarget, 400, fmt.Sprintf("at most %d resource indicators may be requested", resourceindicator.MaxPerRequest), nil)
	}
	resources := make([]string, 0, len(requested))
	var unlisted []string
	for _, r := range requested {
		if err := resourceindicator.Check(r); err != nil {
			return nil, newError(ErrorInvalidTarget, 400, "resource must be an absolute URI without a fragment", err)
		}
		if slices.Contains(resources, r) {
			continue
		}
		if !client.AllowsResource(r) {
			return nil, newError(ErrorInvalidTarget, 400, "resource is not one this client may request", nil)
		}
		resources = append(resources, r)
		if !slices.Contains(s.cfg.Resources, r) {
			unlisted = append(unlisted, r)
		}
	}
	if len(unlisted) == 0 {
		return resources, nil
	}
	if s.deps.ResourcePolicy == nil {
		return nil, newError(ErrorInvalidTarget, 400, "resource is not one this server serves", nil)
	}
	switch err := s.deps.ResourcePolicy.AllowResources(ctx, client, slices.Clone(unlisted)); {
	case err == nil:
		return resources, nil
	case errors.Is(err, ErrResourceNotAllowed):
		return nil, newError(ErrorInvalidTarget, 400, "resource is not one this server serves", err)
	default:
		return nil, newError(ErrorServerError, 500, "failed to decide the requested resources", err)
	}
}

// defaultResources is what a request from client naming no resource is
// for. A client without AllowedResources gets none, so its tokens are
// addressed to the issuer. A client confined by AllowedResources can't
// be given an issuer-audience token, which every resource server that
// accepts the issuer as an audience would take, whatever the list says:
// with one entry, the request is for that one; with more, it must name
// which, so it's invalid_target. With resource indicators disabled,
// there is never a default: the "resource" parameter is ignored, and
// every token is addressed to the issuer.
func (s *Server) defaultResources(client storage.RegisteredClient) ([]string, *Error) {
	if !s.resourceIndicatorsEnabled() {
		return nil, nil
	}
	allowed := client.AllowedResources()
	if len(allowed) > 1 {
		return nil, newError(ErrorInvalidTarget, 400, "a resource is required: this client may request more than one, so must name which", nil)
	}
	return allowed, nil
}

// narrowResources returns the resources a token request may have its
// access token restricted to: requested, when it named any, which must
// all be among granted (RFC 8707 §2.2: a token request may narrow the
// grant's resources, never widen them), and otherwise granted.
func narrowResources(granted, requested []string) ([]string, *Error) {
	if len(requested) == 0 {
		return granted, nil
	}
	if len(requested) > resourceindicator.MaxPerRequest {
		return nil, newError(ErrorInvalidTarget, 400, fmt.Sprintf("at most %d resource indicators may be requested", resourceindicator.MaxPerRequest), nil)
	}
	narrowed := make([]string, 0, len(requested))
	for _, r := range requested {
		if !slices.Contains(granted, r) {
			return nil, newError(ErrorInvalidTarget, 400, "resource was not granted", nil)
		}
		if !slices.Contains(narrowed, r) {
			narrowed = append(narrowed, r)
		}
	}
	return narrowed, nil
}

// allowedGrantAudience is checkGrantStillAllowed for a token request
// from grant asking for scope, followed by narrowedAudience for the
// resources it requested.
func (s *Server) allowedGrantAudience(ctx context.Context, client storage.RegisteredClient, grant grantRecord, scope, requested []string) (string, []string, *Error) {
	if err := s.checkGrantStillAllowed(client, grant, scope); err != nil {
		return "", nil, err
	}
	return s.narrowedAudience(ctx, client, grant.Resources, requested)
}

// usableGrantAudience is allowedGrantAudience for the CIBA token
// exchange, whose grant checkGrantUsable checks.
func (s *Server) usableGrantAudience(ctx context.Context, client storage.RegisteredClient, grant grantRecord, requested []string) (string, []string, *Error) {
	if err := s.checkGrantUsable(ctx, client, grant); err != nil {
		return "", nil, err
	}
	return s.narrowedAudience(ctx, client, grant.Resources, requested)
}

// narrowedAudience is the audience of an access token from a grant for
// granted resources, narrowed to requested (see narrowResources).
//
// The resources the token would be restricted to are then checked again
// as a request naming them would be (checkRequestedResources), as
// checkGrantStillAllowed checks the grant's scopes: a grant was checked
// when it was made, but a resource may since have been removed from the
// client's AllowedResources or from Config.Resources, or be refused by
// the ResourcePolicy, or resource indicators turned off altogether. It
// refuses rather than narrowing silently, with invalid_target, and the
// client can still get a token by naming only resources it may still
// use. When none is — resource indicators turned off, say — it must
// authorize again. The refresh token keeps all of the grant's
// resources, so one allowed again later can be named again.
//
// A grant without resources, made before the client was confined by
// AllowedResources, gets the client's default as a request naming none
// would (defaultResources): its single allowed resource, or
// invalid_target when it has several, so it must authorize again.
func (s *Server) narrowedAudience(ctx context.Context, client storage.RegisteredClient, granted, requested []string) (string, []string, *Error) {
	resources, err := narrowResources(granted, requested)
	if err != nil {
		return "", nil, err
	}
	if resources, err = s.checkRequestedResources(ctx, client, resources); err != nil {
		return "", nil, err
	}
	audience, audiences := s.accessTokenAudience(resources)
	return audience, audiences, nil
}

// accessTokenAudience returns an access token's audience: the resources
// it's restricted to, or, without any, this server's issuer identifier.
// audience is AccessTokenParams.Audience — the first resource, or the
// issuer — and audiences AccessTokenParams.Audiences.
func (s *Server) accessTokenAudience(resources []string) (audience string, audiences []string) {
	if len(resources) == 0 {
		return s.cfg.Issuer.String(), nil
	}
	return resources[0], slices.Clone(resources)
}

// validateResources checks Config.Resources at New: each a resource
// indicator RFC 8707 §2 allows, none repeated.
func validateResources(resources []string) error {
	for i, r := range resources {
		if err := resourceindicator.Check(r); err != nil {
			return fmt.Errorf("server: config: resources[%d]: %w", i, err)
		}
		if slices.Contains(resources[:i], r) {
			return fmt.Errorf("server: config: resources[%d]: %q is repeated", i, r)
		}
	}
	return nil
}
