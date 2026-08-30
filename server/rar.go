package server

import (
	"context"
	"encoding/json"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
)

// authorizationDetailsParameter is the RFC 9396 §5 wire name shared by PAR,
// CIBA backchannel authentication requests, and client_credentials token
// requests (RFC 9396 §6) — structurally distinct from an ordinary
// extension.Definition-backed parameter (it's a bounded array of typed
// detail objects, not a single scalar/array value), so it's validated
// against Config.RAR rather than Config.Extensions, even though both end
// up stored the same way: as one more entry in the request's own
// Parameters map.
const authorizationDetailsParameter = "authorization_details"

// parseRequestedAuthorizationDetails validates params' own
// "authorization_details" member (if any) against Config.RAR, returning it
// as validated raw JSON array once RARRegistry.Parse has confirmed its
// shape and bounds — nil if params carries no such member. Config.RAR ==
// nil rejects any request that carries the parameter at all — see
// Config.RAR's own doc comment for why "unconfigured" is deliberately not
// the same as "an empty registry accepting nothing extra."
//
// The caller wraps a non-nil error in whichever *Error code its own flow
// uses for a malformed parameter — checkExtensions (PAR) and
// checkBackchannelExtensions (CIBA) already apply the same per-flow split
// for the generic extension.Registry, and this mirrors it rather than
// picking one error code itself; RequestClientCredentialsToken (which has
// no request-object concept at all) always uses ErrorInvalidRequest.
func (s *Server) parseRequestedAuthorizationDetails(params map[string]json.RawMessage) (json.RawMessage, error) {
	raw, ok := params[authorizationDetailsParameter]
	if !ok {
		return nil, nil
	}
	if s.cfg.RAR == nil {
		return nil, fmt.Errorf("authorization_details is not supported by this server")
	}
	if _, err := s.cfg.RAR.Parse(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// validateGrantedAuthorizationDetails checks a resource owner's granted
// subset (granted — one entry per approved detail object, from
// GrantedAuthorization.AuthorizationDetails) against requestedRaw (the
// original request's own validated "authorization_details" array, as
// returned by parseRequestedAuthorizationDetails and re-extracted from the
// stored request Parameters at completion time). It returns the granted
// set re-encoded as one canonical JSON array, ready to persist and later
// embed as a token claim — nil if granted is empty.
//
// A non-empty granted with an empty/absent requestedRaw is always
// rejected: there is nothing it could be a subset of.
func (s *Server) validateGrantedAuthorizationDetails(requestedRaw json.RawMessage, granted []json.RawMessage) (json.RawMessage, error) {
	if len(granted) == 0 {
		return nil, nil
	}
	if len(requestedRaw) == 0 {
		return nil, fmt.Errorf("authorization_details was granted but never requested")
	}
	if s.cfg.RAR == nil {
		return nil, fmt.Errorf("authorization_details is not supported by this server")
	}

	grantedRaw, _ := json.Marshal(granted) // marshaling a []json.RawMessage cannot fail

	requestedValues, err := s.cfg.RAR.Parse(requestedRaw)
	if err != nil {
		return nil, fmt.Errorf("stored requested authorization_details is invalid: %w", err)
	}
	grantedValues, err := s.cfg.RAR.Parse(grantedRaw)
	if err != nil {
		return nil, err
	}
	if err := s.cfg.RAR.ValidateGrant(requestedValues, grantedValues); err != nil {
		return nil, err
	}
	return grantedRaw, nil
}

// withAuthorizationDetails merges details (RFC 9396's "authorization_details"
// top-level claim) into base, for an issued access token's own claims —
// mirrors withRequestedUserinfoClaims exactly, and is a no-op (returns base
// unchanged) when details is empty.
func withAuthorizationDetails(details json.RawMessage, base map[string]json.RawMessage) map[string]json.RawMessage {
	if len(details) == 0 {
		return base
	}
	merged := make(map[string]json.RawMessage, len(base))
	for k, v := range base {
		merged[k] = v
	}
	merged[authorizationDetailsParameter] = details
	return merged
}

// RARPolicy decides which of a set of Rich Authorization Requests (RFC
// 9396) detail objects a client is entitled to receive — used in two
// distinct roles, one per Dependencies field it may be assigned to:
//
//   - Dependencies.ClientCredentialsRARPolicy: RFC 9396 §6's "client's
//     policy" check for the client_credentials grant, consulted at
//     token-issuance time (RequestClientCredentialsToken). This grant
//     has no resource owner at all, so this is the *only* entitlement
//     check it ever gets.
//   - Dependencies.RARRequestPolicy: a defense-in-depth, request-time
//     gate for PAR and CIBA — consulted before a request's own
//     authorization_details is ever stored or shown to a resource
//     owner (checkExtensions/checkBackchannelExtensions), so an
//     unentitled client can't even *ask* for a detail type, regardless
//     of what a resource owner might otherwise approve. PAR/CIBA's own
//     resource-owner grant step (validateGrantedAuthorizationDetails,
//     driven by GrantedAuthorization.AuthorizationDetails) remains the
//     primary entitlement check for those two flows either way — this
//     is additional narrowing on top of it, not a replacement for it.
//
// Both fields are optional, but neither's absence is permissive: a
// request naming authorization_details with no policy configured for
// the applicable field is refused (applyRARPolicy), the same
// "unconfigured is not the same as an empty registry accepting nothing
// extra" stance Config.RAR itself takes — every registered RAR type is
// available to be *requested* once Config.RAR is set, but nothing is
// ever *entitled* to be granted, or even asked for, without an explicit
// policy decision saying so.
type RARPolicy interface {
	// Authorize returns the subset of requested (each entry one of its
	// already-validated — RARRegistry.Parse has run — detail objects)
	// that clientID's own policy permits, narrowed or reordered however
	// the implementation decides; applyRARPolicy checks the result is
	// an acceptable narrowing of requested the same way
	// validateGrantedAuthorizationDetails already checks a resource
	// owner's own decision (RARDefinition.ValidateGrant, or exact-match
	// if that hook is nil for a given type). Returning an empty granted
	// (no error) is a legitimate "deny everything requested" decision —
	// applyRARPolicy surfaces that as ErrorInvalidAuthorizationDetails
	// itself, so an implementation doesn't need to return an error just
	// to express a full denial. Returning an error instead signals a
	// policy-evaluation failure (a lookup error, an unreachable policy
	// engine) — also surfaced as ErrorInvalidAuthorizationDetails, since
	// the caller cannot tell the two apart from the client-visible
	// response.
	Authorize(ctx context.Context, clientID fapi.ClientID, requested []json.RawMessage) ([]json.RawMessage, error)
}

// applyRARPolicy narrows requested (already structurally validated by
// parseRequestedAuthorizationDetails — a registered type, correct
// shape, within bounds) against policy — the shared implementation
// behind both RequestClientCredentialsToken's own
// Dependencies.ClientCredentialsRARPolicy check and PAR/CIBA's
// request-time Dependencies.RARRequestPolicy check. requested empty (no
// authorization_details in the request at all) returns (nil, nil)
// unconditionally, even with policy == nil — a request that never asked
// for anything has nothing for a policy to decide. Every caller wraps a
// non-nil error in ErrorInvalidAuthorizationDetails (RFC 9396 §6's own
// dedicated code for exactly this decision).
func (s *Server) applyRARPolicy(ctx context.Context, clientID fapi.ClientID, policy RARPolicy, requested json.RawMessage) (json.RawMessage, error) {
	if len(requested) == 0 {
		return nil, nil
	}
	if policy == nil {
		return nil, fmt.Errorf("no authorization_details policy is configured")
	}
	var requestedObjects []json.RawMessage
	if err := json.Unmarshal(requested, &requestedObjects); err != nil {
		return nil, fmt.Errorf("failed to decode validated authorization_details: %w", err)
	}
	granted, err := policy.Authorize(ctx, clientID, requestedObjects)
	if err != nil {
		return nil, fmt.Errorf("authorization_details policy rejected the request: %w", err)
	}
	if len(granted) == 0 {
		return nil, fmt.Errorf("policy does not permit any of the requested authorization_details")
	}
	validated, err := s.validateGrantedAuthorizationDetails(requested, granted)
	if err != nil {
		return nil, fmt.Errorf("policy decision is not an acceptable narrowing of the request: %w", err)
	}
	return validated, nil
}

// rarValuesFromStoredParameters best-effort re-parses an
// "authorization_details" member out of a request's own already-validated,
// stored Parameters — for InteractionRequest/BackchannelInteractionRequest
// construction, mirroring how interactionRequestFrom/
// backchannelInteractionRequestFrom already re-extract scope/login_hint
// from the same map rather than caching them separately. A parse failure
// here would mean the stored value was corrupted after having already
// passed parseRequestedAuthorizationDetails at PAR/BC-Auth time, so it is
// treated the same way a malformed stored scope would be: silently
// ignored, leaving the zero value, rather than surfaced as a caller-facing
// error this deep into the flow.
func rarValuesFromStoredParameters(registry *extension.RARRegistry, params map[string]json.RawMessage) extension.RARValues {
	if registry == nil {
		return extension.RARValues{}
	}
	raw, ok := params[authorizationDetailsParameter]
	if !ok {
		return extension.RARValues{}
	}
	values, err := registry.Parse(raw)
	if err != nil {
		return extension.RARValues{}
	}
	return values
}
