package server

import (
	"encoding/json"
	"fmt"

	"github.com/idfoundry/fapigo/extension"
)

// authorizationDetailsParameter is the RFC 9396 §5 wire name shared by PAR
// and CIBA backchannel authentication requests — structurally distinct
// from an ordinary extension.Definition-backed parameter (it's a bounded
// array of typed detail objects, not a single scalar/array value), so it's
// validated against Config.RAR rather than Config.Extensions, even though
// both end up stored the same way: as one more entry in the request's own
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
// picking one error code itself.
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
