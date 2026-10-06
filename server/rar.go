package server

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/storage"
)

// authorizationDetailsParameter is the RFC 9396 §2 wire name shared by PAR,
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
// 9396) detail objects a client is entitled to receive — used in three
// distinct roles, one per Dependencies field it may be assigned to:
//
//   - Dependencies.ClientCredentialsRARPolicy: RFC 9396 §6's "client's
//     policy" check for the client_credentials grant, consulted at
//     token-issuance time (RequestClientCredentialsToken). This grant
//     has no resource owner at all, so beyond the client's registered
//     types this is the only entitlement check it gets: with
//     AllowRequestedAuthorizationDetails here, a client is granted any
//     content — any amount, any account — of the types it may request.
//   - Dependencies.AuthorizationCodeRARPolicy / Dependencies.CIBARARPolicy: a
//     request-time gate for the Authorization Code and
//     CIBA grants respectively — two independent fields (not one shared
//     between them, since neither checkExtensions nor
//     checkBackchannelExtensions tells a RARPolicy which grant it's
//     being consulted for) — consulted before a request's own
//     authorization_details is ever stored or shown to a resource
//     owner, so an unentitled client can't even *ask* for a detail
//     type on that grant, regardless of what a resource owner might
//     otherwise approve. For Authorization Code this runs at PAR
//     submission time (checkExtensions) — FAPI 2 mandates PAR for this
//     grant, so PAR is just where the request arrives, not a distinct
//     grant of its own. Both grants' own resource-owner grant step
//     (validateGrantedAuthorizationDetails, driven by
//     GrantedAuthorization.AuthorizationDetails) remains the primary
//     entitlement check either way — this is additional narrowing on
//     top of it, not a replacement for it.
//
// Which types a client may request at all is decided before any policy
// runs, by the client's registration
// (storage.RegisteredClientConfig.AuthorizationDetailsTypes): a policy
// only ever sees types the client is registered for. The policy then
// decides on the details themselves.
//
// All three fields are optional, but none's absence is permissive: a
// request naming authorization_details with no policy configured for
// the applicable field is refused (applyRARPolicy), even of a type the
// client is registered for. A registration says which types a client
// may ask for; nothing is granted, or even put to a resource owner,
// without a policy decision saying so — AllowRequestedAuthorizationDetails
// when the registration is the only rule.
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

// AllowRequestedAuthorizationDetails is a RARPolicy that grants every
// detail requested, as requested. The server has already refused any
// type the client isn't registered for
// (storage.RegisteredClientConfig.AuthorizationDetailsTypes), so this
// suits a deployment whose only rule is which types each client may use.
// One that also checks the details themselves — a payment limit, a
// standing mandate — supplies its own RARPolicy.
type AllowRequestedAuthorizationDetails struct{}

// Authorize implements RARPolicy.
func (AllowRequestedAuthorizationDetails) Authorize(_ context.Context, _ fapi.ClientID, requested []json.RawMessage) ([]json.RawMessage, error) {
	return requested, nil
}

// applyRARPolicy narrows requested (already structurally validated by
// parseRequestedAuthorizationDetails — a registered type, correct
// shape, within bounds) against policy — the shared implementation
// behind RequestClientCredentialsToken's own
// Dependencies.ClientCredentialsRARPolicy check and the Authorization
// Code and CIBA grants' own request-time
// Dependencies.AuthorizationCodeRARPolicy/CIBARARPolicy checks.
// requested empty (no authorization_details in the request at all)
// returns (nil, nil) unconditionally, even with policy == nil — a
// request that never asked for anything has nothing for a policy to
// decide. Every caller wraps a non-nil error in
// ErrorInvalidAuthorizationDetails (RFC 9396 §6's own dedicated code
// for exactly this decision).
func (s *Server) applyRARPolicy(ctx context.Context, client storage.RegisteredClient, policy RARPolicy, requested json.RawMessage) (json.RawMessage, error) {
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
	if err := checkAuthorizationDetailsTypes(client, requestedObjects); err != nil {
		if unknown := unknownRARTypes(s.cfg.RAR, client.AuthorizationDetailsTypes()); len(unknown) > 0 {
			// For the logs: a registration naming a type this server
			// doesn't know is usually a typo.
			return nil, fmt.Errorf("%w; the client's registration lists %q, which Config.RAR doesn't register", err, unknown)
		}
		return nil, err
	}
	granted, err := policy.Authorize(ctx, client.ID(), requestedObjects)
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

// checkAuthorizationDetailsTypes refuses a requested detail whose type
// the client isn't registered for
// (storage.RegisteredClientConfig.AuthorizationDetailsTypes, RFC 9396
// §10). It runs before the RARPolicy, so a policy only ever sees types
// the client may request at all.
func checkAuthorizationDetailsTypes(client storage.RegisteredClient, details []json.RawMessage) error {
	for _, d := range details {
		var typed struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(d, &typed); err != nil {
			return fmt.Errorf("failed to decode validated authorization_details: %w", err)
		}
		if !client.AllowsAuthorizationDetailsType(typed.Type) {
			return fmt.Errorf("authorization_details type %q is not registered for this client", typed.Type)
		}
	}
	return nil
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

// unknownRARTypes returns those of types registry doesn't register: all
// of them for a nil registry.
func unknownRARTypes(registry *extension.RARRegistry, types []string) []string {
	var known []string
	if registry != nil {
		known = registry.Types()
	}
	var unknown []string
	for _, typ := range types {
		if !slices.Contains(known, typ) {
			unknown = append(unknown, typ)
		}
	}
	return unknown
}

// CheckClientRegistration reports what in client's registration this
// server can't honour: today, Rich Authorization Request types
// (storage.RegisteredClientConfig.AuthorizationDetailsTypes) Config.RAR
// doesn't register — usually a typo. Nothing else reports it before a
// request for that type is refused, since clients live in the
// ClientRepository, out of New's sight. Call it when registering a
// client, or over every client at startup; nil means nothing found.
func (s *Server) CheckClientRegistration(client storage.RegisteredClient) error {
	if unknown := unknownRARTypes(s.cfg.RAR, client.AuthorizationDetailsTypes()); len(unknown) > 0 {
		return fmt.Errorf("server: client %q: authorization_details_types %q aren't registered in Config.RAR", client.ID(), unknown)
	}
	return nil
}
