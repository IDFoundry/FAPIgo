package server

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/idfoundry/fapigo/federation"
	"github.com/idfoundry/fapigo/keys"
)

// EntityConfiguration signs and returns this server's own OpenID
// Federation 1.0 Entity Configuration (federation.SelfIssuer's own
// EntityConfiguration), carrying metadata as its own "metadata" claim —
// build it yourself, typically a federation_entity object plus an
// openid_provider object mirroring this server's own Metadata, and pass
// it here; this method resolves this server's own federation signing
// key and signs, and derives only two metadata values from Config: when
// automatic registration is configured (Config.AutomaticRegistration has
// TrustAnchors), it sets the openid_provider object's
// subject_types_supported to AutomaticRegistrationSubjectTypes, what a
// Relying Party registering through federation may ask for, which can be
// fewer types than Metadata advertises to statically registered
// clients, and adds "automatic" to its
// client_registration_types_supported (OpenID Federation 1.0 §12.1).
// The openid_provider issuer, when present, must be
// Config.Federation.EntityID (§5.1.3). The caller's map is left
// unchanged. Serve the result verbatim, with Content-Type
// federation.EntityStatementContentType, at
// Config.Federation.EntityID+federation.WellKnownPath — this package
// still doesn't own HTTP transport itself.
//
// Fails if Config.Federation.EntityID is unset — see FederationConfig's
// own doc comment. trustMarks are published as the "trust_marks"
// claim, as federation.SelfIssuer.EntityConfiguration describes.
func (s *Server) EntityConfiguration(ctx context.Context, metadata map[string]json.RawMessage, trustMarks ...federation.RawTrustMark) (string, error) {
	if s.cfg.Federation.EntityID == "" {
		return "", fmt.Errorf("server: federation self-issuance is not configured (config.federation.entity_id is empty)")
	}
	signer, kid, err := s.newSigner(ctx, keys.FederationEntitySigning, s.cfg.Federation.Algorithm)
	if err != nil {
		return "", fmt.Errorf("server: resolve federation signing key: %w", err)
	}
	keySet, err := keys.PublicJWKS(ctx, []keys.SigningKeyUse{
		{Manager: s.deps.Keys, Purpose: keys.FederationEntitySigning, Algorithm: s.cfg.Federation.Algorithm},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("server: build federation jwks: %w", err)
	}
	jwks, err := json.Marshal(keySet)
	if err != nil {
		return "", fmt.Errorf("server: marshal federation jwks: %w", err)
	}

	issuer, err := federation.NewSelfIssuer(federation.SelfIssueConfig{
		EntityID:       s.cfg.Federation.EntityID,
		AuthorityHints: s.cfg.Federation.AuthorityHints,
		Lifetime:       s.cfg.Federation.Lifetime,
	}, federation.SelfIssueDependencies{
		Signer: signer, Algorithm: s.cfg.Federation.Algorithm, KeyID: kid,
		JWKS: jwks, Clock: s.deps.Clock,
	})
	if err != nil {
		return "", fmt.Errorf("server: %w", err)
	}
	metadata, err = s.withAutomaticRegistrationMetadata(metadata)
	if err != nil {
		return "", err
	}
	return issuer.EntityConfiguration(metadata, trustMarks...)
}

// withAutomaticRegistrationMetadata returns metadata with its
// openid_provider object's subject_types_supported set to
// AutomaticRegistrationSubjectTypes, and "automatic" added to its
// client_registration_types_supported (OpenID Federation 1.0 §12.1: "An
// OP that supports Automatic Registration MUST include the automatic
// keyword"), when automatic registration is configured and metadata has
// an openid_provider object; otherwise metadata itself. It copies
// rather than changing the caller's map.
func (s *Server) withAutomaticRegistrationMetadata(metadata map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	raw, ok := metadata[openIDProviderEntityType]
	if !ok || len(s.cfg.AutomaticRegistration.TrustAnchors) == 0 {
		return metadata, nil
	}
	var op map[string]json.RawMessage
	if err := json.Unmarshal(raw, &op); err != nil || op == nil {
		return nil, fmt.Errorf("server: entity configuration: %s metadata must be a JSON object", openIDProviderEntityType)
	}
	types, err := json.Marshal(s.AutomaticRegistrationSubjectTypes())
	if err != nil {
		return nil, fmt.Errorf("server: entity configuration: %w", err)
	}
	op["subject_types_supported"] = types
	registrationTypes, err := withAutomaticRegistrationType(op["client_registration_types_supported"])
	if err != nil {
		return nil, err
	}
	op["client_registration_types_supported"] = registrationTypes
	rewritten, err := json.Marshal(op)
	if err != nil {
		return nil, fmt.Errorf("server: entity configuration: %w", err)
	}
	out := maps.Clone(metadata)
	out[openIDProviderEntityType] = rewritten
	return out, nil
}

// withAutomaticRegistrationType returns raw, a
// client_registration_types_supported value (absent when empty), with
// "automatic" added if it isn't already listed.
func withAutomaticRegistrationType(raw json.RawMessage) (json.RawMessage, error) {
	var types []string
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &types); err != nil {
			return nil, fmt.Errorf("server: entity configuration: %s client_registration_types_supported must be an array of strings: %w", openIDProviderEntityType, err)
		}
	}
	if !slices.Contains(types, "automatic") {
		types = append(types, "automatic")
	}
	return json.Marshal(types)
}

// openIDProviderEntityType is the Entity Type identifier an OpenID
// Provider's metadata is published under (OpenID Federation 1.0 §5.1.3).
const openIDProviderEntityType = "openid_provider"
