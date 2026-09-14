package server

import (
	"context"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/clientassertion"
	"github.com/idfoundry/fapigo/internal/clientattestation"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// resolveAttestationHeaders reduces attestations/pops — a request's own
// ClientAttestations/ClientAttestationPoPs fields — down to the single
// pair of values this package's attestation verification expects, per
// draft-ietf-oauth-attestation-based-client-auth-07 §9 rule 1 ("The
// HTTP request contains exactly one field OAuth-Client-Attestation and
// one field OAuth-Client-Attestation-PoP"). Mirrors resolveDPoPProof's
// own "reject more than one, regardless of whether any individual value
// would otherwise have verified" stance. Returns ("", "", nil) when
// neither header was sent at all — a caller uses that to fall through
// to another client authentication mechanism, the same way an absent
// client_assertion does.
func resolveAttestationHeaders(attestations, pops []string) (attestation, pop string, err *Error) {
	if len(attestations) == 0 && len(pops) == 0 {
		return "", "", nil
	}
	if len(attestations) != 1 {
		return "", "", newError(ErrorInvalidClient, 401, "exactly one OAuth-Client-Attestation header is required", nil)
	}
	if len(pops) != 1 {
		return "", "", newError(ErrorInvalidClient, 401, "exactly one OAuth-Client-Attestation-PoP header is required", nil)
	}
	return attestations[0], pops[0], nil
}

// authenticateClientViaAttestation verifies attestation/pop (OAuth 2.0
// Attestation-Based Client Authentication draft-07) and resolves the
// registered client the Client Attestation's sub claim names.
func (s *Server) authenticateClientViaAttestation(ctx context.Context, attestation, pop string) (storage.RegisteredClient, clientassertion.VerifiedAssertion, *Error) {
	if !s.cfg.AttestationBasedClientAuthentication {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "attestation-based client authentication is not enabled", nil)
	}

	parsedAttestation, err := clientattestation.Parse(attestation)
	if err != nil {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "malformed client attestation", err)
	}
	parsedPoP, err := clientattestation.ParsePoP(pop)
	if err != nil {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "malformed client attestation pop", err)
	}

	client, err := s.deps.Clients.ResolveClient(ctx, fapi.ClientID(parsedAttestation.ClaimedSubject()))
	if err != nil {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "unknown client", err)
	}
	if client.ClientAuthMethod() != storage.ClientAuthMethodAttestation {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "client is not registered for attestation-based client authentication", nil)
	}

	if !s.cfg.Algorithms.ClientAttestation.Contains(client.ClientAttestationAlgorithm()) {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "client attestation algorithm is not permitted", nil)
	}

	attesterPub, err := s.resolveClientKey(ctx, client.ID(), keys.AttestationVerification, client.ClientAttestationAlgorithm(), parsedAttestation.KeyID())
	if err != nil {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "no matching attester key", err)
	}

	verifiedAttestation, err := parsedAttestation.Verify(attesterPub, clientattestation.VerifyPolicy{
		ExpectedIssuer:  client.ExpectedAttesterIssuer(),
		ExpectedSubject: client.ID().String(),
		Algorithm:       client.ClientAttestationAlgorithm(),
		Now:             s.deps.Clock.Now(),
		MaxLifetime:     s.cfg.Limits.MaxClientAttestationLifetime,
		MaxClockSkew:    s.cfg.Limits.MaxClockSkew,
	})
	if err != nil {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "client attestation verification failed", err)
	}

	if !s.cfg.Algorithms.ClientAttestationPoP.Contains(parsedPoP.Algorithm()) {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "client attestation pop algorithm is not permitted", nil)
	}

	verifiedPoP, err := parsedPoP.Verify(ctx, verifiedAttestation.ConfirmationJWK, clientattestation.PoPVerifyPolicy{
		ExpectedIssuer:   client.ID().String(),
		ExpectedAudience: s.cfg.Issuer.String(),
		Now:              s.deps.Clock.Now(),
		MaxAge:           s.cfg.Limits.MaxClientAttestationPoPAge,
		MaxClockSkew:     s.cfg.Limits.MaxClockSkew,
		Replay:           s.clientAttestationPoPReplayChecker(),
	})
	if err != nil {
		return storage.RegisteredClient{}, clientassertion.VerifiedAssertion{},
			newError(ErrorInvalidClient, 401, "client attestation pop verification failed", err)
	}

	return client, clientassertion.VerifiedAssertion{
		ClientID:  verifiedPoP.ClientID,
		ExpiresAt: verifiedAttestation.ExpiresAt,
	}, nil
}
