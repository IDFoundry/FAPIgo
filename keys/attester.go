package keys

import (
	"context"
	"fmt"
	"slices"

	fapi "github.com/idfoundry/fapigo"
)

// AttesterKeyRequest describes which of an Attester's verification keys
// is needed to verify a Client Attestation (OAuth 2.0 Attestation-Based
// Client Authentication). Issuer is the Attester the client is
// registered with (storage.RegisteredClient.ExpectedAttesterIssuer),
// never the attestation's own unverified "iss". Algorithm is the
// client's registered attestation algorithm, and KeyID the attestation
// header's "kid" ("" if it carried none), usable only as a lookup key.
type AttesterKeyRequest struct {
	Issuer    string
	Algorithm fapi.SignatureAlgorithm
	KeyID     string
}

// AttesterKeySource resolves an Attester's verification keys, by the
// Attester's own issuer. It is deliberately separate from
// ClientKeySource: an Attester vouches for clients, so its keys must
// never be ones a client registered or published for itself — a source
// that looked keys up by client could hand back the client's own key,
// letting it attest for itself. server.RegisteredAttesterKeys uses one.
//
// Like ClientKeySource, an implementation must declare
// KeySourceAssurance to be accepted under server.AssuranceProduction.
type AttesterKeySource interface {
	ResolveAttesterKeys(ctx context.Context, req AttesterKeyRequest) (VerificationKeySet, error)
}

// StaticAttesterKeys is an AttesterKeySource holding each trusted
// Attester's keys, by issuer, administratively registered. It never
// fetches: rotating an Attester's key means updating the map.
type StaticAttesterKeys map[string][]VerificationKey

// ResolveAttesterKeys implements AttesterKeySource: the keys registered
// for req.Issuer, or an error if the Attester is unknown.
func (s StaticAttesterKeys) ResolveAttesterKeys(_ context.Context, req AttesterKeyRequest) (VerificationKeySet, error) {
	registered, ok := s[req.Issuer]
	if !ok {
		return VerificationKeySet{}, fmt.Errorf("keys: no keys registered for attester %q", req.Issuer)
	}
	return VerificationKeySet{Keys: slices.Clone(registered)}, nil
}

// Capabilities implements KeySourceAssurance: StaticAttesterKeys never
// fetches over the network.
func (StaticAttesterKeys) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: true}
}
