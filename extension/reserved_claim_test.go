package extension_test

import (
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/extension"
)

// reservedTokenClaimNames is every claim name a client-supplied
// extension value may never be copied into a token under: the claims an
// authorization server sets itself, RFC 9068 §2.2.3.1's authorization
// attributes, RFC 8693's delegation claims, authorization_details, the
// OIDC Core §5.1 standard claims, the claims that change how a recipient
// processes a token, and the JARM parameters.
var reservedTokenClaimNames = []string{
	"iss", "sub", "aud", "exp", "iat", "nbf", "jti", "client_id", "scope", "cnf",
	"nonce", "auth_time", "acr", "amr", "azp", "at_hash", "c_hash", "s_hash",
	"roles", "groups", "entitlements", "act", "may_act", "authorization_details",
	"events", "_claim_names", "_claim_sources", "sub_jwk",
	"code", "state", "error",
	"name", "email", "email_verified", "phone_number", "address", "updated_at",
}

func tokenClaimDefinition(name string, returnInTokenClaims bool) extension.Definition[[]string] {
	return extension.Definition[[]string]{
		Sensitivity: extension.NotSensitive, Name: name, Cardinality: extension.Multiple,
		AllowedSources: extension.SourceRequestObject, MaxBytes: 512,
		ReturnInTokenClaims: returnInTokenClaims,
	}
}

// TestNewRegistryRefusesReservedTokenClaimNames: a client's value under
// one of these names would reach ID and access tokens as if the
// authorization server had set it — roles:["admin"] at a resource
// server enforcing RFC 9068 roles, say — so registering one with
// ReturnInTokenClaims fails.
func TestNewRegistryRefusesReservedTokenClaimNames(t *testing.T) {
	for _, name := range reservedTokenClaimNames {
		t.Run(name, func(t *testing.T) {
			if _, err := extension.NewRegistry(tokenClaimDefinition(name, true)); !errors.Is(err, extension.ErrReservedTokenClaim) {
				t.Fatalf("NewRegistry(%q with ReturnInTokenClaims) = %v, want ErrReservedTokenClaim", name, err)
			}
		})
	}
}

// TestNewRegistryAllowsReservedNameNotReturnedInTokenClaims: the same
// names without ReturnInTokenClaims never reach a token, and a name
// nothing reserves may be returned in them.
func TestNewRegistryAllowsReservedNameNotReturnedInTokenClaims(t *testing.T) {
	if _, err := extension.NewRegistry(tokenClaimDefinition("roles", false)); err != nil {
		t.Fatalf("NewRegistry(roles without ReturnInTokenClaims) = %v", err)
	}
	if _, err := extension.NewRegistry(tokenClaimDefinition("x_payment_purpose", true)); err != nil {
		t.Fatalf("NewRegistry(x_payment_purpose with ReturnInTokenClaims) = %v", err)
	}
}
