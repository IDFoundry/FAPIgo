package federation

import intfed "github.com/idfoundry/fapigo/internal/federation"

// These name the internal/federation types this package's own API takes
// and returns, so code outside this module — which can't import an
// internal package — can declare and construct them: a Trust Anchor
// setting a Subordinate Statement's metadata policy or constraints, a
// Trust Mark Issuer reporting a status, or a caller passing verified
// claims to its own functions.
type (
	// MetadataPolicy is a Subordinate Statement's "metadata_policy"
	// claim (OpenID Federation 1.0 §6.1): entity type to metadata
	// parameter to its PolicyOperators.
	MetadataPolicy = intfed.MetadataPolicy

	// PolicyOperators maps each metadata policy operator name ("value",
	// "subset_of", ...) to its JSON-encoded operand.
	PolicyOperators = intfed.PolicyOperators

	// Constraints is a Subordinate Statement's "constraints" claim
	// (OpenID Federation 1.0 §6.2).
	Constraints = intfed.Constraints

	// NamingConstraints is Constraints' "naming_constraints" member
	// (OpenID Federation 1.0 §6.2.2).
	NamingConstraints = intfed.NamingConstraints

	// RawTrustMark is one "trust_marks" entry of an Entity
	// Configuration: a Trust Mark type and its signed JWT, unverified.
	RawTrustMark = intfed.RawTrustMark

	// TrustMarkOwner is one "trust_mark_owners" entry of a Trust
	// Anchor's Entity Configuration (OpenID Federation 1.0 §7.2).
	TrustMarkOwner = intfed.TrustMarkOwner

	// TrustMarkStatus is a Trust Mark Status response's "status"
	// (OpenID Federation 1.0 §8.4.2).
	TrustMarkStatus = intfed.TrustMarkStatus

	// TrustMarkClaims is a verified Trust Mark's claims, as
	// Resolver.VerifyTrustMark returns them.
	TrustMarkClaims = intfed.TrustMarkClaims

	// TrustMarkStatusResponseClaims is a verified Trust Mark Status
	// response's claims, as Resolver.CheckTrustMarkStatus returns them.
	TrustMarkStatusResponseClaims = intfed.TrustMarkStatusResponseClaims

	// ResolveResponseClaims is a verified Resolve Response's claims, as
	// Resolver.ResolveViaEndpoint returns them.
	ResolveResponseClaims = intfed.ResolveResponseClaims

	// HistoricalKeysClaims is a verified Federation Historical Keys
	// response's claims, as Resolver.FetchHistoricalKeys returns them.
	HistoricalKeysClaims = intfed.HistoricalKeysClaims
)

// The Trust Mark statuses a Trust Mark Status response may report
// (OpenID Federation 1.0 §8.4.2).
const (
	TrustMarkStatusActive  = intfed.TrustMarkStatusActive
	TrustMarkStatusExpired = intfed.TrustMarkStatusExpired
	TrustMarkStatusRevoked = intfed.TrustMarkStatusRevoked
	TrustMarkStatusInvalid = intfed.TrustMarkStatusInvalid
)
