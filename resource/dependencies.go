package resource

import (
	"io"

	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/storage"
)

// Dependencies are this verifier's injected collaborators. NewVerifier
// rejects a nil value for any field required unconditionally — there is
// no implicit fallback (no default clock, no silently-installed
// in-memory replay store). Nonces/Random are the one exception: unlike
// every other field, DPoP nonce-challenge support (RFC 9449 §8, §9) is
// genuinely optional protocol behavior, not a security check this
// module considers non-negotiable — leaving Nonces nil disables it
// entirely, with no visible-opt-out sentinel needed the way
// Revocation's NoRevocation{} is, because declining it is the normal,
// fully spec-compliant default, not a choice that needs to be visible.
// NewVerifier also rejects, in every field, a typed nil: an interface
// holding a nil pointer (or nil map, slice or func), which isn't == nil
// but would fail on the first call.
type Dependencies struct {
	// AccessTokens resolves a presented access token's claims — see
	// AccessTokenResolver. Required — pass JWTAccessTokens{...} (the
	// default), OpaqueAccessTokens{...}, or your own AccessTokenResolver.
	AccessTokens AccessTokenResolver

	// Replay detects reuse of a DPoP proof's jti.
	Replay storage.ReplayStore

	// Revocation reports whether an access token has been revoked by
	// the issuing authorization server (RFC 6749 §4.1.2). Required,
	// like every field above — pass a real RevocationChecker, or
	// NoRevocation{} to explicitly decline (see NoRevocation's own doc
	// comment for why). Under AssuranceProduction, decline with
	// NoRevocationUntilExpiry instead: NoRevocation is refused there.
	Revocation RevocationChecker

	// Clock supplies the current time. Under AssuranceProduction it
	// must declare ClockAssurance, as SystemClock does.
	Clock Clock

	// Nonces persists DPoP nonces this verifier issues and checks.
	// Nil disables DPoP nonce-challenge support entirely — Verify never
	// requires or checks a nonce, exactly like today. Set it (and
	// Random, and Config.Limits.DPoPNonceLifetime) to have Verify
	// challenge a request whose proof carries no valid nonce, and hand
	// out its current nonce on every successful call. A nonce stays
	// valid until it expires, for any number of proofs (see
	// storage.NonceStore); the Verifier stores a new one only when half
	// of Config.Limits.DPoPNonceLifetime has passed.
	//
	// Never pass an authorization server's own Dependencies.Nonces: a
	// nonce store is keyed by the nonce alone, so a nonce one role issued
	// would be accepted by the other, while RFC 9449 keeps the
	// authorization server's nonces (§8) apart from a resource server's
	// (§9). serverresource.NewVerifier refuses that for its
	// Options.Nonces; a Verifier built here can't tell.
	Nonces storage.NonceStore

	// Random is the source of randomness for DPoP nonce generation.
	// Required only when Nonces is non-nil — NewVerifier rejects nil
	// Random in that case, matching server.Dependencies.Random's own
	// "no implicit fallback" rule.
	Random io.Reader

	// PairwiseSubjects maps an access token's pairwise "sub" (OpenID
	// Connect Core §8) back to the end user's internal subject, which
	// AuthorizationContext.InternalSubject then carries: the authorization
	// server's own Reversible deriver (pairwise.NewReversible over the
	// same keys, or pairwise.NewMapping over the same store), with Config.PairwisePrefix set
	// to the server's Config.Subjects.Prefix. serverresource.NewVerifier
	// wires both from the server's configuration.
	//
	// Required (or PairwiseSubjectResolver) to verify a self-contained access
	// token whose sub is pairwise: Verify answers one with server_error
	// rather than give the pairwise sub as InternalSubject. A server-side token
	// record (OpaqueAccessTokens) already keeps the internal subject and
	// needs no lookup. Nil when the authorization server issues only
	// public subjects, or only opaque access tokens.
	//
	// It maps every pairwise sub back to its end user, which OpenID
	// Connect Core §8.1 reserves to the OpenID Provider: set it only on
	// the OP's own resource servers. One outside the OP sets
	// Config.PairwiseResolution to PairwiseClientSubjectsOnly instead.
	PairwiseSubjects pairwise.Lookup

	// PairwiseSubjectResolver maps a self-contained access token's pairwise sub
	// back to the end user's internal subject when the authorization
	// server derives subs one way (pairwise.NewHMAC or NewHMACWith), so PairwiseSubjects
	// can't: the embedder's own mapping, the same resolver the server
	// declares (server.Dependencies.PairwiseSubjectResolver). Verify uses
	// PairwiseSubjects when set, otherwise PairwiseSubjectResolver; a pairwise
	// sub neither maps is never given as InternalSubject. Under
	// AssuranceProduction it must declare Durable custody
	// (keys.KeyCustodyAssurance), and CrossInstanceConsistent with
	// DeploymentHorizontallyScaled. Like PairwiseSubjects, it reverses
	// pairwise subs, so only the OP's own resource servers get one.
	PairwiseSubjectResolver pairwise.SubjectResolver
}
