package resource

import (
	"io"

	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/storage"
)

// Dependencies are this verifier's injected collaborators. NewVerifier
// rejects a nil value for any field required unconditionally — there is
// no implicit fallback (no default clock, no silently-installed
// in-memory replay store). Nonces and Random are required only as
// noted on each: under AssuranceDevelopment a nil Nonces disables DPoP
// nonce challenges (RFC 9449 §9), while AssuranceProduction requires a
// nonce store or the explicit NoDPoPNonces{} decline, the way
// Revocation requires NoRevocation{} to decline.
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

	// Nonces persists DPoP nonces this verifier issues and checks. Set
	// it (and Random, and Config.Limits.DPoPNonceLifetime) to have
	// Verify challenge a request whose proof carries no valid nonce
	// with use_dpop_nonce, and hand out its current nonce on every
	// successful call. A nonce stays valid until it expires, for any
	// number of proofs (see storage.NonceStore); the Verifier stores a
	// new one only when half of Config.Limits.DPoPNonceLifetime has
	// passed.
	//
	// A nonce is what keeps a DPoP proof from being made ahead of time:
	// without one, a proof's freshness rests on the "iat" the client
	// chose, so an attacker able to have a client generate proofs for
	// later, or to capture them, can use one until it ages out (RFC 9449
	// §11, the FAPI 2.0 attacker model's A5). The cost is one extra round
	// trip per client on first use, and again each time the nonce
	// rotates: the client retries once with the nonce the challenge
	// carried.
	//
	// Required under AssuranceProduction: pass a store — shared by
	// every instance serving the same resource URLs, since a nonce one
	// instance issues must be valid at the next, and declaring
	// storage.StoreAssurance (Durable, and CrossInstanceConsistent with
	// DeploymentHorizontallyScaled) — or NoDPoPNonces{} to explicitly
	// decline. Under AssuranceDevelopment nil also declines, and Verify
	// never requires or checks a nonce.
	//
	// Never pass an authorization server's own Dependencies.Nonces: a
	// nonce store is keyed by the nonce alone, so a nonce one role issued
	// would be accepted by the other, while RFC 9449 keeps the
	// authorization server's nonces (§8) apart from a resource server's
	// (§9). serverresource.NewVerifier refuses that for its
	// Options.Nonces; a Verifier built here can't tell.
	Nonces storage.NonceStore

	// Random is the source of randomness for DPoP nonce generation.
	// Required only when Nonces is a nonce store (not nil or
	// NoDPoPNonces{}) — NewVerifier rejects nil
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
