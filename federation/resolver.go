package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	intfed "github.com/idfoundry/fapigo/internal/federation"
	"github.com/idfoundry/fapigo/internal/jose"
)

// TrustAnchor is a Trust Anchor this Resolver trusts, configured out of
// band — OpenID Federation 1.0 §10's own opening requirement: "Party A
// MUST have ... a list of Entity Identifiers of Trust Anchors and their
// public signing keys." JWKS is never fetched live for the purpose of
// establishing this root of trust; it must come from the same
// out-of-band channel (configuration, a provisioning process, a pinned
// value shipped with the deploying application) a TLS root CA bundle
// would, precisely because a live fetch has nothing yet to validate it
// against. A Trust Anchor's own Entity Configuration is still fetched
// during resolution (to discover its metadata and, for a multi-entity
// federation, its own federation_fetch_endpoint), but its signature is
// always additionally checked against this pre-configured JWKS, never
// trusted from that fetch alone.
type TrustAnchor struct {
	EntityID string

	// JWKS is EntityID's own federation signing keys, as a JWK Set (RFC
	// 7517 §5) JSON object.
	JWKS json.RawMessage
}

// Limits bounds how far a Resolve call is willing to go. None of these
// have an implicit default — NewResolver rejects a zero value.
type Limits struct {
	// MaxPathLength bounds how many Intermediate Entities Resolve will
	// walk through before giving up — a hard, resolver-wide ceiling
	// enforced regardless of what any individual Subordinate
	// Statement's own "constraints" claim (OpenID Federation 1.0 §6.2)
	// says, so a misbehaving or malicious federation member can't send
	// Resolve down an unbounded (or merely very long) chain. Resolve
	// separately enforces each Subordinate Statement's own
	// max_path_length (§6.2.1), naming_constraints (§6.2.2) and
	// allowed_entity_types (§6.2.3) constraints — this field is this
	// package's own independent, always-on ceiling, not a substitute for
	// those per-statement ones.
	MaxPathLength int

	// MaxStatementLifetime bounds how far in the future (relative to
	// Dependencies.Clock) any fetched Entity Statement's exp claim may
	// be.
	MaxStatementLifetime time.Duration

	// MaxClockSkew bounds how far in the future an iat claim may be,
	// and extends how long past exp a statement is still accepted.
	// Zero means no tolerance.
	MaxClockSkew time.Duration
}

// Config is this Resolver's immutable configuration. It is copied by
// NewResolver; mutating a Config after passing it to NewResolver has no
// effect.
type Config struct {
	// TrustAnchors is every Trust Anchor Resolve is willing to root a
	// Trust Chain at. Required — at least one.
	TrustAnchors []TrustAnchor

	Limits Limits
}

// Dependencies are this Resolver's injected collaborators. NewResolver
// rejects a nil value for either field — there is no implicit default
// HTTP client or clock.
type Dependencies struct {
	// HTTP performs every outbound Entity Configuration and Subordinate
	// Statement fetch, through fapihttp's own hardened protections
	// (ARCHITECTURE.md design rule 6) — never a bare *http.Client.
	HTTP *fapihttp.Client

	Clock Clock
}

// Resolver resolves a Trust Chain from a subject entity up to one of
// Config.TrustAnchors, and the subject's Resolved Metadata. It is
// entirely unexported apart from its exported methods; construct one
// with NewResolver.
type Resolver struct {
	cfg              Config
	deps             Dependencies
	trustAnchorsByID map[string]TrustAnchor
}

// NewResolver validates cfg and deps and returns a Resolver.
func NewResolver(cfg Config, deps Dependencies) (*Resolver, error) {
	if len(cfg.TrustAnchors) == 0 {
		return nil, fmt.Errorf("federation: config: at least one trust anchor is required")
	}
	byID := make(map[string]TrustAnchor, len(cfg.TrustAnchors))
	for _, a := range cfg.TrustAnchors {
		if a.EntityID == "" {
			return nil, fmt.Errorf("federation: config: trust anchor entity ID is empty")
		}
		if len(a.JWKS) == 0 {
			return nil, fmt.Errorf("federation: config: trust anchor %q: jwks is empty", a.EntityID)
		}
		byID[a.EntityID] = a
	}
	if cfg.Limits.MaxPathLength <= 0 {
		return nil, fmt.Errorf("federation: config: limits.max_path_length must be positive")
	}
	if cfg.Limits.MaxStatementLifetime <= 0 {
		return nil, fmt.Errorf("federation: config: limits.max_statement_lifetime must be positive")
	}
	if cfg.Limits.MaxClockSkew < 0 {
		return nil, fmt.Errorf("federation: config: limits.max_clock_skew must not be negative")
	}
	if deps.HTTP == nil {
		return nil, fmt.Errorf("federation: dependencies: http is required")
	}
	if deps.Clock == nil {
		return nil, fmt.Errorf("federation: dependencies: clock is required")
	}
	return &Resolver{cfg: cfg, deps: deps, trustAnchorsByID: byID}, nil
}

// ResolvedEntity is a successfully resolved Trust Chain and its
// subject's Resolved Metadata.
type ResolvedEntity struct {
	EntityID    string
	TrustAnchor string

	// Chain is every entity identifier in the Trust Chain, from
	// EntityID itself up to and including TrustAnchor.
	Chain []string

	// Metadata is the subject's Resolved Metadata (OpenID Federation
	// 1.0 §6.1.4.2) — entity-type identifier to that type's resolved
	// metadata object.
	Metadata map[string]json.RawMessage

	// ExpiresAt is the Trust Chain's own expiration (OpenID Federation
	// 1.0 §10.4): the minimum exp across every Entity Statement in the
	// chain. A caller resolving the same subject again after this time
	// gets a fresh chain, not a stale one — this package performs no
	// caching of its own.
	ExpiresAt time.Time

	// JWKS is EntityID's own trusted Federation Entity Keys (a JWK Set)
	// — whatever its immediate superior's own Subordinate Statement
	// vouches for (or, when EntityID is itself a configured Trust
	// Anchor, the pre-configured TrustAnchor.JWKS), not necessarily
	// identical to EntityID's own self-claimed jwks. This is the key
	// set trusted to verify anything else EntityID itself signs — most
	// notably a Trust Mark it issued — via VerifyTrustMark.
	JWKS json.RawMessage

	// TrustMarks is EntityID's own unverified "trust_marks" claim
	// (OpenID Federation 1.0 §7), exactly as intfed.Claims.TrustMarks
	// describes — nil if EntityID declared none. Establish trust in a
	// specific entry with VerifyTrustMark before relying on it for
	// anything.
	TrustMarks []intfed.RawTrustMark

	// TrustMarkOwners is EntityID's own "trust_mark_owners" claim
	// (OpenID Federation 1.0 §7.2), exactly as
	// intfed.Claims.TrustMarkOwners describes — nil if EntityID declared
	// none. Only meaningful when EntityID is a Trust Anchor;
	// VerifyTrustMark reads this (from the Trust Anchor actually used to
	// establish trust in a Trust Mark's own issuer) to decide whether
	// that Trust Mark's type requires a "delegation" claim at all.
	TrustMarkOwners map[string]intfed.TrustMarkOwner

	// Tokens is the raw compact-serialized Entity Statement JWTs
	// composing this Trust Chain, in the exact order OpenID Federation
	// 1.0 §4 defines: ES[0] (EntityID's own Entity Configuration), each
	// Subordinate Statement from EntityID's immediate superior up
	// through the Trust Anchor's own Subordinate Statement about the
	// top-most Intermediate (or EntityID itself, if there are none), and
	// finally ES[i] (TrustAnchor's own Entity Configuration) — every
	// entry Resolve actually verified, never a re-serialization of
	// parsed claims (not guaranteed byte-identical to what was signed).
	// Every Intermediate's own self-signed Entity Configuration, fetched
	// along the way purely to discover its authority_hints and
	// federation_fetch_endpoint, is deliberately excluded — §4's own
	// worked example names exactly these entries and no others. Chiefly
	// useful for ResolveIssuer.Response's own "trust_chain" claim
	// (OpenID Federation 1.0 §8.3.2); most callers have no reason to
	// read this directly.
	Tokens []string
}

// chainWalkState is Resolve's own mutable state as it walks upward from
// subjectID, one hop (one Intermediate) at a time, until it reaches a
// configured Trust Anchor. Split out purely to keep Resolve itself and
// its per-hop helpers (selfClaimsForHop, finalizeTrustChain,
// advanceIntermediateHop) within a manageable parameter count — every
// field here is exactly one of the loop-scoped variables the original,
// unsplit Resolve tracked directly; see each helper's own doc comment
// for how and when it reads or mutates one.
type chainWalkState struct {
	subjectID  string
	leafClaims intfed.Claims

	minExpiry time.Time

	// belowStmt is always "the most recently fetched statement that
	// still needs to be verified against a key vouched for by its own
	// issuer's superior" — initially LE's self-signed Entity
	// Configuration (ES[0]). belowIssuer/belowSubject are belowStmt's
	// own claimed iss/sub, tracked explicitly rather than re-derived
	// from entityAt: once belowStmt becomes a genuine Subordinate
	// Statement (any hop after the first), its subject is whichever
	// entity was entityAt when it was fetched, not entityAt's current
	// value — entityAt keeps advancing up the chain every iteration,
	// but a Subordinate Statement's own "sub" never changes.
	belowStmt    intfed.Statement
	belowIssuer  string
	belowSubject string
	entityAt     string

	visited map[string]bool
	chain   []string
	tokens  []string

	subordinatePolicies    []subordinatePolicy
	subordinateConstraints []subordinateConstraint

	// subjectJWKS is captured exactly once, at hop 0 — the first
	// superior's own statement "about entityAt" is, at that point,
	// necessarily about subjectID itself (entityAt only ever advances
	// past subjectID at the end of hop 0). See ResolvedEntity.JWKS's
	// own doc comment for what this value means and is used for.
	subjectJWKS json.RawMessage
}

func newChainWalkState(subjectID string, leafStmt intfed.Statement, leafToken string, leafClaims intfed.Claims) *chainWalkState {
	return &chainWalkState{
		subjectID:  subjectID,
		leafClaims: leafClaims,
		minExpiry:  leafClaims.ExpiresAt,

		belowStmt:    leafStmt,
		belowIssuer:  subjectID,
		belowSubject: subjectID,
		entityAt:     subjectID,

		visited: map[string]bool{subjectID: true},
		chain:   []string{subjectID},
		tokens:  []string{leafToken},
	}
}

// Resolve resolves subjectID's Trust Chain against one of
// Config.TrustAnchors and returns its Resolved Metadata, enforcing
// every Subordinate Statement's own max_path_length, naming_constraints
// and allowed_entity_types constraints along the way. See doc.go for
// this release's scope (leaf-entity resolution only, automatic
// registration's own trust model — no server-side federation endpoints
// of this Resolver's own, no trust marks).
func (r *Resolver) Resolve(ctx context.Context, subjectID string) (ResolvedEntity, error) {
	if subjectID == "" {
		return ResolvedEntity{}, fmt.Errorf("federation: subject entity ID is empty")
	}
	now := r.deps.Clock.Now()

	leafStmt, leafToken, err := fetchEntityConfiguration(ctx, r.deps.HTTP, subjectID)
	if err != nil {
		return ResolvedEntity{}, err
	}
	if leafStmt.ClaimedIssuer() != subjectID || leafStmt.ClaimedSubject() != subjectID {
		return ResolvedEntity{}, fmt.Errorf("federation: entity configuration for %q has iss=%q sub=%q, want both equal to the requested entity ID",
			subjectID, leafStmt.ClaimedIssuer(), leafStmt.ClaimedSubject())
	}
	leafClaims, err := r.verifySelfSigned(leafStmt, subjectID, now)
	if err != nil {
		return ResolvedEntity{}, fmt.Errorf("federation: entity configuration for %q: %w", subjectID, err)
	}

	// The subject may itself be a configured Trust Anchor — a
	// degenerate, zero-hop Trust Chain: its own Entity Configuration is
	// both ES[0] and ES[i], and the only remaining check is that it
	// validates against the pre-configured key, not merely its own
	// self-claimed one.
	if anchor, ok := r.trustAnchorsByID[subjectID]; ok {
		return r.resolveSelfAsTrustAnchor(subjectID, leafStmt, leafToken, leafClaims, anchor, now)
	}

	st := newChainWalkState(subjectID, leafStmt, leafToken, leafClaims)

	for hop := 0; ; hop++ {
		if hop >= r.cfg.Limits.MaxPathLength {
			return ResolvedEntity{}, fmt.Errorf("federation: trust chain for %q exceeds the configured max path length (%d)", subjectID, r.cfg.Limits.MaxPathLength)
		}

		selfClaims, err := r.selfClaimsForHop(ctx, st, now)
		if err != nil {
			return ResolvedEntity{}, err
		}

		hints := selfClaims.AuthorityHints
		if len(hints) == 0 {
			return ResolvedEntity{}, fmt.Errorf("federation: %q has no authority_hints and is not a configured trust anchor: no path to a trusted trust anchor", st.entityAt)
		}

		superiorID, superiorConfig, superiorToken, superiorClaims, err := r.findReachableSuperior(ctx, hints, st.visited, now)
		if err != nil {
			return ResolvedEntity{}, fmt.Errorf("federation: %q: %w", st.entityAt, err)
		}
		st.visited[superiorID] = true
		if superiorClaims.ExpiresAt.Before(st.minExpiry) {
			st.minExpiry = superiorClaims.ExpiresAt
		}

		aboveStmt, aboveToken, err := r.fetchAboveStatement(ctx, superiorID, superiorClaims, st.entityAt)
		if err != nil {
			return ResolvedEntity{}, err
		}

		st.chain = append(st.chain, superiorID)
		// aboveStmt (issued by superiorID, about entityAt) is a genuine
		// Trust Chain entry regardless of whether superiorID turns out to
		// be a Trust Anchor or another Intermediate — unlike an
		// Intermediate's own self-signed Entity Configuration (see
		// selfClaimsForHop's own doc comment), appended here
		// unconditionally, in order.
		st.tokens = append(st.tokens, aboveToken)

		if anchor, ok := r.trustAnchorsByID[superiorID]; ok {
			return r.finalizeTrustChain(st, hop, superiorID, superiorConfig, superiorClaims, aboveStmt, superiorToken, anchor, now)
		}

		if err := r.advanceIntermediateHop(st, hop, superiorID, aboveStmt, now); err != nil {
			return ResolvedEntity{}, err
		}
	}
}

// resolveSelfAsTrustAnchor handles Resolve's degenerate, zero-hop case:
// subjectID is itself a configured Trust Anchor, so leafStmt (ES[0]) is
// also ES[i] — the only remaining check is that it validates against
// the pre-configured key, not merely its own self-claimed one. See
// Resolve's own call site comment for why this never needs to enter the
// hop loop.
func (r *Resolver) resolveSelfAsTrustAnchor(subjectID string, leafStmt intfed.Statement, leafToken string, leafClaims intfed.Claims, anchor TrustAnchor, now time.Time) (ResolvedEntity, error) {
	if _, err := r.verifyAgainstJWKS(leafStmt, anchor.JWKS, subjectID, subjectID, leafStmt.Algorithm(), now); err != nil {
		return ResolvedEntity{}, fmt.Errorf("federation: %q is configured as a trust anchor but does not validate against its configured keys: %w", subjectID, err)
	}
	return ResolvedEntity{
		EntityID: subjectID, TrustAnchor: subjectID, Chain: []string{subjectID},
		Metadata: leafClaims.Metadata, ExpiresAt: leafClaims.ExpiresAt,
		JWKS: anchor.JWKS, TrustMarks: leafClaims.TrustMarks, TrustMarkOwners: leafClaims.TrustMarkOwners,
		Tokens: []string{leafToken},
	}, nil
}

// selfClaimsForHop returns st.entityAt's own claims for this hop — at
// hop 0 that's simply st.leafClaims (already self-verified by Resolve
// before the loop began: st.entityAt starts equal to st.subjectID, and
// moves away from it only at the end of advanceIntermediateHop, so
// entityAt == subjectID is exactly "hop 0" for every call this function
// can see). Every later hop fetches and self-verifies entityAt's own
// Entity Configuration purely to discover its authority_hints and
// federation_fetch_endpoint; that self-signed statement's own raw token
// is discarded, never appended to st.tokens — it is not itself an entry
// of the canonical Trust Chain sequence, see ResolvedEntity.Tokens's own
// doc comment. Updates st.minExpiry when this hop's statement expires
// sooner than every one already seen.
func (r *Resolver) selfClaimsForHop(ctx context.Context, st *chainWalkState, now time.Time) (intfed.Claims, error) {
	if st.entityAt == st.subjectID {
		return st.leafClaims, nil
	}
	selfConfig, _, err := fetchEntityConfiguration(ctx, r.deps.HTTP, st.entityAt)
	if err != nil {
		return intfed.Claims{}, err
	}
	if selfConfig.ClaimedIssuer() != st.entityAt || selfConfig.ClaimedSubject() != st.entityAt {
		return intfed.Claims{}, fmt.Errorf("federation: entity configuration for %q has iss=%q sub=%q, want both equal to %q",
			st.entityAt, selfConfig.ClaimedIssuer(), selfConfig.ClaimedSubject(), st.entityAt)
	}
	selfClaims, err := r.verifySelfSigned(selfConfig, st.entityAt, now)
	if err != nil {
		return intfed.Claims{}, fmt.Errorf("federation: entity configuration for %q: %w", st.entityAt, err)
	}
	if selfClaims.ExpiresAt.Before(st.minExpiry) {
		st.minExpiry = selfClaims.ExpiresAt
	}
	return selfClaims, nil
}

// fetchAboveStatement fetches and validates the Subordinate Statement
// that superiorID's own federation_fetch_endpoint (resolved from
// superiorClaims' federation_entity metadata) issues about entityAt —
// the "aboveStmt" that Resolve either closes the Trust Chain with
// (superiorID is a configured Trust Anchor, see finalizeTrustChain) or
// carries into the next hop as the new belowStmt (see
// advanceIntermediateHop).
func (r *Resolver) fetchAboveStatement(ctx context.Context, superiorID string, superiorClaims intfed.Claims, entityAt string) (intfed.Statement, string, error) {
	aboveMeta, err := parseEntityMetadata(superiorClaims.Metadata)
	if err != nil {
		return intfed.Statement{}, "", fmt.Errorf("federation: %q: federation_entity metadata: %w", superiorID, err)
	}
	if aboveMeta.FetchEndpoint == "" {
		return intfed.Statement{}, "", fmt.Errorf("federation: %q has no federation_fetch_endpoint", superiorID)
	}
	aboveStmt, aboveToken, err := fetchSubordinateStatement(ctx, r.deps.HTTP, aboveMeta.FetchEndpoint, entityAt)
	if err != nil {
		return intfed.Statement{}, "", err
	}
	if aboveStmt.ClaimedIssuer() != superiorID || aboveStmt.ClaimedSubject() != entityAt {
		return intfed.Statement{}, "", fmt.Errorf("federation: subordinate statement about %q from %q has iss=%q sub=%q",
			entityAt, superiorID, aboveStmt.ClaimedIssuer(), aboveStmt.ClaimedSubject())
	}
	return aboveStmt, aboveToken, nil
}

// finalizeTrustChain handles the hop where superiorID — whose
// Subordinate Statement aboveStmt about st.entityAt was just fetched and
// appended to st.chain/st.tokens — turns out to be a configured Trust
// Anchor, closing the Trust Chain. Called at most once per Resolve call,
// from the hop where it happens; see Resolve's own call site.
func (r *Resolver) finalizeTrustChain(st *chainWalkState, hop int, superiorID string, superiorConfig intfed.Statement, superiorClaims intfed.Claims, aboveStmt intfed.Statement, superiorToken string, anchor TrustAnchor, now time.Time) (ResolvedEntity, error) {
	// superiorConfig now plays two roles at once: it's both the routing
	// statement that got us here, and ES[i] — "the statement about
	// superiorID" collapses to superiorID's own self-signed config,
	// since a trust anchor has no superior of its own to issue a
	// separate one.
	if _, err := r.verifyAgainstJWKS(superiorConfig, anchor.JWKS, superiorID, superiorID, superiorConfig.Algorithm(), now); err != nil {
		return ResolvedEntity{}, fmt.Errorf("federation: trust anchor %q does not validate against its configured keys: %w", superiorID, err)
	}
	aboveClaims, err := r.verifyAgainstJWKS(aboveStmt, superiorClaims.JWKS, superiorID, st.entityAt, aboveStmt.Algorithm(), now)
	if err != nil {
		return ResolvedEntity{}, fmt.Errorf("federation: subordinate statement about %q from trust anchor %q: %w", st.entityAt, superiorID, err)
	}
	if _, err := r.verifyAgainstJWKS(st.belowStmt, aboveClaims.JWKS, st.belowIssuer, st.belowSubject, st.belowStmt.Algorithm(), now); err != nil {
		return ResolvedEntity{}, fmt.Errorf("federation: %q's statement (issued by %q) does not match the keys vouched for it by %q: %w", st.belowSubject, st.belowIssuer, superiorID, err)
	}
	if hop == 0 {
		st.subjectJWKS = aboveClaims.JWKS
	}
	st.subordinatePolicies = append(st.subordinatePolicies, subordinatePolicy{policy: aboveClaims.MetadataPolicy, crit: aboveClaims.MetadataPolicyCritical})
	if aboveClaims.Constraints != nil {
		st.subordinateConstraints = append(st.subordinateConstraints, subordinateConstraint{
			constraints: *aboveClaims.Constraints,
			appliesTo:   append([]string{}, st.chain[:len(st.chain)-1]...),
		})
	}

	if err := checkNamingConstraints(st.subordinateConstraints); err != nil {
		return ResolvedEntity{}, err
	}
	if err := checkMaxPathLengthConstraints(st.subordinateConstraints); err != nil {
		return ResolvedEntity{}, err
	}
	leafMetadata := filterAllowedEntityTypes(st.subordinateConstraints, st.leafClaims.Metadata)
	resolvedMetadata, err := r.resolveMetadata(st.subordinatePolicies, leafMetadata)
	if err != nil {
		return ResolvedEntity{}, err
	}
	// superiorConfig's own raw token (ES[i], the Trust Anchor's own
	// Entity Configuration) closes the sequence — see
	// ResolvedEntity.Tokens's own doc comment.
	return ResolvedEntity{
		EntityID: st.subjectID, TrustAnchor: superiorID, Chain: st.chain,
		Metadata: resolvedMetadata, ExpiresAt: st.minExpiry,
		JWKS: st.subjectJWKS, TrustMarks: st.leafClaims.TrustMarks, TrustMarkOwners: st.leafClaims.TrustMarkOwners,
		Tokens: append(st.tokens, superiorToken),
	}, nil
}

// advanceIntermediateHop handles the hop where superiorID — whose
// Subordinate Statement aboveStmt about st.entityAt was just fetched and
// appended to st.chain/st.tokens — is an Intermediate, not (yet known to
// be) a Trust Anchor: aboveStmt can't be verified until the next hop
// learns what vouches for superiorID's own keys, so it becomes the new
// st.belowStmt. Verifies the OLD st.belowStmt now, though: aboveStmt
// (issued by superiorID, about st.entityAt) is exactly "the statement
// about st.entityAt" that belowStmt's own verification rule calls for.
func (r *Resolver) advanceIntermediateHop(st *chainWalkState, hop int, superiorID string, aboveStmt intfed.Statement, now time.Time) error {
	if _, err := r.verifyAgainstJWKS(st.belowStmt, aboveStmt.ClaimedJWKS(), st.belowIssuer, st.belowSubject, st.belowStmt.Algorithm(), now); err != nil {
		return fmt.Errorf("federation: %q's statement (issued by %q) does not match the keys vouched for it by %q: %w", st.belowSubject, st.belowIssuer, superiorID, err)
	}
	if hop == 0 {
		// Unverified until the next iteration verifies aboveStmt's
		// signature (as the new belowStmt) — safe to capture now for
		// the same reason ClaimedMetadataPolicy's own doc comment
		// gives; see ResolvedEntity.JWKS's own doc comment for why
		// hop 0 specifically.
		st.subjectJWKS = aboveStmt.ClaimedJWKS()
	}
	// aboveStmt's own metadata_policy is unverified until the next
	// iteration verifies aboveStmt's signature (as the new
	// belowStmt) — safe to read now for the reasons
	// Statement.ClaimedMetadataPolicy's own doc comment gives: it's
	// only ever merged and applied once the whole chain, this
	// statement included, has been cryptographically verified.
	policy, crit := aboveStmt.ClaimedMetadataPolicy()
	st.subordinatePolicies = append(st.subordinatePolicies, subordinatePolicy{policy: policy, crit: crit})
	// aboveStmt's own constraints claim is unverified for exactly the
	// same reason and until exactly the same later point as its
	// metadata_policy, immediately above — see
	// intfed.Statement.ClaimedConstraints's own doc comment.
	if constraints := aboveStmt.ClaimedConstraints(); constraints != nil {
		st.subordinateConstraints = append(st.subordinateConstraints, subordinateConstraint{
			constraints: *constraints,
			appliesTo:   append([]string{}, st.chain[:len(st.chain)-1]...),
		})
	}

	st.belowStmt = aboveStmt
	st.belowIssuer = superiorID
	st.belowSubject = st.entityAt
	st.entityAt = superiorID
	return nil
}

// subordinatePolicy is one Subordinate Statement's own metadata_policy
// and metadata_policy_crit claims, collected bottom-up (closest to the
// Trust Chain subject first) as Resolve walks upward.
type subordinatePolicy struct {
	policy intfed.MetadataPolicy
	crit   []string
}

// resolveMetadata merges policies (collected bottom-up by Resolve) in
// the top-down order OpenID Federation 1.0 §6.1.4.1 requires — starting
// from the statement issued by the most superior entity — and applies
// the result to leafMetadata (the Trust Chain subject's own declared
// metadata, from its Entity Configuration).
func resolveMetadataPolicies(policies []subordinatePolicy) (intfed.MetadataPolicy, []string, error) {
	var merged intfed.MetadataPolicy
	var crit []string
	for i := len(policies) - 1; i >= 0; i-- {
		p := policies[i]
		var err error
		merged, err = intfed.MergePolicy(merged, crit, p.policy, p.crit)
		if err != nil {
			return nil, nil, err
		}
		crit = mergeCrit(crit, p.crit)
	}
	return merged, crit, nil
}

func mergeCrit(a, b []string) []string {
	seen := make(map[string]bool, len(a))
	out := append([]string{}, a...)
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	return out
}

func (r *Resolver) resolveMetadata(policies []subordinatePolicy, leafMetadata map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	merged, crit, err := resolveMetadataPolicies(policies)
	if err != nil {
		return nil, fmt.Errorf("federation: resolve metadata policy: %w", err)
	}
	resolved, err := intfed.ApplyPolicy(merged, crit, leafMetadata)
	if err != nil {
		return nil, fmt.Errorf("federation: apply metadata policy: %w", err)
	}
	return resolved, nil
}

// findReachableSuperior tries each hint in order (OpenID Federation 1.0
// §10.1's own loop-prevention rule: "Federation participants MUST NOT
// attempt to fetch Entity Statements they already have obtained during
// this process"), returning the first whose Entity Configuration
// fetches and self-verifies successfully.
func (r *Resolver) findReachableSuperior(ctx context.Context, hints []string, visited map[string]bool, now time.Time) (string, intfed.Statement, string, intfed.Claims, error) {
	var lastErr error
	for _, hint := range hints {
		if visited[hint] {
			continue
		}
		stmt, token, err := fetchEntityConfiguration(ctx, r.deps.HTTP, hint)
		if err != nil {
			lastErr = err
			continue
		}
		if stmt.ClaimedIssuer() != hint || stmt.ClaimedSubject() != hint {
			lastErr = fmt.Errorf("entity configuration for %q has iss=%q sub=%q", hint, stmt.ClaimedIssuer(), stmt.ClaimedSubject())
			continue
		}
		claims, err := r.verifySelfSigned(stmt, hint, now)
		if err != nil {
			lastErr = err
			continue
		}
		return hint, stmt, token, claims, nil
	}
	if lastErr != nil {
		return "", intfed.Statement{}, "", intfed.Claims{}, fmt.Errorf("no reachable superior among %v (last error: %w)", hints, lastErr)
	}
	return "", intfed.Statement{}, "", intfed.Claims{}, fmt.Errorf("no unvisited superior among %v", hints)
}

// verifySelfSigned verifies stmt (expected to be entityID's own Entity
// Configuration, iss == sub == entityID) against its own claimed jwks —
// OpenID Federation 1.0 §10.2's "For ES[0], verify that its signature
// validates with a public key in ES[0]['jwks']", generalized to any
// self-signed statement encountered while walking a chain (every
// Intermediate's own Entity Configuration gets exactly the same
// self-consistency check on the way to discovering its authority_hints
// and fetch endpoint). This alone does not establish trust — it only
// proves the entity controls the keys it claims to — which is why
// Resolve always additionally cross-checks the statement that actually
// closes the chain (a Trust Anchor's pre-configured key, or a
// superior's own vouching) before relying on anything self-signed.
func (r *Resolver) verifySelfSigned(stmt intfed.Statement, entityID string, now time.Time) (intfed.Claims, error) {
	return r.verifyAgainstJWKS(stmt, stmt.ClaimedJWKS(), entityID, entityID, stmt.Algorithm(), now)
}

// verifyAgainstJWKS resolves candidate keys from jwksRaw matching
// stmt's own algorithm (and kid, if the header carries one) and tries
// Verify against each until one succeeds.
func (r *Resolver) verifyAgainstJWKS(stmt intfed.Statement, jwksRaw json.RawMessage, expectedIssuer, expectedSubject string, algorithm fapi.SignatureAlgorithm, now time.Time) (intfed.Claims, error) {
	candidates, err := jose.ParseJWKSet(jwksRaw)
	if err != nil {
		return intfed.Claims{}, fmt.Errorf("parse jwks: %w", err)
	}
	policy := intfed.VerifyPolicy{
		ExpectedIssuer: expectedIssuer, ExpectedSubject: expectedSubject,
		Algorithm: algorithm, Now: now,
		MaxLifetime: r.cfg.Limits.MaxStatementLifetime, MaxClockSkew: r.cfg.Limits.MaxClockSkew,
	}
	kid := stmt.KeyID()
	var lastErr error
	tried := false
	for _, c := range candidates {
		if c.Algorithm != algorithm {
			continue
		}
		if kid != "" && c.KeyID != kid {
			continue
		}
		tried = true
		claims, err := stmt.Verify(c.PublicKey, policy)
		if err == nil {
			return claims, nil
		}
		lastErr = err
	}
	if !tried {
		return intfed.Claims{}, fmt.Errorf("no candidate key found for algorithm %v kid %q among %d keys", algorithm, kid, len(candidates))
	}
	return intfed.Claims{}, fmt.Errorf("signature verification failed against every candidate key: %w", lastErr)
}
