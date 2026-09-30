package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
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

	// MaxAuthorityHints bounds how many "authority_hints" (OpenID
	// Federation 1.0 §3.1.1) any one Entity Configuration on the path
	// may list: Resolve rejects one that lists more, rather than trying
	// only some of them. Resolve fetches each listed superior's Entity
	// Configuration in turn until one validates, and the subject entity
	// ID is often chosen by an unauthenticated caller (automatic
	// registration resolves an unknown client_id before the request
	// naming it can be authenticated), so without this bound one
	// Entity Configuration listing thousands of hints would turn a
	// single Resolve call into thousands of outbound fetches. Together
	// with MaxPathLength it caps one Resolve call at
	// MaxPathLength × (MaxAuthorityHints + 2) + 1 fetches. Real Entity
	// Configurations list one hint, or a handful for an entity in
	// several federations.
	MaxAuthorityHints int

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
	if cfg.Limits.MaxAuthorityHints <= 0 {
		return nil, fmt.Errorf("federation: config: limits.max_authority_hints must be positive")
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
	TrustMarks []RawTrustMark

	// TrustMarkOwners is EntityID's own "trust_mark_owners" claim
	// (OpenID Federation 1.0 §7.2), exactly as
	// intfed.Claims.TrustMarkOwners describes — nil if EntityID declared
	// none. Only meaningful when EntityID is a Trust Anchor;
	// VerifyTrustMark reads this (from the Trust Anchor actually used to
	// establish trust in a Trust Mark's own issuer) to decide whether
	// that Trust Mark's type requires a "delegation" claim at all.
	TrustMarkOwners map[string]TrustMarkOwner

	// TrustMarkIssuers is EntityID's own "trust_mark_issuers" claim
	// (OpenID Federation 1.0 §3.1.1), exactly as
	// intfed.Claims.TrustMarkIssuers describes — nil if EntityID declared
	// none. Only meaningful when EntityID is a Trust Anchor:
	// VerifyTrustMark reads it (from the Trust Anchor used to establish
	// trust in a Trust Mark's issuer) under
	// RequireFederationAccreditation.
	TrustMarkIssuers map[string][]string

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

	// superiorMetadata is the "metadata" claim of the Subordinate
	// Statement about the subject — its Immediate Superior's own values
	// for the subject's metadata (§3.1.1), applied before any policy.
	superiorMetadata map[string]json.RawMessage

	// subjectJWKS is captured exactly once, at hop 0 — the first
	// superior's own statement "about entityAt" is, at that point,
	// necessarily about subjectID itself (entityAt only ever advances
	// past subjectID at the end of hop 0). See ResolvedEntity.JWKS's
	// own doc comment for what this value means and is used for.
	subjectJWKS json.RawMessage

	// entityAtClaims are entityAt's own self-verified Entity
	// Configuration claims.
	entityAtClaims intfed.Claims

	// cache is shared by every branch of the search.
	cache *statementCache
}

func newChainWalkState(subjectID string, leafStmt intfed.Statement, leafToken string, leafClaims intfed.Claims, cache *statementCache) *chainWalkState {
	return &chainWalkState{
		cache:          cache,
		entityAtClaims: leafClaims,
		subjectID:      subjectID,
		leafClaims:     leafClaims,
		minExpiry:      leafClaims.ExpiresAt,

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

	cache := newStatementCache()
	leafStmt, leafToken, err := cache.entityConfiguration(ctx, r.deps.HTTP, subjectID)
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

	st := newChainWalkState(subjectID, leafStmt, leafToken, leafClaims, cache)
	budget := r.cfg.Limits.MaxPathLength * r.cfg.Limits.MaxAuthorityHints
	return r.walk(ctx, st, 0, &budget, now)
}

// walk extends the Trust Chain in st from its current entity (st.entityAt)
// by one hop, trying each of that entity's authority hints — configured
// Trust Anchors first, then the rest in the order listed — and
// backtracking to the next hint whenever a branch can't reach a
// configured Trust Anchor. OpenID Federation 1.0 §10.1 builds chains
// through every authority hint, so taking only the first reachable one
// would fail to resolve an entity whose first superior leads nowhere
// trusted while another reaches a configured Trust Anchor.
//
// budget bounds the whole search to MaxPathLength × MaxAuthorityHints
// superiors tried — the most a single first-reachable walk could already
// fetch — so backtracking adds no amplification an entity's authority
// hints could exploit (§18.1).
func (r *Resolver) walk(ctx context.Context, st *chainWalkState, hop int, budget *int, now time.Time) (ResolvedEntity, error) {
	if hop >= r.cfg.Limits.MaxPathLength {
		return ResolvedEntity{}, fmt.Errorf("federation: trust chain for %q exceeds the configured max path length (%d)", st.subjectID, r.cfg.Limits.MaxPathLength)
	}
	hints := r.selfClaimsForHop(st).AuthorityHints
	if len(hints) == 0 {
		return ResolvedEntity{}, fmt.Errorf("federation: %q has no authority_hints and is not a configured trust anchor: no path to a trusted trust anchor", st.entityAt)
	}
	if len(hints) > r.cfg.Limits.MaxAuthorityHints {
		return ResolvedEntity{}, fmt.Errorf("federation: %q lists %d authority_hints, more than the configured limit (%d)", st.entityAt, len(hints), r.cfg.Limits.MaxAuthorityHints)
	}

	var lastErr error
	for _, hint := range r.trustAnchorsFirst(hints) {
		if st.visited[hint] {
			continue
		}
		if *budget <= 0 {
			return ResolvedEntity{}, fmt.Errorf("federation: trust chain for %q: stopped after trying %d superiors (MaxPathLength × MaxAuthorityHints)", st.subjectID, r.cfg.Limits.MaxPathLength*r.cfg.Limits.MaxAuthorityHints)
		}
		*budget--
		result, err := r.tryHint(ctx, st, hop, hint, budget, now)
		if err == nil {
			return result, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		return ResolvedEntity{}, fmt.Errorf("federation: %q: no unvisited superior among %v", st.entityAt, hints)
	}
	return ResolvedEntity{}, fmt.Errorf("federation: %q: no path to a configured trust anchor through %v (last error: %w)", st.entityAt, hints, lastErr)
}

// tryHint extends a copy of st through the superior hint — its Entity
// Configuration and its Subordinate Statement about st.entityAt — and
// either completes the chain there, when hint is a configured Trust
// Anchor, or continues the walk above it. st itself is never modified,
// so a failed branch leaves nothing behind for the next hint.
func (r *Resolver) tryHint(ctx context.Context, st *chainWalkState, hop int, hint string, budget *int, now time.Time) (ResolvedEntity, error) {
	config, token, err := st.cache.entityConfiguration(ctx, r.deps.HTTP, hint)
	if err != nil {
		return ResolvedEntity{}, err
	}
	if config.ClaimedIssuer() != hint || config.ClaimedSubject() != hint {
		return ResolvedEntity{}, fmt.Errorf("federation: entity configuration for %q has iss=%q sub=%q", hint, config.ClaimedIssuer(), config.ClaimedSubject())
	}
	claims, err := r.verifySelfSigned(config, hint, now)
	if err != nil {
		return ResolvedEntity{}, fmt.Errorf("federation: entity configuration for %q: %w", hint, err)
	}
	aboveStmt, aboveToken, err := r.fetchAboveStatement(ctx, st.cache, hint, claims, st.entityAt)
	if err != nil {
		return ResolvedEntity{}, err
	}

	branch := st.clone()
	branch.visited[hint] = true
	if claims.ExpiresAt.Before(branch.minExpiry) {
		branch.minExpiry = claims.ExpiresAt
	}
	branch.chain = append(branch.chain, hint)
	// aboveStmt (issued by hint, about st.entityAt) is a genuine Trust
	// Chain entry whether hint is a Trust Anchor or another Intermediate
	// — unlike an Intermediate's own self-signed Entity Configuration
	// (see selfClaimsForHop), which is fetched for routing only.
	branch.tokens = append(branch.tokens, aboveToken)
	sup := hopSuperior{id: hint, config: config, claims: claims, token: token, aboveStmt: aboveStmt}

	if anchor, ok := r.trustAnchorsByID[hint]; ok {
		return r.finalizeTrustChain(branch, hop, sup, anchor, now)
	}
	if err := r.advanceIntermediateHop(branch, hop, sup, now); err != nil {
		return ResolvedEntity{}, err
	}
	return r.walk(ctx, branch, hop+1, budget, now)
}

// trustAnchorsFirst orders hints with this resolver's configured Trust
// Anchors first, each group keeping the order the entity listed them in.
func (r *Resolver) trustAnchorsFirst(hints []string) []string {
	ordered := make([]string, 0, len(hints))
	for _, h := range hints {
		if _, ok := r.trustAnchorsByID[h]; ok {
			ordered = append(ordered, h)
		}
	}
	for _, h := range hints {
		if _, ok := r.trustAnchorsByID[h]; !ok {
			ordered = append(ordered, h)
		}
	}
	return ordered
}

// statementCache holds every Entity Configuration and Subordinate
// Statement fetched during one Resolve — including failed fetches — so
// the search never fetches one twice: OpenID Federation 1.0 §10.1's
// "Federation participants MUST NOT attempt to fetch Entity Statements
// they already have obtained during this process", which backtracking
// through a federation where two superiors share a superior would
// otherwise do. Every branch of the search shares it.
type statementCache struct {
	configs      map[string]fetchedStatement
	subordinates map[string]fetchedStatement
}

type fetchedStatement struct {
	stmt  intfed.Statement
	token string
	err   error
}

func newStatementCache() *statementCache {
	return &statementCache{configs: map[string]fetchedStatement{}, subordinates: map[string]fetchedStatement{}}
}

func (c *statementCache) entityConfiguration(ctx context.Context, fetcher *fapihttp.Client, entityID string) (intfed.Statement, string, error) {
	f, ok := c.configs[entityID]
	if !ok {
		f.stmt, f.token, f.err = fetchEntityConfiguration(ctx, fetcher, entityID)
		c.configs[entityID] = f
	}
	return f.stmt, f.token, f.err
}

func (c *statementCache) subordinateStatement(ctx context.Context, fetcher *fapihttp.Client, fetchEndpoint, subjectID string) (intfed.Statement, string, error) {
	key := fetchEndpoint + "\x00" + subjectID
	f, ok := c.subordinates[key]
	if !ok {
		f.stmt, f.token, f.err = fetchSubordinateStatement(ctx, fetcher, fetchEndpoint, subjectID)
		c.subordinates[key] = f
	}
	return f.stmt, f.token, f.err
}

// clone copies st for one branch of the search, so extending the copy
// never changes st or any other branch.
func (st *chainWalkState) clone() *chainWalkState {
	c := *st
	c.visited = maps.Clone(st.visited)
	c.chain = slices.Clone(st.chain)
	c.tokens = slices.Clone(st.tokens)
	c.subordinatePolicies = slices.Clone(st.subordinatePolicies)
	c.subordinateConstraints = slices.Clone(st.subordinateConstraints)
	return &c
}

// hopSuperior groups the reachable superior a hop discovered (via
// findReachableSuperior) with the Subordinate Statement it went on to
// issue about the entity below it (via fetchAboveStatement) — purely a
// parameter-count reduction for finalizeTrustChain and
// advanceIntermediateHop; see Resolve's own call site for how each
// field is populated.
type hopSuperior struct {
	id        string
	config    intfed.Statement
	claims    intfed.Claims
	token     string
	aboveStmt intfed.Statement
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
		TrustMarkIssuers: leafClaims.TrustMarkIssuers,
		Tokens:           []string{leafToken},
	}, nil
}

// selfClaimsForHop returns st.entityAt's own claims for this hop: the
// subject's own at hop 0, and at every later hop the claims of the
// Entity Configuration tryHint already fetched and self-verified when it
// chose entityAt as a superior (and folded into st.minExpiry then). The
// configuration is never fetched a second time, so the one that decided
// the hop is the one whose authority_hints continue it. Its raw token is
// never appended to st.tokens: an Intermediate's own Entity
// Configuration is fetched for routing only, not itself an entry of the
// canonical Trust Chain (see ResolvedEntity.Tokens).
func (r *Resolver) selfClaimsForHop(st *chainWalkState) intfed.Claims {
	return st.entityAtClaims
}

// fetchAboveStatement fetches and validates the Subordinate Statement
// that superiorID's own federation_fetch_endpoint (resolved from
// superiorClaims' federation_entity metadata) issues about entityAt —
// the "aboveStmt" that Resolve either closes the Trust Chain with
// (superiorID is a configured Trust Anchor, see finalizeTrustChain) or
// carries into the next hop as the new belowStmt (see
// advanceIntermediateHop).
func (r *Resolver) fetchAboveStatement(ctx context.Context, cache *statementCache, superiorID string, superiorClaims intfed.Claims, entityAt string) (intfed.Statement, string, error) {
	aboveMeta, err := parseEntityMetadata(superiorClaims.Metadata)
	if err != nil {
		return intfed.Statement{}, "", fmt.Errorf("federation: %q: federation_entity metadata: %w", superiorID, err)
	}
	if aboveMeta.FetchEndpoint == "" {
		return intfed.Statement{}, "", fmt.Errorf("federation: %q has no federation_fetch_endpoint", superiorID)
	}
	aboveStmt, aboveToken, err := cache.subordinateStatement(ctx, r.deps.HTTP, aboveMeta.FetchEndpoint, entityAt)
	if err != nil {
		return intfed.Statement{}, "", err
	}
	if aboveStmt.ClaimedIssuer() != superiorID || aboveStmt.ClaimedSubject() != entityAt {
		return intfed.Statement{}, "", fmt.Errorf("federation: subordinate statement about %q from %q has iss=%q sub=%q",
			entityAt, superiorID, aboveStmt.ClaimedIssuer(), aboveStmt.ClaimedSubject())
	}
	return aboveStmt, aboveToken, nil
}

// finalizeTrustChain handles the hop where sup — whose Subordinate
// Statement sup.aboveStmt about st.entityAt was just fetched and
// appended to st.chain/st.tokens — turns out to be a configured Trust
// Anchor, closing the Trust Chain. Called at most once per Resolve call,
// from the hop where it happens; see Resolve's own call site.
func (r *Resolver) finalizeTrustChain(st *chainWalkState, hop int, sup hopSuperior, anchor TrustAnchor, now time.Time) (ResolvedEntity, error) {
	// sup.config now plays two roles at once: it's both the routing
	// statement that got us here, and ES[i] — "the statement about
	// sup.id" collapses to sup.id's own self-signed config, since a
	// trust anchor has no superior of its own to issue a separate one.
	if _, err := r.verifyAgainstJWKS(sup.config, anchor.JWKS, sup.id, sup.id, sup.config.Algorithm(), now); err != nil {
		return ResolvedEntity{}, fmt.Errorf("federation: trust anchor %q does not validate against its configured keys: %w", sup.id, err)
	}
	aboveClaims, err := r.verifyAgainstJWKS(sup.aboveStmt, sup.claims.JWKS, sup.id, st.entityAt, sup.aboveStmt.Algorithm(), now)
	if err != nil {
		return ResolvedEntity{}, fmt.Errorf("federation: subordinate statement about %q from trust anchor %q: %w", st.entityAt, sup.id, err)
	}
	if _, err := r.verifyAgainstJWKS(st.belowStmt, aboveClaims.JWKS, st.belowIssuer, st.belowSubject, st.belowStmt.Algorithm(), now); err != nil {
		return ResolvedEntity{}, fmt.Errorf("federation: %q's statement (issued by %q) does not match the keys vouched for it by %q: %w", st.belowSubject, st.belowIssuer, sup.id, err)
	}
	if hop == 0 {
		st.subjectJWKS = aboveClaims.JWKS
		st.superiorMetadata = aboveClaims.Metadata
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
	declared, err := applySuperiorMetadata(st.leafClaims.Metadata, st.superiorMetadata)
	if err != nil {
		return ResolvedEntity{}, fmt.Errorf("federation: metadata %q's Immediate Superior sets for it: %w", st.subjectID, err)
	}
	leafMetadata := filterAllowedEntityTypes(st.subordinateConstraints, declared)
	resolvedMetadata, err := r.resolveMetadata(st.subordinatePolicies, leafMetadata)
	if err != nil {
		return ResolvedEntity{}, err
	}
	// sup.token (ES[i], the Trust Anchor's own Entity Configuration)
	// closes the sequence — see ResolvedEntity.Tokens's own doc comment.
	return ResolvedEntity{
		EntityID: st.subjectID, TrustAnchor: sup.id, Chain: st.chain,
		Metadata: resolvedMetadata, ExpiresAt: st.minExpiry,
		JWKS: st.subjectJWKS, TrustMarks: st.leafClaims.TrustMarks, TrustMarkOwners: st.leafClaims.TrustMarkOwners,
		TrustMarkIssuers: st.leafClaims.TrustMarkIssuers,
		Tokens:           append(st.tokens, sup.token),
	}, nil
}

// advanceIntermediateHop handles the hop where sup — whose Subordinate
// Statement sup.aboveStmt about st.entityAt was just fetched and
// appended to st.chain/st.tokens — is an Intermediate, not (yet known
// to be) a Trust Anchor: sup.aboveStmt can't be verified until the next
// hop learns what vouches for sup.id's own keys, so it becomes the new
// st.belowStmt. Verifies the OLD st.belowStmt now, though: sup.aboveStmt
// (issued by sup.id, about st.entityAt) is exactly "the statement about
// st.entityAt" that belowStmt's own verification rule calls for.
func (r *Resolver) advanceIntermediateHop(st *chainWalkState, hop int, sup hopSuperior, now time.Time) error {
	if _, err := r.verifyAgainstJWKS(st.belowStmt, sup.aboveStmt.ClaimedJWKS(), st.belowIssuer, st.belowSubject, st.belowStmt.Algorithm(), now); err != nil {
		return fmt.Errorf("federation: %q's statement (issued by %q) does not match the keys vouched for it by %q: %w", st.belowSubject, st.belowIssuer, sup.id, err)
	}
	if hop == 0 {
		// Unverified until the next iteration verifies sup.aboveStmt's
		// signature (as the new belowStmt) — safe to capture now for
		// the same reason ClaimedMetadataPolicy's own doc comment
		// gives; see ResolvedEntity.JWKS's own doc comment for why
		// hop 0 specifically.
		st.subjectJWKS = sup.aboveStmt.ClaimedJWKS()
		st.superiorMetadata = sup.aboveStmt.ClaimedMetadata()
	}
	// sup.aboveStmt's own metadata_policy is unverified until the next
	// iteration verifies its signature (as the new belowStmt) — safe to
	// read now for the reasons Statement.ClaimedMetadataPolicy's own
	// doc comment gives: it's only ever merged and applied once the
	// whole chain, this statement included, has been cryptographically
	// verified.
	policy, crit := sup.aboveStmt.ClaimedMetadataPolicy()
	st.subordinatePolicies = append(st.subordinatePolicies, subordinatePolicy{policy: policy, crit: crit})
	// sup.aboveStmt's own constraints claim is unverified for exactly
	// the same reason and until exactly the same later point as its
	// metadata_policy, immediately above — see
	// intfed.Statement.ClaimedConstraints's own doc comment.
	if constraints := sup.aboveStmt.ClaimedConstraints(); constraints != nil {
		st.subordinateConstraints = append(st.subordinateConstraints, subordinateConstraint{
			constraints: *constraints,
			appliesTo:   append([]string{}, st.chain[:len(st.chain)-1]...),
		})
	}

	st.belowStmt = sup.aboveStmt
	st.belowIssuer = sup.id
	st.belowSubject = st.entityAt
	st.entityAt = sup.id
	st.entityAtClaims = sup.claims
	return nil
}

// applySuperiorMetadata applies the Immediate Superior's own metadata
// values (the "metadata" claim of its Subordinate Statement about the
// subject) to the subject's declared metadata, as OpenID Federation 1.0
// §3.1.1 and §6.1.4.2 require before any metadata policy: each parameter
// the superior sets replaces the subject's own under the same Entity
// Type, and only for Entity Types the subject's Entity Configuration
// itself declares. subject is not modified.
func applySuperiorMetadata(subject, superior map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	if len(superior) == 0 {
		return subject, nil
	}
	out := make(map[string]json.RawMessage, len(subject))
	for entityType, raw := range subject {
		out[entityType] = raw
		override, ok := superior[entityType]
		if !ok {
			continue
		}
		var params, overrides map[string]json.RawMessage
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, fmt.Errorf("the subject's %s metadata is not a JSON object: %w", entityType, err)
		}
		if err := json.Unmarshal(override, &overrides); err != nil {
			return nil, fmt.Errorf("the superior's %s metadata is not a JSON object: %w", entityType, err)
		}
		if params == nil {
			params = make(map[string]json.RawMessage, len(overrides))
		}
		for name, value := range overrides {
			params[name] = value
		}
		merged, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		out[entityType] = merged
	}
	return out, nil
}

// subordinatePolicy is one Subordinate Statement's own metadata_policy
// and metadata_policy_crit claims, collected bottom-up (closest to the
// Trust Chain subject first) as Resolve walks upward.
type subordinatePolicy struct {
	policy MetadataPolicy
	crit   []string
}

// resolveMetadata merges policies (collected bottom-up by Resolve) in
// the top-down order OpenID Federation 1.0 §6.1.4.1 requires — starting
// from the statement issued by the most superior entity — and applies
// the result to leafMetadata (the Trust Chain subject's own declared
// metadata, from its Entity Configuration).
func resolveMetadataPolicies(policies []subordinatePolicy) (MetadataPolicy, []string, error) {
	var merged MetadataPolicy
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
