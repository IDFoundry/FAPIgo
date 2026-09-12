// Package federation implements the leaf-entity side of OpenID
// Federation 1.0 (Final): resolving a Trust Chain from a subject entity
// up to a pre-configured Trust Anchor, applying every metadata_policy
// encountered along the way, and returning the subject's Resolved
// Metadata (OpenID Federation 1.0 §10). It wraps internal/federation's
// Entity Statement create/verify/policy primitives with the network
// fetching (over fapihttp, per ARCHITECTURE.md design rule 6) that
// package deliberately leaves out.
//
// Like keys and storage, this is a shared subsystem package, not a
// fourth role alongside client/server/resource — both an authorization
// server (as an OpenID Provider) and a client (as a Relying Party) need
// the identical capability (self-issue an Entity Configuration via
// SelfIssuer, resolve a peer's Trust Chain via Resolver), which is
// exactly why it isn't split asymmetrically the way most of this
// module's internal/ packages are. server and client each gain their
// own thin, role-specific glue over this package — building their own
// federation_entity/openid_relying_party/openid_provider metadata and
// serving SelfIssuer's output at their own WellKnownPath, using Resolve
// to establish trust in a federation-presented peer — rather than this
// package trying to be a fourth role itself.
//
// # Scope
//
// Resolving a Trust Chain (Resolver) fetches Entity Configurations and
// Subordinate Statements as a client of those endpoints (OpenID
// Federation 1.0 §8.1/§9). A Trust Anchor's own Entity Identifier and
// public signing keys must be supplied out of band (see TrustAnchor) —
// OpenID Federation 1.0 §10's own opening requirement, mirroring how a
// TLS client is configured with a root CA bundle rather than
// discovering trust roots live over the network.
//
// SubordinateIssuer is the counterpart for an entity acting as an
// Intermediate or Trust Anchor — it signs Subordinate Statements about
// its own Immediate Subordinates, the same way SelfIssuer signs an
// Entity Configuration. Like every other type in this package, it is
// transport-agnostic: SubjectFromFetchRequest and
// RejectUnsupportedListingFilters are small net/http adapter helpers
// for the request-shape checks OpenID Federation 1.0 §9/§8.2 require of
// a federation_fetch_endpoint/federation_list_endpoint, but this
// package still does not itself serve HTTP — an embedder wires
// SubordinateIssuer and these helpers into its own http.Handler, the
// same way it already does for SelfIssuer's own output at WellKnownPath
// (see cmd/conformance-federation-trust-anchor for a complete
// reference). What this package still doesn't do: serve the actual
// Fetch/List endpoints itself (no role in this module owns an
// http.Server — see ARCHITECTURE.md design rules 6-7), track which
// entities are subordinates (an embedder's own storage, not a
// federation.SubordinateRepository this package doesn't define — see
// SubordinateStatementParams' own doc comment for why a direct-call-
// argument shape was chosen over a lookup interface), or support any of
// §8.2's four Subordinate Listing filter parameters (entity_type,
// trust_marked, trust_mark_type, intermediate) — RejectUnsupportedListingFilters
// exists specifically because this package cannot honor them, not
// despite that.
//
// Resolve enforces the resolver-wide Limits.MaxPathLength ceiling (the
// constraint most directly relevant to resource exhaustion) and every
// Subordinate Statement's own constraints claim in full:
// max_path_length (§6.2.1), naming_constraints (§6.2.2) and
// allowed_entity_types (§6.2.3).
//
// Trust marks (OpenID Federation 1.0 §7) an entity declares about
// itself are surfaced, unverified, as ResolvedEntity.TrustMarks;
// Resolver.VerifyTrustMark establishes trust in one, resolving the
// mark's own issuer as a fresh Trust Chain against this Resolver's own
// Trust Anchors before checking its signature and claims — and, when
// the Trust Anchor used to establish that trust names the mark's own
// type in its own "trust_mark_owners" claim (§7.2), additionally
// requiring and validating a "delegation" claim against that type's
// real owner (whose keys are published directly in trust_mark_owners,
// not resolved via a separate Trust Chain). TrustMarkIssuer issues
// Trust Marks and Trust Mark Delegations for a caller acting as a Trust
// Mark Issuer or a type's real owner — transport-agnostic like
// everything else here, since (unlike Fetch/List) OpenID Federation 1.0
// defines no HTTP endpoint for requesting one; issuance is always an
// out-of-band administrative act. See its own doc comment, and
// internal/federation's own doc.go "Trust Marks" section, for exactly
// which parts of §7 this first version does not yet implement (the
// Trust Mark Status/Trust Marked Entities Listing endpoints, §8/§9).
//
// Automatic client registration (OpenID Federation 1.0 §12.1) is
// implemented by AutomaticClientRepository/AutomaticClientKeySource,
// for an OpenID Provider that wants to accept a Relying Party's own
// Entity Identifier as client_id without a prior registration step —
// see AutomaticClientRepository's own doc comment for exactly which
// registration shapes this first version supports (only
// ClientAuthMethodPrivateKeyJWT; jwks or jwks_uri; CIBA and
// client_credentials each gated by their own
// AutomaticRegistrationConfig switch, off by default) and which it
// deliberately doesn't yet (Explicit Registration, §12.2, is not
// implemented by this package at all).
// §12.1.1's own aud/sub/jti Request Object rules are enforced by the
// server package via storage.RegisteredClientConfig's own
// AutomaticFederationRegistration field, not by this package — a
// request-handling concern, not a client registration one.
package federation
