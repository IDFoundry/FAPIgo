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
// federation_entity/openid_provider metadata (OpenIDRelyingPartyMetadata
// is this package's own typed struct for the openid_relying_party side)
// and serving SelfIssuer's output at their own WellKnownPath
// (WriteEntityStatement writes the Content-Type header and body an HTTP
// handler needs for that, and for a SubordinateIssuer's own output),
// using Resolve to establish trust in a federation-presented peer —
// rather than this package trying to be a fourth role itself.
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
// argument shape was chosen over a lookup interface), or decide
// whether a given filtered listing is actually correct — §8.2's four
// Subordinate Listing filter parameters (entity_type, trust_marked,
// trust_mark_type, intermediate) are parsed and validated by
// SubordinateListingFiltersFromRequest, the same "this package only
// validates the request shape, the embedder's own storage answers the
// query" division TrustMarkListingFilters already establishes for its
// own endpoint; an embedder that can't honor any of the four instead
// calls RejectUnsupportedListingFilters, per §8.2's own requirement
// that an unsupported filter be rejected outright rather than silently
// ignored.
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
// out-of-band administrative act.
//
// §7's two live-query companions are both covered too.
// Resolver.CheckTrustMarkStatus is a real network call (like Resolve
// itself) — it queries a Trust Mark's own issuer's Trust Mark Status
// endpoint (§8, POST-only, hence fapihttp.Client.Post) and verifies the
// signed response the same "resolve the issuer's Trust Chain first"
// way VerifyTrustMark does. TrustMarkIssuer.StatusResponse and
// TrustMarkFromStatusRequest are the producer-side counterpart — sign
// the answer, validate the incoming query's shape — for an embedder
// serving that endpoint itself; see cmd/conformance-federation-trust-anchor's
// own doc comment style of reference wiring for the analogous
// Fetch/List pattern (this package doesn't yet ship one for Status,
// but the shape is identical). Trust Marked Entities Listing (§8.5) is
// request-parsing only — TrustMarkListingFilters — since, like
// Subordinate Listing, an embedder's own storage of issued Trust Marks
// answers the actual query. The adjacent Trust Mark endpoint (§8.6, a
// subject — or, when the embedder chooses to allow it, another
// authenticated party — retrieving a subject's own Trust Mark by type)
// is covered the identical "request-parsing only" way:
// TrustMarkRequestFromHTTP validates the incoming "trust_mark_type"/
// "sub" (both REQUIRED, unlike Listing's own OPTIONAL "sub"), and
// TrustMarkIssuer.TrustMark's own returned token — already meant to be
// served verbatim, Content-Type TrustMarkContentType — answers it once
// the embedder's own storage confirms the subject actually has that
// Trust Mark; ErrorNotFound (via NewError) is the §8.6.2-shaped 404
// when it doesn't. Not covered: any revocation/active-tracking storage
// of this package's own — CheckTrustMarkStatus and StatusResponse
// exist to move the wire format, never to decide or record a Trust
// Mark's actual standing.
//
// The Resolve endpoint (§8.3) is covered on the consumer side only:
// Resolver.ResolveViaEndpoint queries a peer's resolve endpoint instead
// of walking a Trust Chain hop by hop itself, trusting the response by
// resolving its own issuer as a fresh Trust Chain first — the same
// "establish trust in the issuer before trusting its signature" pattern
// VerifyTrustMark/CheckTrustMarkStatus already use — then verifying the
// signature against that issuer's own vouched-for key, never a key the
// response itself merely claims to hold. The producer side is covered
// too: ResolveIssuer.Response signs a Resolve Response for an
// already-resolved ResolvedEntity (a caller's own Resolve result,
// exposed via ResolvedEntity.Tokens — the raw compact-serialized Entity
// Statement tokens that composed the chain, OpenID Federation 1.0 §4's
// own ES[0..i] sequence, excluding every Intermediate's own self-signed
// Entity Configuration fetched purely for routing) rather than
// performing a resolution of its own — the resolution work is identical
// to what Resolve already does for any other caller. Response itself
// checks the resolved Trust Anchor is one of the request's own (possibly
// repeated) "trust_anchor" values (§8.3.1); ResolveRequestFromHTTP
// parses an incoming request's shape the same way SubjectFromFetchRequest/
// TrustMarkFromStatusRequest already do for their own endpoints. Trust
// Mark inclusion in a Resolve Response (§8.3's own "and Trust Marks for
// an Entity") is covered too: Response's own trustMarks parameter takes
// a caller-verified []VerifiedTrustMark (typically produced by looping
// over ResolvedEntity.TrustMarks and calling VerifyTrustMark on each,
// keeping only the ones that verify — Response itself never verifies
// one) and folds each entry's own expiry into the response's "exp" the
// same way resolved.ExpiresAt already is.
//
// The Federation Historical Keys endpoint (§8.7) is covered on both
// sides, unlike Resolve — publishing a rotated-out key's own lifetime
// and revocation status (§8.7.3) is self-contained per-entity data, not
// dependent on Resolve's own internals the way a Resolve Response's
// trust_chain claim is. Resolver.FetchHistoricalKeys queries a peer's
// endpoint and authenticates the response the identical way
// ResolveViaEndpoint does (resolve the response's own issuer as a fresh
// Trust Chain first, verify against that resolution's own vouched-for
// key); intfed.CreateHistoricalKeysResponse is the producer-side signing
// primitive, for an embedder tracking its own retired keys. Consulting
// this endpoint is always an explicit, separate call — Resolve itself
// never falls back to it automatically when a statement's own "kid"
// isn't found among an issuer's current jwks.
//
// Automatic client registration (OpenID Federation 1.0 §12.1) is
// implemented by AutomaticClientRepository/AutomaticClientKeySource,
// for an OpenID Provider that wants to accept a Relying Party's own
// Entity Identifier as client_id without a prior registration step —
// see AutomaticClientRepository's own doc comment for exactly which
// registration shapes this first version supports: every
// storage.ClientAuthMethod this module implements (private_key_jwt, and
// every RFC 8705 mTLS method — self_signed_tls_client_auth reads the
// RP's own certificate from its jwks/jwks_uri's own "x5c" member; the
// four SAN-typed siblings each read their own plain-string RFC 8705
// §2.1.2 metadata parameter directly); jwks or jwks_uri; CIBA and
// client_credentials each gated by their own
// AutomaticRegistrationConfig switch, off by default. Deliberately not
// yet implemented: Explicit Registration (§12.2, not implemented by
// this package at all).
// §12.1.1's own aud/sub/jti Request Object rules are enforced by the
// server package via storage.RegisteredClientConfig's own
// AutomaticFederationRegistration field, not by this package — a
// request-handling concern, not a client registration one.
package federation
