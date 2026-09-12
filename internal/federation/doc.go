// Package federation implements the wire-level primitives of OpenID
// Federation 1.0 (Final) Entity Statements: the signed JWT ("Entity
// Configuration" when self-issued, iss == sub; "Subordinate Statement"
// when issued by a superior about an immediate subordinate, iss != sub)
// that carries an entity's metadata, and the metadata-policy operators
// (value/add/default/one_of/subset_of/superset_of/essential) a superior
// uses to constrain a subordinate's metadata.
//
// This package covers exactly one Entity Statement in isolation —
// building, signing, parsing and verifying one JWT, and applying one
// metadata_policy to one metadata object — the same "internal protocol
// core" role internal/requestobject and internal/clientassertion play
// for their own JWTs. It does not walk a multi-hop trust chain
// (fetching a chain of superiors, accumulating and merging policy
// across every link, honoring constraints like max_path_length): that
// requires HTTP fetching and caching, and is a public package's
// concern, not this one's — see ARCHITECTURE.md's own reasoning for
// why fapihttp-mediated network access never lives in internal/.
//
// Unlike this repo's other internal/ packages, Entity Statement
// signing and verification are not asymmetric between client and
// server: a FAPI 2.0 authorization server (as an OpenID Provider) and
// a FAPI 2.0 client (as a Relying Party) both need to self-issue their
// own Entity Configuration and both need to verify a peer's statements
// while resolving a trust chain, so Create and Verify are both
// exported here rather than split one-per-role the way
// internal/jarm/internal/requestobject are.
//
// # Trust Marks
//
// trustmark.go covers Trust Mark JWTs (OpenID Federation 1.0 §7) and
// Trust Mark Delegation JWTs (§7.2) the same narrow way this package
// covers Entity Statements: building/signing and parsing/verifying one
// JWT in isolation (TrustMark/ParseTrustMark/Verify/CreateTrustMark,
// TrustMarkDelegation/ParseTrustMarkDelegation/Verify/
// CreateTrustMarkDelegation), never fetching or resolving anything
// itself, and never cross-checking a Trust Anchor's own
// "trust_mark_owners" claim to know whether a delegation is required at
// all (a federation.Resolver's own concern; see its VerifyTrustMark).
// trustmarkstatus.go covers the Trust Mark Status Response JWT (§8) the
// identical way — TrustMarkStatusResponse/ParseTrustMarkStatusResponse/
// Verify/CreateTrustMarkStatusResponse — one JWT in isolation, with the
// live query-and-verify sequence itself living in
// federation.Resolver.CheckTrustMarkStatus.
// federation.TrustMarkIssuer wraps CreateTrustMark/
// CreateTrustMarkDelegation/CreateTrustMarkStatusResponse the same way
// SelfIssuer/SubordinateIssuer wrap this package's own Create, for a
// caller acting as a Trust Mark Issuer or a type's real owner.
// Trust Marked Entities Listing (§9's first endpoint) needs no JWT type
// of its own at all — its response is a bare JSON array, so
// federation.TrustMarkListingFilters' request-shape validation is the
// whole of what §9 needs from this package. Not implemented: the
// adjacent Trust Mark endpoint (§9's third endpoint, a subject
// retrieving its own Trust Mark by type).
package federation
