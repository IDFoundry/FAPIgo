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
// covers Entity Statements: parsing and verifying one JWT in isolation
// (TrustMark/ParseTrustMark/Verify, TrustMarkDelegation/
// ParseTrustMarkDelegation/Verify), never fetching or resolving
// anything itself, and never cross-checking a Trust Anchor's own
// "trust_mark_owners" claim to know whether a delegation is required at
// all (a federation.Resolver's own concern; see its VerifyTrustMark).
// This first version deliberately does not implement: the Trust Mark
// Status endpoint (§8) or Trust Marked Entities Listing endpoint (§9),
// both live alternatives/supplements to the offline validation
// procedure this package implements; and Trust Mark (or delegation)
// issuance (this package only ever verifies one someone else issued,
// the same "consumer, not producer" stance this package already takes
// toward Explicit Registration Responses).
package federation
