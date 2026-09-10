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
// This first version resolves a chain for a leaf entity only — it
// fetches Entity Configurations and Subordinate Statements as a client
// of those endpoints (OpenID Federation 1.0 §8.1/§9), it does not
// implement the server side of those endpoints for an entity acting as
// an Intermediate or Trust Anchor. A Trust Anchor's own Entity
// Identifier and public signing keys must be supplied out of band (see
// TrustAnchor) — OpenID Federation 1.0 §10's own opening requirement,
// mirroring how a TLS client is configured with a root CA bundle rather
// than discovering trust roots live over the network.
//
// Trust marks (OpenID Federation 1.0 §7), the naming_constraints and
// allowed_entity_types members of a Subordinate Statement's own
// constraints claim (OpenID Federation 1.0 §6.2.2/§6.2.3), and
// automatic/explicit client registration are not implemented by this
// package — Resolve enforces max_path_length (the constraint most
// directly relevant to resource exhaustion) and leaves the rest for a
// later revision once a concrete caller needs them, the same
// deliberately-narrow-first-cut precedent internal/federation's own
// doc.go already sets for trust marks.
package federation
