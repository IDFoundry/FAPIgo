// Package jose implements the shared JWT/JWS/JWK parsing, encoding and
// signature-verification primitives used throughout the module: strict
// parsing, JWK validation, and algorithm-policy enforcement.
//
// It is intentionally low-level and generic — client, server and resource
// each build role-specific signers/verifiers with their own policy on top
// of it (see internal/requestobject, internal/jarm, internal/dpop,
// internal/clientassertion, internal/token). jose itself must not encode
// any FAPI-specific policy or trust decision; those belong one layer up,
// where the difference between "signing" and "verifying" — and the
// resulting trust boundary — is explicit.
//
// # JWK encoding
//
// Every JWK this package parses — ParseJWK, a JWS header's "jwk", and
// each entry of ParseJWKSet, ParseTrustedJWKSet and ParseEncryptionJWKSet
// — follows three rules for the length of its members:
//
//   - An EC "x" or "y" must decode to exactly the size of a coordinate
//     on its curve, 32 octets for P-256, leading zero octets included
//     (RFC 7518 §6.2.1.2, §6.2.1.3). One written without its leading
//     zero octets, or with extra ones, is refused with
//     ErrCoordinateLength, and a JWK Set entry holding one is skipped:
//     some implementations read such a coordinate and others refuse it.
//   - An Ed25519 "x" must be 32 octets (RFC 8037 §2).
//   - An RSA "n" or "e" may carry leading zero octets, which are
//     dropped. RFC 7518 §2 asks a producer to encode a Base64urlUInt
//     minimally, but some write a modulus as 257 octets.
//
// Only the key itself is kept, so MarshalJSON and Thumbprint encode it
// canonically whatever spelling it arrived in, and every identifier
// this module derives from a JWK — a DPoP proof's jkt and replay key,
// an attestation's instance key, the kid a key given without one
// answers to (ThumbprintKeyID) — is computed from the parsed key,
// never from the member strings received: two spellings of one key
// have one thumbprint. A producer that computes a thumbprint over a
// non-minimal "n" or "e" as it wrote it gets a different value from
// this package's.
package jose
