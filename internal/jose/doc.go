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
package jose
