// Package pkce implements PKCE (RFC 7636) code-verifier generation and
// code-challenge derivation/verification.
//
// Generation is used by client when starting an authorization request;
// verification is used by server when redeeming an authorization code.
// Both sides share the same S256 transform so there is exactly one
// implementation of it to audit.
package pkce
