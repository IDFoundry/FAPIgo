// Package grantrevocation is how a revoked grant is recorded and found:
// shared by server, which revokes grants and refuses their codes and
// refresh tokens, and resource, which refuses their access tokens.
package grantrevocation

import (
	"crypto/sha256"
	"encoding/base64"
)

// Claim is the access token claim carrying the grant ID — the name the
// OAuth Grant Management draft (FAPI working group) uses for the same
// concept.
const Claim = "grant_id"

// Key is the revocation-store key recording grantID as revoked. The
// prefix keeps it apart from the access token keys (a JWT's jti, an
// opaque token's hash) the same store holds.
func Key(grantID string) string { return "grant:" + grantID }

// CodeClaim is the access token claim carrying the code grant ID: the
// identifier the server derives, with CodeGrantID, for every grant that
// came from an authorization code, so a reused code can revoke
// everything issued from it (RFC 6749 §4.1.2) whether or not the
// application named the grant itself (Claim).
const CodeClaim = "code_grant_id"

// CodeKey is the revocation-store key recording a code grant ID as
// revoked, kept apart from Key's and from access token keys by its
// prefix.
func CodeKey(codeGrantID string) string { return "code-grant:" + codeGrantID }

// CodeGrantID derives the code grant ID from an authorization code's
// SHA-256 hash: the same at the first exchange, which records it in the
// grant, and at a reuse, which revokes it — so neither needs the store
// to remember it. Domain-separated from the hash the store keys the
// code by, and one-way, so the ID in an access token reveals nothing
// about the code.
func CodeGrantID(codeHash [32]byte) string {
	h := sha256.New()
	h.Write([]byte("fapigo code grant v1\x00"))
	h.Write(codeHash[:])
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
