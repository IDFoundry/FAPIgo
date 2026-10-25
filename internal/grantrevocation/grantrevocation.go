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

// Key is the revocation-store key recording grantID, a grant issuer
// issued, as revoked. The prefix keeps it apart from the access token
// keys (a JWT's jti, an opaque token's hash) the same store holds, and
// the issuer keeps one issuer's grant IDs apart from another's when
// servers with different issuers share the store: the application
// chooses grant IDs, so two tenants can both have a grant "g1". A grant
// ID never contains "@" (see server.GrantedAuthorization.GrantID), and
// a code grant ID never does either, so the issuer can't be mistaken for
// part of the ID, and no key here equals a legacy one.
func Key(issuer, grantID string) string { return "grant:" + grantID + "@" + issuer }

// Keys are the keys IsRevoked checks for grantID: Key, the only one
// written, and the key servers before v0.61.0 wrote, not namespaced by
// issuer, so a grant revoked before an upgrade stays revoked. Such a
// record expires once nothing issued from the grant can still be used,
// so the legacy key stops matching anything by itself.
func Keys(issuer, grantID string) []string {
	return []string{Key(issuer, grantID), "grant:" + grantID}
}

// CodeClaim is the access token claim carrying the code grant ID: the
// identifier the server derives, with CodeGrantID, for every grant that
// came from an authorization code, so a reused code can revoke
// everything issued from it (RFC 6749 §4.1.2) whether or not the
// application named the grant itself (Claim).
const CodeClaim = "code_grant_id"

// CodeKey is the revocation-store key recording a code grant ID issuer
// issued as revoked, kept apart from Key's and from access token keys by
// its prefix, and namespaced by issuer as Key is.
func CodeKey(issuer, codeGrantID string) string { return "code-grant:" + codeGrantID + "@" + issuer }

// CodeKeys are the keys IsRevoked checks for codeGrantID: CodeKey and
// its legacy form, as Keys.
func CodeKeys(issuer, codeGrantID string) []string {
	return []string{CodeKey(issuer, codeGrantID), "code-grant:" + codeGrantID}
}

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

// BackchannelGrantID names the grant a CIBA authentication request
// (authReqIDHash, the SHA-256 of its auth_req_id) was approved with,
// for the same use as CodeGrantID: carried in every access token from
// the grant, refreshed ones included, under CodeClaim and revoked with
// CodeKey, so revoking its refresh token (RFC 7009 §2.1) ends them all
// without the store remembering the name. Its own domain separator
// keeps it from ever equalling a CodeGrantID.
func BackchannelGrantID(authReqIDHash [32]byte) string {
	h := sha256.New()
	h.Write([]byte("fapigo backchannel grant v1\x00"))
	h.Write(authReqIDHash[:])
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
