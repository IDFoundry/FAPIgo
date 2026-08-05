// Package token implements shared JWT access token (RFC 9068) and ID
// token (OIDC Core) issuance and validation logic that sits below the
// public TokenSet/TokenResult types.
//
// issue.go is used by server to mint tokens, including DPoP sender
// constraint binding via a cnf.jkt claim; validate.go is used by client
// (validating an ID token it received from the token endpoint) and by
// resource (validating a presented access token, including its
// cnf.jkt). Each token kind's Parse and Validate stay separate types
// from its Issue, even though they interpret the same claim set, because
// a server issuing a token and a verifier checking one make different
// trust assumptions about where the token came from.
//
// Refresh tokens are not covered here: this module treats them as
// opaque, storage-backed credentials issued and redeemed by
// storage.GrantStore, not as JWTs with claims to parse.
//
// As with internal/requestobject and internal/jarm, only the claims each
// token kind's governing spec defines are parsed into typed fields;
// anything else — most notably a granted authorization_details
// (RFC 9396) reflected into an access token — is left as raw JSON in
// Parameters.
package token
