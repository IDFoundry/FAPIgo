// Package client implements the FAPI 2.0 relying-party (RP) role: the
// public API a client application uses to drive an authorization-code
// flow against a FAPI-conformant authorization server.
//
// The package exposes workflow methods (BeginAuthorization,
// HandleAuthorizationResponse, ExchangeCode, CompleteAuthorization) rather
// than low-level JWT, PAR or DPoP primitives — those live under internal/
// and are composed here behind a state machine that a caller cannot drive
// out of order. In particular, only this package may construct request
// objects and PAR submissions; verifying them is the server package's
// responsibility.
//
// FetchUserInfo, VerifyIssuerJWS and ProtectedResource (via
// ResourceClient.Do) are the deliberate exceptions: a caller that
// reaches a protected resource beyond token issuance (the UserInfo
// endpoint, most commonly, which FetchUserInfo covers directly) needs
// both to sign a DPoP proof bound to that request and to check
// something else the authorization server signed, and the alternative —
// forcing that caller to hand-roll its own DPoP proof construction and
// to re-fetch and re-parse the issuer's JWKS on its own — is exactly
// the unhardened, uncoordinated-cache duplication this package exists
// to avoid. PublicJWKS is the same idea applied to publishing this
// client's own keys — the mirror image of server.PublicJWKS — so an
// embedder registering with an authorization server (out of band; this
// package has no dynamic client registration flow) doesn't have to
// hand-roll RFC 7517 JWK encoding for whatever it configured
// Dependencies.Keys/Dependencies.Decryption with.
//
// client must not import server. Where both roles need the same wire
// format or cryptographic operation, that logic belongs in internal/ and
// is used asymmetrically (e.g. internal/jarm verifies here, but signs in
// server; internal/requestobject signs here, but verifies in server).
//
// It follows the same hardening rules as server and resource (see
// ARCHITECTURE.md, "Hardening rules for every role's public API"):
// AuthorizationSession and SessionHandle are opaque with no public
// constructor; HandleAuthorizationResponse returns a closed sum type
// rather than one struct with optional fields, so a caller can't assume
// every callback carries a code; every DPoP proof, request-object
// signature and client assertion is produced through Dependencies.Keys'
// operation-based Sign, keyed by purpose (ClientAuthentication,
// RequestObjectSigning, DPoPProofSigning) — this package never
// constructs, holds or is handed a crypto.PrivateKey, the same model
// server uses for its own signing keys; TokenSet fields that carry raw
// token values use fapi.Secret so they can't leak into a log line by
// accident; and a validation failure is a typed Error tagged with where
// it's safe to expose the description, not a bare error the caller has
// to string-match.
package client
