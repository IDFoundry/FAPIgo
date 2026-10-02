// Package client implements the FAPI 2.0 relying-party (RP) role: the
// public API a client application uses to drive an authorization-code
// flow against a FAPI-conformant authorization server.
//
// The package exposes workflow methods (BeginAuthorization,
// HandleAuthorizationResponse, ExchangeCode, CompleteAuthorization, for
// CIBA BeginBackchannelAuthentication and PollBackchannelAuthentication,
// and RefreshTokens to redeem the refresh token either flow issued)
// rather than low-level JWT, PAR or DPoP primitives — those live under internal/
// and are composed here behind a state machine that a caller cannot drive
// out of order. In particular, only this package may construct request
// objects and PAR submissions; verifying them is the server package's
// responsibility.
//
// OpenID Connect identity (an ID token, Subject, IDTokenClaims) is
// entirely optional and driven purely by what the authorization server
// actually granted, never assumed by this package: ExchangeCode,
// PollBackchannelAuthentication and RefreshTokens populate
// TokenSet.IDToken/Subject/IDTokenClaims only when the token response
// actually carried an id_token (RefreshTokens keeps the original's when
// a refresh returns none) (which, per the FAPI 2.0 authorization server this package
// targets, happens exactly when "openid" was included in the granted
// scope — see server's own package doc comment for that side of the
// contract) and leave TokenSet.HasIDToken false otherwise, which is a
// normal outcome, not an error. A caller that only needs access
// tokens — no identity layer at all — can omit "openid" from
// BeginAuthorizationRequest.Scope entirely and use this package as a
// plain OAuth 2.0 + FAPI 2.0 client; setting Config.OAuthOnly makes
// that a checked configuration rather than a convention, and lets such
// a client omit Dependencies.IssuerKeys.
//
// RequestClientCredentialsToken (RFC 6749 §4.4) is the third, unrelated
// flow this package drives, for a machine-to-machine client with no end
// user at all: no BeginAuthorization/PAR, no browser hop, no session,
// and no ID token or refresh token, ever — a Config with neither the
// browser flow's endpoints nor Endpoints.BackchannelAuthentication set
// is a legitimate client_credentials-only client, not an incomplete
// one. ClientCredentialsResource sends its token to a protected
// resource. Such a client authenticating with a TLS client certificate
// and holding mTLS-bound tokens signs nothing, and needs no
// Dependencies.Keys.
//
// FetchUserInfo, VerifyIssuerJWS and ProtectedResource or
// ClientCredentialsResource (via ResourceClient.Do) are the deliberate exceptions: a caller that
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
// Dependencies.Keys/Dependencies.Decryption with. ClientAttestationHeaders,
// likewise, hands an embedder the attestation-based client
// authentication headers for a request it sends itself — OpenID4VCI's
// pre-authorized_code token request, say — built by the same code as
// this package's own requests, rather than a second copy of the PoP
// format.
//
// client must not import server. Where both roles need the same wire
// format or cryptographic operation, that logic belongs in internal/ and
// is used asymmetrically (e.g. internal/jarm verifies here, but signs in
// server; internal/requestobject signs here, but verifies in server).
//
// It follows the same hardening rules as server and resource (see
// ARCHITECTURE.md, "Design rules"): AuthorizationSession is opaque with
// no public constructor, and a SessionHandle can only be recovered from
// its own String form (ParseSessionHandle) — the caller stores it with
// the user agent that began the flow, and HandleAuthorizationResponse
// rejects a callback that doesn't carry the matching one;
// HandleAuthorizationResponse returns a closed sum type
// rather than one struct with optional fields, so a caller can't assume
// every callback carries a code; every DPoP proof, request-object
// signature and client assertion is produced through Dependencies.Keys'
// operation-based Sign, keyed by purpose (ClientAuthentication,
// RequestObjectSigning, DPoPProofSigning) — this package never
// constructs, holds or is handed a crypto.PrivateKey, the same model
// server uses for its own signing keys; TokenSet fields that carry raw
// token values use fapi.Secret so they can't leak into a log line by
// accident; and a failure is a typed Error — with the server's own
// error response, when there was one, available through
// Error.ServerResponse — not a bare error the caller has to
// string-match.
package client
