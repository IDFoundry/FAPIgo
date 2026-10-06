// Package resource implements the FAPI 2.0 resource-server (RS) role:
// verifying incoming access tokens and their sender-constraint proofs on
// behalf of a protected API.
//
// It is deliberately a third role rather than a mode of client or server,
// because token verification is inseparable from HTTP request context
// (method, URL, DPoP proof) — see AuthorizationContext and Verify. The
// package must not expose a bare VerifyJWT-style primitive as its main
// entry point, and symmetrically must not expose a bare VerifyDPoP
// either — a DPoP proof can't be judged valid without the request's
// method, target URI, access-token hash, expected nonce and JTI replay
// state alongside it. Verify is the primary API and takes the full
// request context needed for issuer/audience/expiry checks, DPoP proof
// validation, ath, method/URI binding, replay detection, and cnf
// binding (a DPoP key's jkt, or an mTLS certificate's x5t#S256).
//
// AuthorizationContext carries no raw token value — only what the
// verified token says, and its revocation key — so it can't leak a
// usable token into a log line, and Verify returns a typed Error tagged
// with what's safe to expose in a response, matching the pattern used by
// client and server — see ARCHITECTURE.md, "Design rules".
//
// Config.Assurance is required, as server.Config.Assurance is:
// AssuranceDevelopment accepts in-memory stores and key sources, and
// AssuranceProduction requires every store and key source the verifier
// relies on to declare its capabilities (see AssuranceProduction).
//
// A verifier for endpoints hosted in the authorization server's own
// process can be built from that server's configuration with
// serverresource.NewVerifier instead, so its access-token format and
// revocation store always match the server's.
package resource
