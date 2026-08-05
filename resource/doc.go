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
// validation, ath, method/URI binding, replay detection and cnf.jkt
// binding.
//
// AuthorizationContext.Claims uses fapi.Secret for any raw token value it
// carries, and Verify returns a typed Error tagged with what's safe to
// expose in a response, matching the pattern used by client and server —
// see ARCHITECTURE.md, "Hardening rules for every role's public API".
package resource
