// Package oidc implements protocol-level OpenID Connect primitives shared
// by client and server: ID token claim sets, discovery document shape,
// and OIDC-specific parameter semantics layered on top of internal/oauth.
//
// This is unexported protocol core, not a public API — see
// ARCHITECTURE.md, "Share protocol implementation, not role-level APIs".
package oidc
