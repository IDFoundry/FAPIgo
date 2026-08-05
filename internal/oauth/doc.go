// Package oauth implements protocol-level OAuth 2.0 primitives shared by
// client and server: message and error formats, grant and response types,
// and endpoint semantics that are not FAPI- or JOSE-specific.
//
// This is unexported protocol core, not a public API — see
// ARCHITECTURE.md, "Share protocol implementation, not role-level APIs".
// Higher-level FAPI behaviour (PAR, DPoP, request objects, JARM) has its
// own internal package and builds on top of this one.
package oauth
