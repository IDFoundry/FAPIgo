// Package dpop implements DPoP (RFC 9449) proof creation and verification:
// proof JWT construction, the "ath" access-token hash, JWK thumbprint
// computation, and the checks needed to detect proof replay.
//
// create.go is used by client (to prove possession of its DPoP key on
// requests to the AS and to resource servers); verify.go is used by both
// server and resource, since both roles must independently validate a
// proof presented to them rather than trusting a previous validation.
package dpop
