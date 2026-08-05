// Package requestobject implements signed JAR (RFC 9101) request-object
// construction and verification for the parameters carried in an
// authorization/PAR request.
//
// create.go is used by client to build the request object it pushes to
// the AS; verify.go is used by server to authenticate and parse it,
// including replay detection via a ReplayChecker. Create and Verify
// intentionally take independent parameter types (CreateParams and
// VerifyPolicy), even though they share JOSE encoding and claim-parsing
// helpers — signing policy (what the client is allowed to assert) and
// verification policy (what the server is willing to accept) are
// independent decisions that must be configurable independently.
//
// Only the JWT-standard claims (iss, aud, exp, nbf, iat, jti) are parsed
// into typed fields. Every other top-level claim — the actual
// authorization request parameters, including any registered
// extension/RAR parameter — is left as raw JSON in Parameters for the
// extension package to interpret; this package has no opinion on which
// parameters are valid, only on the JWT envelope around them.
package requestobject
