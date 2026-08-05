// Package jarm implements JWT Secured Authorization Response Mode
// signing and verification: encoding the authorization response as a
// signed JWT and validating one on receipt.
//
// create.go is used by server, which produces the response JWT;
// verify.go is used by client, which must independently check issuer,
// audience, expiry and signature before trusting anything in the
// response. Create and Verify treat a success response and an error
// response identically — both are just a bag of top-level claims signed
// and checked the same way — which is what prevents a spoofed error
// response from getting weaker integrity protection than a success
// response.
//
// As with internal/requestobject, only the JWT-standard claims (iss,
// aud, exp, nbf, iat) are parsed into typed fields; every actual
// authorization response parameter (code, state, error,
// error_description, error_uri, ...) is left as raw JSON in Parameters.
// This package has no notion of replay detection: an authorization
// response is correlated against the attempt it belongs to — and
// retired — by the client's storage.SessionStore, not by anything here.
package jarm
