// Package clientassertion implements private_key_jwt-style client
// authentication: assertion construction and verification.
//
// create.go is used by client when authenticating to the PAR and token
// endpoints; verify.go is used by server when authenticating an inbound
// request. As with internal/requestobject, the two directions are kept as
// separate types so signing and verification policy can evolve
// independently.
package clientassertion
