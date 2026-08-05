// Package par implements the shared wire format for Pushed Authorization
// Requests (RFC 9126): request encoding, the request_uri response shape,
// and the parameter rules common to submitting and accepting a PAR
// request.
//
// client uses this to submit a PAR request and interpret the
// request_uri/expires_in response; server uses it to parse and validate
// an inbound PAR submission. Client-authentication verification and
// request-object verification are out of scope here — see
// internal/clientassertion and internal/requestobject.
package par
