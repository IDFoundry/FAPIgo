// Package fapi holds value types shared across the client, server and
// resource packages because their semantics are identical regardless of
// role: identifiers, algorithm enums and other data with a single, stable
// meaning on the wire. This includes Secret (a self-redacting wrapper for
// any token, code or credential value — String, GoString and MarshalText
// all redact; Reveal is the only way out) and URL (constructed only via
// ParseIssuerURL/ParseEndpointURL, never a bare string, enforcing HTTPS,
// no fragment, no embedded credentials and a normalized host).
//
// It must never hold workflow types, configuration, or anything whose
// meaning differs between an authorization request a client is about to
// send and one a server has already validated. Those stay in their
// respective role packages — see ARCHITECTURE.md, "Shared public value
// types only where semantics match".
package fapi
