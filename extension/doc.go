// Package extension lets a single definition of a custom authorization
// parameter — including a Rich Authorization Requests (RFC 9396) detail
// type — be shared between client and server, so its wire name,
// cardinality, encoding, size limit, sensitivity and validation rules are
// implemented exactly once instead of twice with subtly different rules.
//
// A Definition is created once (typically as a package-level var) and
// then used by client code to set a value on an outgoing request
// (req.Extensions.Set(Definition, value)) and by server code, after
// registering the same Definition via a server option, to read the
// validated value back out through a typed accessor
// (extension.Get(validated.Extensions, Definition)) — never a generic
// map[string]any, which would allow name collisions and invalid type
// assertions. A RAR detail type additionally bounds the number of detail
// objects, bytes per object, total bytes, JSON depth, and how
// duplicate/unknown JSON members are handled.
//
// Any parameter without a registered Definition is rejected by default;
// there is no production option to silently preserve unknown fields.
// extension has no dependency on client or server and must stay that way.
package extension
