package fapi

// ClientID identifies an OAuth client. It has one meaning regardless of
// role — the client-generated instruction and the server-validated
// record both refer to the same client by the same ID.
type ClientID string

// String returns the wire value of id.
func (id ClientID) String() string {
	return string(id)
}

// RegisteredRedirectURI is a redirect URI exactly as registered for a
// client. Equal performs OAuth registration-semantics comparison — exact
// string equality, no normalization, no wildcard matching — never
// generic URL equivalence. A candidate redirect_uri that differs only in
// trailing slash, percent-encoding case, or default-port presence is not
// a match.
type RegisteredRedirectURI string

// Equal reports whether candidate is exactly this registered redirect
// URI.
func (r RegisteredRedirectURI) Equal(candidate string) bool {
	return string(r) == candidate
}

// String returns the wire value of r.
func (r RegisteredRedirectURI) String() string {
	return string(r)
}
