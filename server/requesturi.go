package server

// RequestURI is an opaque request_uri value returned by
// PushAuthorizationRequest. It has no public constructor — only this
// package can produce one — so a caller can pass it around and log its
// string form without being able to forge one.
type RequestURI struct {
	value string
}

// String returns the request_uri's wire value.
func (r RequestURI) String() string { return r.value }
