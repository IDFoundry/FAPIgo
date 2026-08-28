// Package mtls implements the one primitive RFC 8705 mTLS-bound access
// tokens need beyond what the TLS layer itself already provides:
// computing a certificate's "x5t#S256" confirmation value (§3.1). There
// is no proof format to construct or verify here, unlike internal/dpop
// — mTLS binding is derived entirely from the already-authenticated TLS
// connection (net/http's own client-certificate handshake), not from an
// application-layer signed artifact a caller presents on each request.
package mtls
