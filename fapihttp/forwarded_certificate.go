package fapihttp

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// ClientCertHeader is RFC 9440 §2.2's Client-Cert header field, which a
// TLS-terminating reverse proxy sets to the client certificate of the
// mutually authenticated connection it accepted.
const ClientCertHeader = "Client-Cert"

// MaxForwardedCertificateBytes bounds the forwarded header's value that
// ForwardedClientCertificate decodes: far more than any client
// certificate needs (a typical one is 1–2 KiB of DER, a third more in
// base64), and far less than a request's whole header allowance.
const MaxForwardedCertificateBytes = 16 << 10

var (
	// ErrUntrustedForwarder indicates ForwardedClientCertificate's
	// trusted function reported that the request didn't come from the
	// proxy, so nothing in its headers says which certificate the client
	// presented.
	ErrUntrustedForwarder = errors.New("fapihttp: the request didn't come through the trusted proxy")

	// ErrMalformedForwardedCertificate indicates the forwarded
	// certificate header occurred more than once, was too large, wasn't
	// an RFC 9440 Byte Sequence, or didn't hold one DER certificate.
	ErrMalformedForwardedCertificate = errors.New("fapihttp: the forwarded client certificate is malformed")
)

// ForwardedClientCertificate returns the client certificate a
// TLS-terminating reverse proxy forwarded in r's header field (RFC 9440
// §2.2; "" means ClientCertHeader), or nil, nil when the header is absent
// (the client presented no certificate to the proxy). Use it, behind
// such a proxy, where PeerCertificateFromHTTP in server or resource
// would read the connection's own certificate: set the result as the
// PeerCertificate of a server request from one of its …FromHTTP
// constructors (TokenEndpointRequest.SetPeerCertificate for a token
// request), or of a resource.VerifyRequest.
//
// A certificate is public, so having one proves nothing: only the TLS
// handshake with the proxy proved the client holds its private key, and
// the header is only as trustworthy as whoever set it. So trusted must
// report whether r came from the proxy itself, typically by r.RemoteAddr
// (RemoteAddrIn) or the proxy's own mutually authenticated connection,
// never by anything else in the request. When it reports false, or is
// nil, ForwardedClientCertificate returns ErrUntrustedForwarder, whether
// or not the header is there. The proxy must, as RFC 9440 §2.4 requires,
// remove or overwrite any copy of the header the client sent, also on
// connections where no client certificate was negotiated; a proxy that
// passes a client's own copy through lets anyone claim any client's
// certificate, authenticating as that client and presenting its
// certificate-bound tokens.
//
// The value is RFC 8941 §3.3.5's Byte Sequence: the DER certificate in
// base64 between colons. A header occurring more than once (RFC 9440
// §2.2 makes it a singleton), a value longer than
// MaxForwardedCertificateBytes, anything but one Byte Sequence
// (parameters included: RFC 9440 defines none), or bytes that aren't
// exactly one X.509 certificate is ErrMalformedForwardedCertificate.
// Missing "=" padding is accepted, as RFC 8941 §4.2.7 asks. A forwarded
// PEM or URL-encoded certificate, which some proxies send in their own
// headers, isn't RFC 9440's encoding and is refused: configure the proxy
// to send Client-Cert instead.
//
// Nothing here checks the certificate's chain or validity: that is the
// proxy's (RFC 9440 §2.4) and then the server's own ClientCertificateTrust,
// exactly as for a certificate read from the connection.
func ForwardedClientCertificate(r *http.Request, header string, trusted func(*http.Request) bool) (*x509.Certificate, error) {
	if trusted == nil || !trusted(r) {
		return nil, ErrUntrustedForwarder
	}
	if header == "" {
		header = ClientCertHeader
	}
	values := r.Header.Values(header)
	switch {
	case len(values) == 0:
		return nil, nil
	case len(values) > 1:
		return nil, fmt.Errorf("%w: the %s header occurs %d times", ErrMalformedForwardedCertificate, header, len(values))
	}
	der, err := parseByteSequence(values[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrMalformedForwardedCertificate, header, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrMalformedForwardedCertificate, header, err)
	}
	return cert, nil
}

// parseByteSequence decodes a header field value that is one RFC 8941
// Byte Sequence (§3.3.5, parsed per §4.2 and §4.2.7): optional spaces,
// ":", base64, ":", optional spaces, and nothing else.
func parseByteSequence(value string) ([]byte, error) {
	if len(value) > MaxForwardedCertificateBytes {
		return nil, fmt.Errorf("the value is longer than %d bytes", MaxForwardedCertificateBytes)
	}
	// RFC 8941 §4.2: leading and trailing SP are discarded (net/http has
	// already removed any other optional whitespace).
	value = strings.Trim(value, " ")
	if len(value) < 2 || value[0] != ':' || value[len(value)-1] != ':' {
		return nil, errors.New("the value isn't a byte sequence (:base64:)")
	}
	body := value[1 : len(value)-1]
	// Up to two "=" of padding, only at the end; RFC 8941 §4.2.7 asks a
	// parser not to fail when it is missing.
	unpadded := strings.TrimRight(body, "=")
	if unpadded == "" {
		// Padding alone ("=", "==") carries no more bytes than "::".
		return nil, errors.New("the byte sequence is empty")
	}
	if len(body)-len(unpadded) > 2 || strings.ContainsRune(unpadded, '=') {
		return nil, errors.New("the byte sequence's padding is malformed")
	}
	// encoding/base64 skips line breaks, which RFC 8941's base64 doesn't
	// allow, so the alphabet is checked first. Non-zero pad bits are
	// accepted, as RFC 8941 §4.2.7 asks.
	if strings.IndexFunc(unpadded, notBase64) >= 0 {
		return nil, errors.New("the byte sequence isn't base64")
	}
	der, err := base64.RawStdEncoding.DecodeString(unpadded)
	if err != nil {
		return nil, errors.New("the byte sequence isn't base64")
	}
	return der, nil
}

// notBase64 reports whether c is outside base64's alphabet (RFC 4648
// §4), without its "=" padding.
func notBase64(c rune) bool {
	return (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '+' && c != '/'
}

// RemoteAddrIn returns a ForwardedClientCertificate trusted function
// reporting whether r.RemoteAddr, the address of the connection's other
// end as net/http saw it, is in one of prefixes: the proxy's own
// addresses. It reads nothing the client sends, such as X-Forwarded-For,
// so it holds only when the proxy connects to this server directly. An
// IPv4-mapped IPv6 address is compared as IPv4.
func RemoteAddrIn(prefixes ...netip.Prefix) func(*http.Request) bool {
	prefixes = append([]netip.Prefix(nil), prefixes...)
	return func(r *http.Request) bool {
		addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil {
			return false
		}
		addr := addrPort.Addr().Unmap()
		for _, p := range prefixes {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
}
