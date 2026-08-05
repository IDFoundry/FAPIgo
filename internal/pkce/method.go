package pkce

// Method is a closed set of PKCE code_challenge_method values (RFC 7636
// §4.2). It exists so a caller-supplied method string is never used as
// policy directly — S256 is the only method Verify or Challenge will
// act on.
type Method uint8

const (
	_ Method = iota

	// S256 derives code_challenge as
	// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))).
	S256
)

// String returns the wire value of m, or "" if m is not S256.
func (m Method) String() string {
	if m == S256 {
		return "S256"
	}
	return ""
}

// ParseMethod maps a code_challenge_method wire value to a Method. It
// distinguishes "plain" — syntactically valid per RFC 7636 but refused
// here — from every other unsupported value, and it does not default an
// empty string to "plain" the way RFC 7636 allows a bare authorization
// server to: an absent method must be treated as an error by the
// caller, never silently downgraded.
func ParseMethod(s string) (Method, error) {
	switch s {
	case "S256":
		return S256, nil
	case "plain":
		return 0, ErrPlainMethodNotPermitted
	default:
		return 0, ErrUnsupportedMethod
	}
}
