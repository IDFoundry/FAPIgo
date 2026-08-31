package dpop

// ResolveHeaderValues reduces values — every "DPoP" HTTP header value a
// request carried, in receipt order — to the single proof value this
// package's own verification expects, enforcing RFC 9449 §7.1 itself
// ("the client... MUST NOT send this header field multiple times")
// rather than leaving that check to whichever HTTP adapter a caller
// happens to use. net/http's own Header.Get silently returns only the
// first of several values instead of rejecting the request, so a
// caller that reads a header that way and hands the result to server
// or resource can silently violate the spec; passing every raw value
// here (e.g. via net/http's own Header.Values) closes that structurally
// instead of relying on every adapter to remember its own check.
//
// ok is false when values holds more than one entry, regardless of
// whether any individual value would otherwise have verified. proof is
// "" and ok is true when values is empty — no proof was presented at
// all, which some callers treat as valid on its own (DPoP is optional
// at, for example, the PAR endpoint and an mTLS-sender-constrained
// client's token request).
func ResolveHeaderValues(values []string) (proof string, ok bool) {
	switch len(values) {
	case 0:
		return "", true
	case 1:
		return values[0], true
	default:
		return "", false
	}
}
