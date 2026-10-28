package canonical

// Host names and URI schemes are case-insensitive in ASCII only (RFC
// 3986 §3.1, §3.2.2; RFC 4343). strings.ToLower and strings.EqualFold
// apply Unicode case mapping instead, which folds some non-ASCII
// letters onto ASCII ones: "İ" (U+0130) lowercases to "i", and the
// Kelvin sign "K" (U+212A) and long s "ſ" (U+017F) fold to "k" and
// "s". A non-ASCII host is dialed through IDNA as a different DNS name
// ("İbank.example" is "xn--ibank-7fd.example"), so a Unicode fold
// would make that name compare equal to, or be rewritten as, an
// unrelated ASCII host. These functions fold ASCII letters alone, and
// leave every other byte as it is.

// IsASCII reports whether s is entirely ASCII.
func IsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// LowerASCII returns s with its ASCII uppercase letters lowercased and
// every other byte unchanged.
func LowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if 'A' <= s[i] && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				b[j] = lowerASCIIByte(b[j])
			}
			return string(b)
		}
	}
	return s
}

// EqualFoldASCII reports whether a and b are equal once their ASCII
// letters are lowercased; any other byte must match exactly.
func EqualFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCIIByte(a[i]) != lowerASCIIByte(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCIIByte(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
