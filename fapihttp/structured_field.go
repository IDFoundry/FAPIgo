package fapihttp

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// This file reads just enough of RFC 9651 (Structured Field Values for
// HTTP, which obsoletes RFC 8941) to skip an Item's Parameters: RFC 9440
// §2.2 makes Client-Cert a Byte Sequence, and RFC 9651 §2.3 has every
// Item allow Parameters "as an extensibility mechanism", discouraging a
// field from treating an unrecognized one as an error. Each function
// checks one RFC 9651 §4.2 production at the start of s and returns
// what follows it, so a value that isn't a valid Item is still refused.

var errMalformedParameters = errors.New("the byte sequence's parameters are malformed")

// skipParameters checks that s is zero or more Parameters (RFC 9651
// §4.2.3.2: ";", optional spaces, a key, optionally "=" and a bare item)
// and nothing else. Their keys and values are ignored.
func skipParameters(s string) error {
	for s != "" {
		if s[0] != ';' {
			return errors.New("the value isn't a byte sequence (:base64:)")
		}
		rest, ok := skipKey(strings.TrimLeft(s[1:], " "))
		if !ok {
			return errMalformedParameters
		}
		if rest != "" && rest[0] == '=' {
			if rest, ok = skipBareItem(rest[1:]); !ok {
				return errMalformedParameters
			}
		}
		s = rest
	}
	return nil
}

// skipKey skips a key (RFC 9651 §4.2.3.3): a lowercase letter or "*",
// then lowercase letters, digits, "_", "-", "." and "*".
func skipKey(s string) (string, bool) {
	if s == "" || !isLCAlpha(s[0]) && s[0] != '*' {
		return s, false
	}
	i := 1
	for i < len(s) && (isLCAlpha(s[i]) || isDigit(s[i]) || strings.IndexByte("_-.*", s[i]) >= 0) {
		i++
	}
	return s[i:], true
}

// skipBareItem skips one bare item (RFC 9651 §4.2.3.1), whichever of
// its types s starts with.
func skipBareItem(s string) (string, bool) {
	if s == "" {
		return s, false
	}
	switch c := s[0]; {
	case c == '-' || isDigit(c):
		rest, _, ok := skipNumber(s)
		return rest, ok
	case c == '"':
		return skipString(s[1:])
	case c == '*' || isAlpha(c):
		return skipToken(s[1:]), true
	case c == ':':
		return skipByteSequence(s[1:])
	case c == '?':
		return skipBoolean(s[1:])
	case c == '@':
		rest, decimal, ok := skipNumber(s[1:])
		return rest, ok && !decimal
	case c == '%':
		return skipDisplayString(s[1:])
	}
	return s, false
}

// skipNumber skips an Integer or Decimal (RFC 9651 §4.2.4): an optional
// "-", then at most 15 digits, or at most 12 digits, "." and one to
// three digits. decimal reports which.
func skipNumber(s string) (rest string, decimal bool, ok bool) {
	i := 0
	if i < len(s) && s[i] == '-' {
		i++
	}
	start := i
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	whole := i - start
	if whole == 0 {
		return s, false, false
	}
	if i == len(s) || s[i] != '.' {
		return s[i:], false, whole <= 15
	}
	i++
	fracStart := i
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	fraction := i - fracStart
	return s[i:], true, whole <= 12 && fraction >= 1 && fraction <= 3
}

// skipString skips the rest of a String (RFC 9651 §4.2.5) after its
// opening quote: visible ASCII and spaces, "\"" and "\\" escapes, then
// the closing quote.
func skipString(s string) (string, bool) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			return s[i+1:], true
		case c == '\\':
			i++
			if i == len(s) || s[i] != '"' && s[i] != '\\' {
				return s, false
			}
		case c < 0x20 || c > 0x7e:
			return s, false
		}
	}
	return s, false
}

// skipToken skips the rest of a Token (RFC 9651 §4.2.6) after its first
// character: tchar (RFC 9110 §5.6.2), ":" and "/".
func skipToken(s string) string {
	i := 0
	for i < len(s) && (isAlpha(s[i]) || isDigit(s[i]) || strings.IndexByte("!#$%&'*+-.^_`|~:/", s[i]) >= 0) {
		i++
	}
	return s[i:]
}

// skipByteSequence skips the rest of a Byte Sequence (RFC 9651 §4.2.7)
// after its opening colon: base64 characters, then the closing colon.
func skipByteSequence(s string) (string, bool) {
	end := strings.IndexByte(s, ':')
	if end < 0 || strings.IndexFunc(s[:end], func(c rune) bool { return notBase64(c) && c != '=' }) >= 0 {
		return s, false
	}
	return s[end+1:], true
}

// skipBoolean skips the rest of a Boolean (RFC 9651 §4.2.8) after its
// "?": "0" or "1".
func skipBoolean(s string) (string, bool) {
	if s == "" || s[0] != '0' && s[0] != '1' {
		return s, false
	}
	return s[1:], true
}

// skipDisplayString skips the rest of a Display String (RFC 9651
// §4.2.10) after its "%": a quote, visible ASCII and spaces with "%"
// escaping two lowercase hex digits, a closing quote, and the decoded
// bytes valid UTF-8.
func skipDisplayString(s string) (string, bool) {
	if s == "" || s[0] != '"' {
		return s, false
	}
	var decoded []byte
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			return s[i+1:], utf8.Valid(decoded)
		case c == '%':
			if i+2 >= len(s) || !isLCHex(s[i+1]) || !isLCHex(s[i+2]) {
				return s, false
			}
			decoded = append(decoded, lcHexValue(s[i+1])<<4|lcHexValue(s[i+2]))
			i += 2
		case c < 0x20 || c > 0x7e:
			return s, false
		default:
			decoded = append(decoded, c)
		}
	}
	return s, false
}

func isDigit(c byte) bool   { return '0' <= c && c <= '9' }
func isLCAlpha(c byte) bool { return 'a' <= c && c <= 'z' }
func isAlpha(c byte) bool   { return isLCAlpha(c) || 'A' <= c && c <= 'Z' }
func isLCHex(c byte) bool   { return isDigit(c) || 'a' <= c && c <= 'f' }

func lcHexValue(c byte) byte {
	if isDigit(c) {
		return c - '0'
	}
	return c - 'a' + 10
}
