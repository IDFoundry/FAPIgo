package strictjson

import (
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// DecodesLosslessly reports whether raw, JSON text, decodes without
// encoding/json altering any string in it. encoding/json doesn't refuse
// invalid UTF-8 or a \u escape of an unpaired UTF-16 surrogate: it
// replaces each with U+FFFD, so two different byte strings — one a
// signer meant, one it didn't — read back as the same value. RFC 8259
// §8.1 requires JSON text to be UTF-8, RFC 7519 §7.2 has a JWT's
// claims set be valid UTF-8, and RFC 8725 §3.7 asks a JWT library to
// refuse one that isn't; a lone surrogate escape names no Unicode
// character at all (RFC 8259 §8.2). A backslash only appears inside a
// JSON string, so raw is scanned for escapes without parsing it; raw
// that isn't JSON at all is left for the decoder to refuse.
func DecodesLosslessly(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++ // the escaped character
		if i >= len(raw) || raw[i] != 'u' {
			continue
		}
		n, ok := unicodeEscapeLength(raw, i-1)
		if !ok {
			return false
		}
		i += n - 2 // past the escape (or surrogate pair); the loop adds one
	}
	return true
}

// unicodeEscapeLength returns the length of the \u escape starting at
// raw[i] (its backslash), or of the surrogate pair it starts, and
// whether it decodes as written: a high surrogate must be followed
// directly by an escaped low one, and a low one can't stand alone.
func unicodeEscapeLength(raw []byte, i int) (int, bool) {
	r, ok := hexRune(raw, i+2)
	switch {
	case !ok:
		return 0, false
	case !utf16.IsSurrogate(r):
		return 6, true
	case r >= 0xdc00:
		return 0, false // a low surrogate on its own
	}
	low, ok := hexRune(raw, i+8)
	if !ok || raw[i+6] != '\\' || raw[i+7] != 'u' || low < 0xdc00 || low > 0xdfff {
		return 0, false
	}
	return 12, true
}

// hexRune reads the four hex digits of a \u escape starting at raw[i].
func hexRune(raw []byte, i int) (rune, bool) {
	if i < 0 || i+4 > len(raw) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(raw[i:i+4]), 16, 16)
	if err != nil {
		return 0, false
	}
	return rune(n), true
}
