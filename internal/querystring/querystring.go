// Package querystring adds parameters to a URL's query component without
// re-encoding the parameters already in it.
//
// RFC 6749 §3.1 and §3.1.2 say an endpoint URI's or a redirection
// endpoint URI's query component "MUST be retained when adding additional
// query parameters". Decoding it into url.Values and encoding it again
// doesn't retain it: the parameters come back sorted, a value-less "flag"
// becomes "flag=", and a pair url.ParseQuery can't decode — one with a
// ";" or an invalid escape — is dropped altogether. Append keeps the
// original bytes and adds after them instead.
package querystring

import (
	"net/url"
	"strings"
)

// Append returns raw, a URL's RawQuery, with add — an already-encoded
// query, such as url.Values.Encode's — after it, separated by "&". raw
// is kept byte for byte.
func Append(raw, add string) string {
	switch {
	case add == "":
		return raw
	case raw == "":
		return add
	case strings.HasSuffix(raw, "&"):
		return raw + add
	}
	return raw + "&" + add
}

// Names returns the name of every parameter in raw, a URL's RawQuery,
// in order and decoded where it can be (the raw name where it can't).
// Pairs are split at "&" and at ";", which some servers still treat as
// a separator, so a name hidden behind either is found.
func Names(raw string) []string {
	var names []string
	for _, pair := range strings.FieldsFunc(raw, func(r rune) bool { return r == '&' || r == ';' }) {
		name, _, _ := strings.Cut(pair, "=")
		if decoded, err := url.QueryUnescape(name); err == nil {
			name = decoded
		}
		names = append(names, name)
	}
	return names
}

// FirstReserved returns the first name of raw's parameters (Names) that
// is one of reserved, and whether there is one.
func FirstReserved(raw string, reserved ...string) (string, bool) {
	for _, name := range Names(raw) {
		for _, r := range reserved {
			if name == r {
				return name, true
			}
		}
	}
	return "", false
}
