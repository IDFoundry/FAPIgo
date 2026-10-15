// Package resourceindicator checks RFC 8707 resource indicators: the
// "resource" parameter's syntax, shared by the server (which accepts it)
// and storage (which registers the resources a client may name).
package resourceindicator

import (
	"errors"
	"fmt"
	"net/url"
	"unicode/utf8"
)

// MaxLength bounds one resource indicator, so a value stored with a
// request or grant, and carried in every access token's "aud", stays
// small.
const MaxLength = 2048

// MaxPerRequest bounds how many resource indicators one request may
// name.
const MaxPerRequest = 16

// Check reports whether s is a resource indicator RFC 8707 §2 allows:
// an absolute URI (RFC 3986 §4.3) without a fragment component. A query
// component is allowed, as §2 recognises it may be needed.
func Check(s string) error {
	switch {
	case s == "":
		return errors.New("resource is empty")
	case len(s) > MaxLength:
		return fmt.Errorf("resource is longer than %d bytes", MaxLength)
	case !utf8.ValidString(s):
		return errors.New("resource is not valid UTF-8")
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c == 0x7f {
			return errors.New("resource contains whitespace or a control character")
		}
	}
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return fmt.Errorf("resource is not a URI: %w", err)
	case u.Scheme == "":
		return errors.New("resource is not an absolute URI")
	case u.Fragment != "" || u.RawFragment != "" || containsHash(s):
		return errors.New("resource must not include a fragment")
	}
	return nil
}

func containsHash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '#' {
			return true
		}
	}
	return false
}
