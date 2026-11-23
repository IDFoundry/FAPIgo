// Package redact holds what the client, server and resource packages'
// renderings share: the placeholder a hidden value prints as, the
// summary a URL or query prints as, and the Format a type prints its
// shadow through.
//
// A type holding bearer material prints a shadow of itself: a struct
// declared next to it with the same field names in the same order, in
// which every hidden value is a Hidden and every other field what fmt
// would print of the real one. No raw value is in a shadow, so no verb
// or flag can reach one, and fmt applies the verb and flags to the
// shadow as it would have to the real type.
package redact

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	fapi "github.com/idfoundry/fapigo"
)

// Redacted is what a hidden value prints as.
const Redacted = "[REDACTED]"

// Hidden is a hidden value's placeholder in a shadow: Redacted, or ""
// where there was no value. It is a string, so even fmt's reflection
// fallback, or a verb it rejects, prints only the placeholder.
type Hidden string

// Mask is s's placeholder: Redacted, or "" for the zero Secret.
func Mask(s fapi.Secret) Hidden {
	if s == (fapi.Secret{}) {
		return ""
	}
	return Redacted
}

// MaskString is v's placeholder: Redacted, or "" for "".
func MaskString(v string) Hidden {
	if v == "" {
		return ""
	}
	return Redacted
}

// MaskStrings is a placeholder for each of vs.
func MaskStrings(vs []string) []Hidden {
	if vs == nil {
		return nil
	}
	out := make([]Hidden, len(vs))
	for i, v := range vs {
		out[i] = MaskString(v)
	}
	return out
}

// Format prints shadow under verb and f's flags, width and precision,
// as fmt would print the type it shadows. Under %#v, which names types,
// each name in renames, given as pairs of a shadow type's name and the
// real type's (such as "client.resourceClientShadow",
// "client.ResourceClient"), is replaced by the second.
func Format(f fmt.State, verb rune, shadow any, renames ...string) {
	out := fmt.Sprintf(fmt.FormatString(f, verb), shadow)
	if verb == 'v' && f.Flag('#') && len(renames) > 1 {
		out = strings.NewReplacer(renames...).Replace(out)
	}
	_, _ = io.WriteString(f, out)
}

// URL summarizes u for a log: its scheme, host and escaped path, then
// each query parameter's name, as it is written in u, with Redacted for
// its value, in u's order. No value prints, not even iss or error: a
// redirect's query carries a code or a signed response, and names alone
// tell a success from an error. A name of anything but URL-safe
// characters prints quoted, so it can't forge a log line.
func URL(u url.URL) string {
	base := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path, RawPath: u.RawPath, OmitHost: u.OmitHost}
	summary := base.String()
	if names := Query(u.RawQuery); names != "" {
		summary += "?" + names
	}
	return summary
}

// Query summarizes raw, a URL query or form body, as URL does a URL's
// query: each parameter's name as written, with Redacted for its value,
// joined by "&".
func Query(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	for i, part := range parts {
		name, _, hasValue := strings.Cut(part, "=")
		parts[i] = Name(name)
		if hasValue {
			parts[i] += "=" + Redacted
		}
	}
	return strings.Join(parts, "&")
}

// Name is name, a parameter name, as written, or %q-quoted unless it is
// made of the characters a URL query carries unescaped, so a name the
// client chose can't forge a log line.
func Name(name string) string {
	for i := range len(name) {
		if !isPlainNameByte(name[i]) {
			return fmt.Sprintf("%q", name)
		}
	}
	return name
}

// Text is v, a value a rendering may show, as written, or %q-quoted if
// it holds a byte outside printable ASCII, such as a newline, which
// could forge a log line.
func Text(v string) string {
	for i := range len(v) {
		if v[i] < ' ' || v[i] > '~' {
			return fmt.Sprintf("%q", v)
		}
	}
	return v
}

func isPlainNameByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("._~%+-", c) >= 0
}
