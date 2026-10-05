// Package strictb64 decodes base64 canonically, for JOSE values: a
// value decodes only if it is exactly the encoding of its bytes.
// encoding/base64's decoders accept non-zero unused trailing bits
// unless Strict is set, and skip carriage returns and line feeds even
// then, so several distinct strings decode to the same bytes. RFC 7515
// §2 defines base64url for JOSE with no padding and no line breaks or
// other whitespace; x5c (RFC 7515 §4.1.6) is padded standard base64
// with the same canonical form.
package strictb64

import (
	"encoding/base64"
	"errors"
	"strings"
)

var (
	rawURL = base64.RawURLEncoding.Strict()
	std    = base64.StdEncoding.Strict()
)

// ErrLineBreak reports a carriage return or line feed in a base64
// value, which encoding/base64 would otherwise skip.
var ErrLineBreak = errors.New("strictb64: base64 value contains a line break")

// URL decodes s as unpadded base64url (RFC 4648 §5), refusing padding,
// the standard alphabet, line breaks and non-zero unused trailing bits.
func URL(s string) ([]byte, error) { return decode(rawURL, s) }

// Std decodes s as padded standard base64 (RFC 4648 §4), refusing the
// URL alphabet, missing padding, line breaks and non-zero unused
// trailing bits.
func Std(s string) ([]byte, error) { return decode(std, s) }

func decode(enc *base64.Encoding, s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, ErrLineBreak
	}
	return enc.DecodeString(s)
}
