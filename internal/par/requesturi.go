package par

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// RequestURIPrefix is the URN prefix this package uses when generating a
// request_uri value, following the example construction in RFC 9126
// §2.2. The wire format of a request_uri is at the discretion of the
// authorization server that issues it — a client verifying a response
// from a third-party server must not assume this prefix (see
// DecodeResult) — but a server built on this package uses it
// consistently so it can recognize its own values without a store
// lookup.
const RequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

// referenceSize is the byte length of the random reference component of
// a generated request_uri — 256 bits, well beyond RFC 9126's requirement
// that the value "MUST NOT be guessable".
const referenceSize = 32

// GenerateRequestURI produces a new, random request_uri value. If random
// is nil, crypto/rand.Reader is used.
func GenerateRequestURI(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buf := make([]byte, referenceSize)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", fmt.Errorf("par: generate request_uri: %w", err)
	}
	return RequestURIPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// SplitRequestURI reports whether requestURI has the form this package
// generates and, if so, returns its reference component — the part a
// server can use as a lookup key into its transaction store without
// storing the prefix redundantly. It returns ok == false for any value
// that doesn't have RequestURIPrefix, which a server can use as a fast
// rejection before attempting a store lookup at all.
func SplitRequestURI(requestURI string) (reference string, ok bool) {
	reference, ok = strings.CutPrefix(requestURI, RequestURIPrefix)
	if !ok || reference == "" {
		return "", false
	}
	return reference, true
}
