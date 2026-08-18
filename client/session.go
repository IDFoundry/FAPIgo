package client

import (
	"crypto/rand"
	"encoding/base64"
	"io"

	fapi "github.com/idfoundry/fapigo"
)

// randomTokenSize is the byte length of a generated state, nonce or
// SessionHandle value — 256 bits.
const randomTokenSize = 32

func generateRandomToken(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buf := make([]byte, randomTokenSize)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// SessionHandle identifies one in-progress authorization attempt. It has
// no public constructor — only BeginAuthorization can produce one. This
// package never requires it back as input (HandleAuthorizationResponse
// looks a session up by the "state" value the callback itself carries),
// but the caller may use it for its own correlation purposes — e.g.
// binding the pre-authorization request to the eventual callback with an
// HTTP-only cookie, as defense in depth alongside "state".
type SessionHandle struct {
	value string
}

// String returns the handle's opaque wire value.
func (h SessionHandle) String() string { return h.value }

// AuthorizationSession is returned by BeginAuthorization: the browser URL
// to redirect the user agent to, and an opaque handle for the caller's
// own correlation purposes.
type AuthorizationSession struct {
	url    fapi.URL
	handle SessionHandle
}

// URL is the authorization URL to redirect the user agent to.
func (s AuthorizationSession) URL() fapi.URL { return s.url }

// Handle is this session's opaque correlation handle.
func (s AuthorizationSession) Handle() SessionHandle { return s.handle }
