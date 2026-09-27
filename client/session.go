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

// SessionHandle binds one in-progress authorization attempt to the user
// agent that started it. BeginAuthorization returns it; the caller keeps
// it with that browser — an HttpOnly, Secure, SameSite=Lax cookie, set
// when redirecting to AuthorizationSession.URL — and passes it back as
// AuthorizationCallback.Session when the callback arrives, recovered
// with ParseSessionHandle.
//
// That binding is required, not defense in depth: the callback's own
// "state" only identifies a session, and anyone can deliver a callback
// URL to a victim's browser. Without the check, an attacker could start
// a flow as themselves and have a victim's browser complete it — login
// CSRF, landing the victim in the attacker's account (RFC 9700 §4.7).
// HandleAuthorizationResponse and CompleteAuthorization reject a
// callback whose Session doesn't match its "state".
type SessionHandle struct {
	value string
}

// String returns the handle's opaque wire value, for storing it with the
// user agent (see SessionHandle); ParseSessionHandle reverses it.
func (h SessionHandle) String() string { return h.value }

// ParseSessionHandle recovers a SessionHandle from its String form — the
// value the caller stored with the user agent — for
// AuthorizationCallback.Session. It rejects anything BeginAuthorization
// couldn't have produced.
func ParseSessionHandle(s string) (SessionHandle, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != randomTokenSize {
		return SessionHandle{}, newError(ErrorInvalidRequest, "session handle is malformed", nil)
	}
	return SessionHandle{value: s}, nil
}

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
