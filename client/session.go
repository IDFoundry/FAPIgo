package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"time"

	fapi "github.com/idfoundry/fapigo"
)

// randomTokenSize is the byte length of a generated nonce or
// SessionHandle value — 256 bits. The "state" an authorization request
// carries is the SHA-256 of a SessionHandle value (stateForHandle), the
// same length.
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

// statePrefix separates the digest an authorization request's "state"
// is from every other digest this module computes.
const statePrefix = "fapigo client authorization state\x00"

// stateForHandle is the "state" the authorization request of the session
// whose SessionHandle value is handle carries, and the key that session
// is stored under: the SHA-256 of the handle after statePrefix,
// base64url-encoded. The authorization server echoes "state" in its
// response, which parties other than the user agent can read before it
// does: an app claiming the same redirect URI scheme, a script on the
// redirect page, a log of redirect URLs. A one-way digest tells them
// nothing of the handle, so the response alone can't complete the flow
// in another user agent (RFC 9700 §2.1.1, §4.7).
func stateForHandle(handle string) string {
	sum := sha256.Sum256([]byte(statePrefix + handle))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// SessionHandle binds one in-progress authorization attempt to the user
// agent that started it. BeginAuthorization returns it; the caller keeps
// it with that browser, set when redirecting to AuthorizationSession.URL,
// and passes it back as AuthorizationCallback.Session when the callback
// arrives. Keep it where only this application can have put it:
// package client/sessioncookie seals it into an encrypted HttpOnly,
// Secure, SameSite=Lax __Host- cookie, which can carry the application's
// own value for the authorization (an order ID, say) alongside. A cookie
// MAC'd with a key of the application's own, or a server-side record
// that the browser's own session names, binds it as well. A plain cookie
// holding String() doesn't: anyone who learns the handle can set it.
//
// That binding is required, not defense in depth: the callback's own
// "state" only identifies a session, and anyone can deliver a callback
// URL to a victim's browser. Without the check, an attacker could start
// a flow as themselves and have a victim's browser complete it — login
// CSRF, landing the victim in the attacker's account (RFC 9700 §4.7).
// HandleAuthorizationResponse and CompleteAuthorization reject a
// callback whose "state" isn't the one BeginAuthorization derived from
// its Session, before consuming anything. The handle itself is never
// sent: "state" is a one-way digest of it, so the authorization
// response, which anyone between the authorization server and the user
// agent may read, doesn't reveal it.
//
// A native app whose session store is its own on-device storage has that
// binding already: see CallbackBindingDeviceLocalStore.
//
// String is the handle's wire value, so fmt.Sprint, %s and %v, and the
// templates print it, for building a cookie or a form field: never log
// a SessionHandle on its own with fmt. log/slog logs one given as an
// attribute as [REDACTED] (LogValue), and every rendering of a type of
// this package that holds one shows [REDACTED]; but log/slog's text
// handler prints a struct with %+v, so a SessionHandle in an exported
// field of a struct of yours logs its wire value. fmt's reflection
// fallback (a SessionHandle in an unexported field, or under a verb
// other than v, s, q, x and X) prints an address.
type SessionHandle struct {
	value fapi.Secret
}

// String returns the handle's opaque wire value, for keeping it with the
// user agent (see SessionHandle); ParseSessionHandle reverses it.
func (h SessionHandle) String() string { return h.value.Reveal() }

// ParseSessionHandle recovers a SessionHandle from its String form — the
// value the caller kept with the user agent — for
// AuthorizationCallback.Session. It rejects anything BeginAuthorization
// couldn't have produced. It checks only the form: whether the value is
// the handle of that user agent's session is up to where the caller kept
// it (see SessionHandle). A callback's "state" has the same form, but as
// a handle it matches no session.
func ParseSessionHandle(s string) (SessionHandle, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != randomTokenSize {
		return SessionHandle{}, newError(ErrorInvalidRequest, "session handle is malformed", nil)
	}
	return SessionHandle{value: fapi.NewSecret(s)}, nil
}

// AuthorizationSession is returned by BeginAuthorization: the browser URL
// to redirect the user agent to, and the opaque handle that binds the
// session to that user agent. It prints and logs its URL's scheme, host,
// path and parameter names only, and its handle as [REDACTED]: the URL
// carries the request_uri, which anyone holding it can begin the
// authorization with until it is used (see the server package's
// BeginAuthorization).
type AuthorizationSession struct {
	// url is the authorization URL's string form, held in a fapi.Secret:
	// fmt's reflection fallback, which prints a fapi.URL's query, prints
	// only the Secret's address.
	url       fapi.Secret
	handle    SessionHandle
	expiresAt time.Time
}

// URL is the authorization URL to redirect the user agent to. It carries
// the request_uri, which begins the authorization for whoever holds it
// until it is used: redirect with it, but don't log it.
func (s AuthorizationSession) URL() fapi.URL {
	// BeginAuthorization keeps the String of an endpoint URL, with its
	// own parameters added, which parses back to the same URL; the zero
	// AuthorizationSession has none.
	u, err := fapi.ParseEndpointURL(s.url.Reveal(), fapi.AllowLoopbackHTTP())
	if err != nil {
		return fapi.URL{}
	}
	return u
}

// Handle is this session's opaque handle: the secret that binds it to the
// user agent that began it, to keep with that user agent (see
// SessionHandle). It is never sent to the authorization server.
func (s AuthorizationSession) Handle() SessionHandle { return s.handle }

// ExpiresAt is when the session expires (Limits.SessionLifetime from
// BeginAuthorization, by Dependencies.Clock): a callback after that is
// refused, so whatever binds the handle to the browser — a cookie — can
// expire with it.
func (s AuthorizationSession) ExpiresAt() time.Time { return s.expiresAt }
