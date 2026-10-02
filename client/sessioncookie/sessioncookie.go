// Package sessioncookie binds a client's authorization to the browser
// that began it, as client.SessionHandle's doc requires (RFC 9700 §4.7),
// in one encrypted cookie: the SessionHandle, and the application's own
// value for that authorization — an order or check ID, say — so the two
// can't be mismatched at the callback, as two cookies could be.
//
// Set it when BeginAuthorization returns, before redirecting the
// browser; Read it at the redirect URI, for
// client.AuthorizationCallback.Session; Clear it once the callback is
// handled, whatever its outcome. The cookie expires with the session
// (AuthorizationSession.ExpiresAt).
//
// The cookie is sealed with AES-256-GCM under keys every instance of the
// client shares: the first seals and every key opens, so keys rotate by
// putting the new one first and dropping the old one once cookies sealed
// with it have expired. It is HttpOnly, Secure and SameSite=Lax — the
// authorization response arrives as a top-level GET from the
// authorization server, which Lax lets the cookie ride along on — with
// the __Host- prefix by default. Give it keys of its own, apart from any
// interactioncookie's or client.TokenSetSealer's.
//
// A browser keeps one cookie of a name, so a second authorization begun
// in another tab replaces the first's cookie. The first tab's callback
// then fails, as one that no longer matches the browser's session, and
// the user starts again: that is the binding working, not a fault.
package sessioncookie

import (
	"errors"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/internal/sealedcookie"
)

// DefaultName is the cookie's name unless Options.Name sets another.
// The __Host- prefix makes the browser accept it only Secure, for this
// host alone and with Path=/.
const DefaultName = "__Host-fapi-session"

var (
	// ErrTooLarge is Set's answer for an application value too large for
	// a cookie: keep it on the server, and put its key in the cookie.
	ErrTooLarge = errors.New("sessioncookie: too large for a cookie")

	// ErrNoSession is Read's answer when the request carries no cookie,
	// or one that doesn't open with any key, has expired or is malformed:
	// this browser began no authorization here, or not recently enough.
	ErrNoSession = errors.New("sessioncookie: no authorization in progress")
)

// Options configures a Cookie.
type Options struct {
	// Name is the cookie's name: DefaultName if empty. Keep the __Host-
	// prefix: without it, a sibling subdomain can set the cookie in the
	// victim's browser, with a value it got sealed for itself.
	Name string

	// Path is the cookie's path: "/" if empty. New refuses another path
	// for a __Host- name, which the prefix forbids.
	Path string
}

// Cookie seals authorization sessions into a cookie, and opens them
// again.
type Cookie struct {
	jar *sealedcookie.Jar
}

// New returns a Cookie sealing with keys[0] and opening with any of keys,
// each 32 random bytes (AES-256) shared by every instance of the client.
func New(keys [][]byte, opts Options) (*Cookie, error) {
	name := opts.Name
	if name == "" {
		name = DefaultName
	}
	jar, err := sealedcookie.New("sessioncookie", keys, name, opts.Path)
	if err != nil {
		return nil, err
	}
	return &Cookie{jar: jar}, nil
}

// sealed is what a cookie carries.
type sealed struct {
	Handle string `json:"handle"`
	Value  string `json:"value,omitempty"`
}

// Set seals session's handle and value — the application's own, for this
// authorization; "" for none — into the cookie on w, as of now by the
// client's own clock (Dependencies.Clock). The cookie expires with the
// session. Set returns ErrTooLarge, setting nothing, when value doesn't
// fit.
func (c *Cookie) Set(w http.ResponseWriter, session client.AuthorizationSession, value string, now time.Time) error {
	err := c.jar.Set(w, sealed{Handle: session.Handle().String(), Value: value}, session.ExpiresAt(), now)
	if errors.Is(err, sealedcookie.ErrTooLarge) {
		return ErrTooLarge
	}
	return err
}

// Read opens the cookie r carries, as of now: the session's handle, for
// client.AuthorizationCallback.Session, and the value Set was given. Any
// failure is ErrNoSession.
func (c *Cookie) Read(r *http.Request, now time.Time) (client.SessionHandle, string, error) {
	var s sealed
	if !c.jar.Open(r, now, &s) {
		return client.SessionHandle{}, "", ErrNoSession
	}
	handle, err := client.ParseSessionHandle(s.Handle)
	if err != nil {
		return client.SessionHandle{}, "", ErrNoSession
	}
	return handle, s.Value, nil
}

// Clear expires the cookie on w: call it once the callback is handled,
// whatever its outcome.
func (c *Cookie) Clear(w http.ResponseWriter) {
	c.jar.Clear(w)
}
