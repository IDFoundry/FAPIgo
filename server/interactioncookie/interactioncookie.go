// Package interactioncookie carries an authorization server's
// interaction between its authorization endpoint and its consent
// submission in one encrypted browser cookie: the server.InteractionHandle,
// bound to the browser as server.InteractionHandle's doc asks, and the
// server.InteractionRequest the consent page is drawn from
// (InteractionRequest.MarshalText). Nothing is kept on the server, so any
// instance that shares the keys can finish an interaction another
// began.
//
// The cookie is sealed with AES-256-GCM: an InteractionRequest can carry
// personal data (the login hint, authorization details), so it is
// encrypted, not just signed. Every key opens a cookie and the first
// seals new ones, so keys rotate by putting the new one first and
// dropping the old one once cookies sealed with it have expired.
//
// A browser keeps one cookie of a name, so a second interaction in the
// same browser replaces the first: another tab, or a page that sends the
// browser to the authorization endpoint for a client of its own. The
// consent form must not then complete the replacement in its place. Set
// returns a tag for the page it renders, to put in the form (FormField),
// and Read refuses a form whose tag isn't the cookie's: that page's
// interaction is gone, and the user starts again.
//
// Give it keys of its own, apart from any client/sessioncookie's or
// client.TokenSetSealer's.
//
// The cookie is not a CSRF defence. The consent form's submission still
// needs one, such as net/http's CrossOriginProtection.
package interactioncookie

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/internal/sealedcookie"
	"github.com/idfoundry/fapigo/server"
)

// MaxValueBytes bounds a sealed cookie value. A browser stores about
// 4096 bytes per cookie, its name and attributes included; Set refuses a
// larger value with ErrTooLarge.
const MaxValueBytes = sealedcookie.MaxValueBytes

// DefaultName is the cookie's name unless Options.Name sets another.
// The __Host- prefix makes the browser accept it only Secure, for this
// host alone and with Path=/.
const DefaultName = "__Host-fapi-interaction"

// FormField is a name for the form field that carries Set's tag back to
// Read; any name will do.
const FormField = "interaction"

var (
	// ErrTooLarge is Set's answer for an interaction too large for a
	// cookie, such as one with large authorization details: keep that one
	// in a server-side session instead.
	ErrTooLarge = errors.New("interactioncookie: the interaction is too large for a cookie")

	// ErrNoInteraction is Read's answer when the request carries no
	// cookie, or one that doesn't open with any key, has expired, is
	// malformed, or is for another interaction than the form's tag names:
	// this browser has no interaction in progress here for that form.
	ErrNoInteraction = errors.New("interactioncookie: no interaction in progress")
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

// Cookie seals interactions into a cookie, and opens them again.
type Cookie struct {
	jar *sealedcookie.Jar
}

// New returns a Cookie sealing with keys[0] and opening with any of keys,
// each 32 random bytes (AES-256) shared by every instance of the server.
//
// Give the interaction cookie its own keys, distinct from any other
// sealer's (sessioncookie, client.TokenSetSealer and the like), and
// keep its name distinct too: sealed values under a shared key differ
// only in their name binding, so a separate key keeps one sealer's
// output from ever being offered to another. New refuses an all-zero
// or single-repeated-byte key and the same key twice, which are never
// random.
func New(keys [][]byte, opts Options) (*Cookie, error) {
	name := opts.Name
	if name == "" {
		name = DefaultName
	}
	jar, err := sealedcookie.New("interactioncookie", keys, name, opts.Path)
	if err != nil {
		return nil, err
	}
	return &Cookie{jar: jar}, nil
}

// sealed is what a cookie carries.
type sealed struct {
	Tag     string `json:"tag"`
	Handle  string `json:"handle"`
	Request string `json:"request"`
}

// Set seals a — BeginAuthorization's InteractionRequired — as of now
// into the cookie on w, and returns the tag that names this interaction:
// render it into the consent form, for Read. The tag isn't secret, and
// grants nothing without the cookie. The cookie expires with a's handle
// (a.ExpiresAt), so now must be by the server's own clock
// (Dependencies.Clock). Set returns ErrTooLarge, setting nothing, when
// the interaction doesn't fit.
func (c *Cookie) Set(w http.ResponseWriter, a server.InteractionRequired, now time.Time) (string, error) {
	encoded, err := a.Interaction.MarshalText()
	if err != nil {
		return "", err
	}
	random := make([]byte, 16)
	_, _ = rand.Read(random) // never fails: it crashes the program instead (Go 1.24+)
	tag := base64.RawURLEncoding.EncodeToString(random)
	err = c.jar.Set(w, sealed{Tag: tag, Handle: a.Handle.String(), Request: string(encoded)}, a.ExpiresAt, now)
	if errors.Is(err, sealedcookie.ErrTooLarge) {
		return "", ErrTooLarge
	}
	if err != nil {
		return "", err
	}
	return tag, nil
}

// Read opens the cookie r carries, as of now, for the form that sent tag
// back (Set's result, from the page it rendered). Any failure — no
// cookie, a key that doesn't open it, a tampered or expired value, or a
// cookie for another interaction than tag's — is ErrNoInteraction.
func (c *Cookie) Read(r *http.Request, now time.Time, tag string) (server.InteractionHandle, server.InteractionRequest, error) {
	var s sealed
	if !c.jar.Open(r, now, &s) || tag == "" || subtle.ConstantTimeCompare([]byte(s.Tag), []byte(tag)) != 1 {
		return server.InteractionHandle{}, server.InteractionRequest{}, ErrNoInteraction
	}
	handle, err := server.ParseInteractionHandle(s.Handle)
	if err != nil {
		return server.InteractionHandle{}, server.InteractionRequest{}, ErrNoInteraction
	}
	in, err := server.ParseInteractionRequest(s.Request)
	if err != nil {
		return server.InteractionHandle{}, server.InteractionRequest{}, ErrNoInteraction
	}
	return handle, in, nil
}

// Clear expires the cookie on w: call it once the interaction is
// completed, whatever its outcome.
func (c *Cookie) Clear(w http.ResponseWriter) {
	c.jar.Clear(w)
}
