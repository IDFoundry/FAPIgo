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
// The cookie is not a CSRF defence. The consent form's submission still
// needs one, such as net/http's CrossOriginProtection.
package interactioncookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// version prefixes every sealed value, so a later format can be told
// apart.
const version byte = 1

// MaxValueBytes bounds a sealed cookie value. A browser stores about
// 4096 bytes per cookie, its name and attributes included; Set refuses a
// larger value with ErrTooLarge.
const MaxValueBytes = 3800

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
	// Lifetime is how long a sealed interaction is accepted, and the
	// cookie's Max-Age. Required: at most the server's
	// Limits.InteractionLifetime, after which the handle is no use anyway.
	Lifetime time.Duration

	// Name is the cookie's name: DefaultName if empty. A name with the
	// __Host- prefix gets Path=/, as the prefix requires.
	Name string

	// Path is the cookie's path: "/" if empty. It must be "/" for a
	// __Host- name.
	Path string
}

// Cookie seals interactions into a cookie, and opens them again.
type Cookie struct {
	name, path string
	lifetime   time.Duration
	keys       []sealingKey // keys[0] seals
}

type sealingKey struct {
	id   [4]byte
	aead cipher.AEAD
}

// New returns a Cookie sealing with keys[0] and opening with any of keys,
// each 32 random bytes (AES-256) shared by every instance of the server.
func New(keys [][]byte, opts Options) (*Cookie, error) {
	if len(keys) == 0 {
		return nil, errors.New("interactioncookie: at least one key is required")
	}
	if opts.Lifetime <= 0 {
		return nil, errors.New("interactioncookie: Options.Lifetime is required")
	}
	c := &Cookie{name: opts.Name, path: opts.Path, lifetime: opts.Lifetime}
	if c.name == "" {
		c.name = DefaultName
	}
	if c.path == "" {
		c.path = "/"
	}
	if strings.HasPrefix(c.name, "__Host-") && c.path != "/" {
		return nil, errors.New("interactioncookie: a __Host- cookie must have Path /")
	}
	for i, k := range keys {
		if len(k) != 32 {
			return nil, fmt.Errorf("interactioncookie: key %d is %d bytes, want 32", i, len(k))
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(k)
		c.keys = append(c.keys, sealingKey{id: [4]byte(sum[:4]), aead: aead})
	}
	return c, nil
}

// sealed is the plaintext a cookie value encrypts.
type sealed struct {
	ExpiresAt int64  `json:"exp"`
	Tag       string `json:"tag"`
	Handle    string `json:"handle"`
	Request   string `json:"request"`
}

// Set seals handle and in, as of now, into the cookie on w, and returns
// the tag that names this interaction: render it into the consent form,
// for Read. The tag isn't secret, and grants nothing without the cookie.
// Set returns ErrTooLarge, setting nothing, when the interaction doesn't
// fit.
func (c *Cookie) Set(w http.ResponseWriter, handle server.InteractionHandle, in server.InteractionRequest, now time.Time) (string, error) {
	encoded, err := in.MarshalText()
	if err != nil {
		return "", err
	}
	key := c.keys[0]
	// One read for the tag and the nonce: the tag's 16 bytes, then the
	// nonce.
	random := make([]byte, 16+key.aead.NonceSize())
	_, _ = rand.Read(random) // never fails: it crashes the program instead (Go 1.24+)
	tag, nonce := base64.RawURLEncoding.EncodeToString(random[:16]), random[16:]
	// Strings and an integer: encoding can't fail.
	plaintext, _ := json.Marshal(sealed{ExpiresAt: now.Add(c.lifetime).Unix(), Tag: tag, Handle: handle.String(), Request: string(encoded)})
	header := append([]byte{version}, key.id[:]...)
	box := append(append(header, nonce...), key.aead.Seal(nil, nonce, plaintext, c.additionalData())...)
	value := base64.RawURLEncoding.EncodeToString(box)
	if len(value) > MaxValueBytes {
		return "", ErrTooLarge
	}
	http.SetCookie(w, c.cookie(value, int(c.lifetime/time.Second)))
	return tag, nil
}

// Read opens the cookie r carries, as of now, for the form that sent tag
// back (Set's result, from the page it rendered). Any failure — no
// cookie, a key that doesn't open it, a tampered or expired value, or a
// cookie for another interaction than tag's — is ErrNoInteraction.
func (c *Cookie) Read(r *http.Request, now time.Time, tag string) (server.InteractionHandle, server.InteractionRequest, error) {
	ck, err := r.Cookie(c.name)
	if err != nil {
		return server.InteractionHandle{}, server.InteractionRequest{}, ErrNoInteraction
	}
	s, ok := c.open(ck.Value, now)
	if !ok || tag == "" || subtle.ConstantTimeCompare([]byte(s.Tag), []byte(tag)) != 1 {
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

func (c *Cookie) open(value string, now time.Time) (sealed, bool) {
	box, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(box) < 5 || box[0] != version {
		return sealed{}, false
	}
	id, rest := [4]byte(box[1:5]), box[5:]
	for _, key := range c.keys {
		if key.id != id || len(rest) < key.aead.NonceSize() {
			continue
		}
		nonce, ciphertext := rest[:key.aead.NonceSize()], rest[key.aead.NonceSize():]
		plaintext, err := key.aead.Open(nil, nonce, ciphertext, c.additionalData())
		if err != nil {
			return sealed{}, false
		}
		var s sealed
		if json.Unmarshal(plaintext, &s) != nil || !now.Before(time.Unix(s.ExpiresAt, 0)) {
			return sealed{}, false
		}
		return s, true
	}
	return sealed{}, false
}

// Clear expires the cookie on w: call it once the interaction is
// completed, whatever its outcome.
func (c *Cookie) Clear(w http.ResponseWriter) {
	http.SetCookie(w, c.cookie("", -1))
}

func (c *Cookie) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: c.name, Value: value, Path: c.path, MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}
}

// additionalData binds a sealed value to this cookie's name and format,
// so one sealed for another cookie, or another format, doesn't open.
func (c *Cookie) additionalData() []byte {
	return append([]byte(c.name), version)
}
