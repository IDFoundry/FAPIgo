// Package sealedcookie seals a value into one browser cookie and opens
// it again, for server/interactioncookie and client/sessioncookie:
// AES-256-GCM under a key ring (the first key seals, every key opens,
// each sealed value naming its key), the expiry sealed in with the
// value, and the cookie's name and the format bound in as additional
// data, so a value sealed for one cookie doesn't open as another. The
// cookie is HttpOnly, Secure and SameSite=Lax.
package sealedcookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/idfoundry/fapigo/internal/sealkeys"
	"time"
)

// version prefixes every sealed value, so a later format can be told
// apart.
const version byte = 1

// MaxValueBytes bounds a sealed cookie value. A browser stores about
// 4096 bytes per cookie, its name and attributes included.
const MaxValueBytes = 3800

// ErrTooLarge is Set's answer for a value too large for a cookie.
var ErrTooLarge = errors.New("sealedcookie: too large for a cookie")

// Jar seals values into the cookie it names.
type Jar struct {
	pkg, name, path string
	keys            []key // keys[0] seals
}

type key struct {
	id   [4]byte
	aead cipher.AEAD
}

// New returns a Jar for the cookie name at path ("/" if empty), sealing
// with keys[0] and opening with any of keys, each 32 bytes, as
// sealkeys.Check requires. pkg prefixes its errors.
func New(pkg string, keys [][]byte, name, path string) (*Jar, error) {
	if err := sealkeys.Check(pkg, keys); err != nil {
		return nil, err
	}
	if path == "" {
		path = "/"
	}
	if strings.HasPrefix(name, "__Host-") && path != "/" {
		return nil, fmt.Errorf("%s: a __Host- cookie must have Path /", pkg)
	}
	j := &Jar{pkg: pkg, name: name, path: path}
	for _, k := range keys {
		// A 32-byte key always makes an AES-256 block, and AES always
		// makes a GCM.
		block, _ := aes.NewCipher(k)
		aead, _ := cipher.NewGCM(block)
		sum := sha256.Sum256(k)
		j.keys = append(j.keys, key{id: [4]byte(sum[:4]), aead: aead})
	}
	return j, nil
}

// envelope is the plaintext a cookie value encrypts.
type envelope struct {
	ExpiresAt int64           `json:"exp"`
	Value     json.RawMessage `json:"v"`
}

// Set seals value, as JSON, into the cookie on w, as of now, to be
// opened until expiresAt; it refuses a value already expired, and one
// too large for a cookie (ErrTooLarge), setting nothing.
func (j *Jar) Set(w http.ResponseWriter, value any, expiresAt, now time.Time) error {
	// Max-Age counts whole seconds, and 0 would make a session cookie:
	// less than a second left is as good as expired.
	if expiresAt.Sub(now) < time.Second {
		return fmt.Errorf("%s: already expired", j.pkg)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	// An integer and valid JSON: encoding can't fail.
	plaintext, _ := json.Marshal(envelope{ExpiresAt: expiresAt.Unix(), Value: encoded})
	k := j.keys[0]
	nonce := make([]byte, k.aead.NonceSize())
	_, _ = rand.Read(nonce) // never fails: it crashes the program instead (Go 1.24+)
	box := append(append([]byte{version}, k.id[:]...), nonce...)
	box = k.aead.Seal(box, nonce, plaintext, j.additionalData())
	sealed := base64.RawURLEncoding.EncodeToString(box)
	if len(sealed) > MaxValueBytes {
		return ErrTooLarge
	}
	http.SetCookie(w, j.cookie(sealed, int(expiresAt.Sub(now)/time.Second)))
	return nil
}

// Open decodes the value the cookie r carries into v, as of now. It
// reports false for no cookie, one no key opens, a tampered, expired or
// malformed one, or one that doesn't decode into v.
func (j *Jar) Open(r *http.Request, now time.Time, v any) bool {
	ck, err := r.Cookie(j.name)
	if err != nil {
		return false
	}
	box, err := base64.RawURLEncoding.DecodeString(ck.Value)
	if err != nil || len(box) < 5 || box[0] != version {
		return false
	}
	id, rest := [4]byte(box[1:5]), box[5:]
	for _, k := range j.keys {
		if k.id != id || len(rest) < k.aead.NonceSize() {
			continue
		}
		plaintext, err := k.aead.Open(nil, rest[:k.aead.NonceSize()], rest[k.aead.NonceSize():], j.additionalData())
		if err != nil {
			return false
		}
		var e envelope
		if json.Unmarshal(plaintext, &e) != nil || !now.Before(time.Unix(e.ExpiresAt, 0)) {
			return false
		}
		return json.Unmarshal(e.Value, v) == nil
	}
	return false
}

// Clear expires the cookie on w.
func (j *Jar) Clear(w http.ResponseWriter) {
	http.SetCookie(w, j.cookie("", -1))
}

func (j *Jar) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: j.name, Value: value, Path: j.path, MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}
}

// additionalData binds a sealed value to this cookie's name and format.
func (j *Jar) additionalData() []byte {
	return append([]byte(j.name), version)
}
