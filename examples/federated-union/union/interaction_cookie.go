package union

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// The consent page's state travels with the browser, in a cookie the
// identity provider signs: the interaction handle, the interaction
// itself (server.InteractionRequest.MarshalText), and when it was
// issued. Any instance of the provider holding the same key can show and
// complete the sign-in, so nothing is kept in any one process — the
// pattern a provider running several instances uses. The signature keeps
// the browser from altering what the consent page shows; the server
// checks the grant against the request it stored all the same.

// sealInteraction is the cookie value for handle and in, issued at now.
func (p *identityProvider) sealInteraction(handle server.InteractionHandle, in server.InteractionRequest, now time.Time) (string, error) {
	encoded, err := in.MarshalText()
	if err != nil {
		return "", err
	}
	payload := handle.String() + "~" + string(encoded) + "~" + strconv.FormatInt(now.Unix(), 10)
	return payload + "~" + p.cookieMAC(payload), nil
}

// openInteraction checks value's signature and age, and returns the
// handle and interaction it carries.
func (p *identityProvider) openInteraction(value string, now time.Time) (server.InteractionHandle, server.InteractionRequest, error) {
	payload, mac, ok := cutLast(value, "~")
	if !ok || !hmac.Equal([]byte(mac), []byte(p.cookieMAC(payload))) {
		return server.InteractionHandle{}, server.InteractionRequest{}, errors.New("the sign-in cookie isn't one this provider issued")
	}
	parts := strings.Split(payload, "~")
	if len(parts) != 3 {
		return server.InteractionHandle{}, server.InteractionRequest{}, errors.New("malformed sign-in cookie")
	}
	issued, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || now.Sub(time.Unix(issued, 0)) > pendingLifetime {
		return server.InteractionHandle{}, server.InteractionRequest{}, errors.New("the sign-in has expired")
	}
	handle, err := server.ParseInteractionHandle(parts[0])
	if err != nil {
		return server.InteractionHandle{}, server.InteractionRequest{}, err
	}
	in, err := server.ParseInteractionRequest(parts[1])
	if err != nil {
		return server.InteractionHandle{}, server.InteractionRequest{}, err
	}
	return handle, in, nil
}

func (p *identityProvider) cookieMAC(payload string) string {
	m := hmac.New(sha256.New, p.cookieKey)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}
