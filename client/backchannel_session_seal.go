package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

// backchannelSessionSealVersion prefixes every sealed
// BackchannelAuthenticationSession, so a later format can be told apart.
// (Version 1 was the unsealed text encoding v0.51 and earlier wrote.)
const backchannelSessionSealVersion byte = 2

// maxSealedBackchannelSession bounds what BackchannelSessionSealer.Open
// reads: an auth_req_id and a notification token, with room to spare.
const maxSealedBackchannelSession = 4096

// ErrUnreadableBackchannelSession is the cause, for errors.Is, of a
// BackchannelSessionSealer.Open failure on a session that doesn't open:
// sealed with no key it has, for another issuer, client or owner,
// tampered with, or stored by a version before the sessions were sealed. There
// is nothing to recover: begin the backchannel authentication again.
var ErrUnreadableBackchannelSession = errors.New("client: the sealed backchannel authentication session doesn't open")

// sealedBackchannelSession is the JSON a sealed session encrypts.
type sealedBackchannelSession struct {
	AuthReqID         string    `json:"a"`
	IntervalMillis    int64     `json:"i"`
	ExpiresAt         time.Time `json:"e"`
	NotificationToken string    `json:"n,omitempty"`
	// OpenID: whether the request's scope included "openid", so an
	// approval must carry an ID token.
	OpenID bool `json:"o,omitempty"`
	// EssentialACR: the request's essential "acr" values, which an
	// approval's ID token acr must be one of.
	EssentialACR []string `json:"r,omitempty"`
}

// BackchannelSessionSealer encrypts a BackchannelAuthenticationSession
// for storage, and opens it again, so a session begun on one instance
// can be polled, or its ping callback authenticated, on another: seal
// it, store the result keyed by its AuthReqID, and open it where it's
// needed.
//
// A sealed session is AES-256-GCM, bound to this client's issuer and
// client ID and to an owner the caller names (the user, account or
// connection the request is for), so it opens only for the owner it was
// sealed for: a sealed session leaked from one user, through a log, a
// misrouted cookie or shared storage, doesn't open under another's.
// Sealing matters: the session records whether the request
// asked for "openid", which decides whether an approval without an ID
// token is refused, the essential acr values the ID token must meet, and which of this client's requests to poll, so a
// stored session that could be edited could turn that check off.
//
// It contains the client_notification_token: store it as you would a
// credential, and don't log it. Open returns the session it sealed,
// whatever key it was looked up by, so check its AuthReqID against the
// one you expected when that matters.
type BackchannelSessionSealer struct {
	client *Client
	keys   sealKeyring
}

// NewBackchannelSessionSealer returns a BackchannelSessionSealer for c
// that seals with keys[0] and opens with any of keys, each 32 random
// bytes the application keeps secret. Rotate by putting a new key
// first: Open says when a session it opened was sealed with an older
// key; sessions live minutes, so the old key can go once they're done.
func NewBackchannelSessionSealer(c *Client, keys [][]byte) (*BackchannelSessionSealer, error) {
	if c == nil {
		return nil, errors.New("client: NewBackchannelSessionSealer needs a Client")
	}
	ring, err := newSealKeyring("backchannel session", keys)
	if err != nil {
		return nil, err
	}
	return &BackchannelSessionSealer{client: c, keys: ring}, nil
}

// Seal encrypts session for storage, for owner: whatever names whose
// request this is, such as a user or connection ID, and must be given to
// Open again. owner is required.
func (s *BackchannelSessionSealer) Seal(session BackchannelAuthenticationSession, owner string) ([]byte, error) {
	if owner == "" {
		return nil, newError(ErrorInvalidRequest, "a backchannel authentication session is sealed for an owner", nil)
	}
	if session.authReqID == "" {
		return nil, newError(ErrorInvalidRequest, "a backchannel authentication session without an auth_req_id can't be sealed", nil)
	}
	plaintext, err := json.Marshal(sealedBackchannelSession{
		AuthReqID: session.authReqID, IntervalMillis: session.interval.Milliseconds(),
		ExpiresAt: session.expiresAt.UTC(), NotificationToken: session.notificationToken,
		OpenID: session.openID, EssentialACR: session.essentialACR,
	})
	if err != nil {
		return nil, newError(ErrorInternal, "failed to encode the backchannel authentication session", err)
	}
	return s.keys.seal(backchannelSessionSealVersion, plaintext, s.additionalData(owner)), nil
}

// Open decrypts a session Seal sealed for owner, for PollBackchannelAuthentication
// or BackchannelNotification.Authenticates. reseal reports a session
// sealed with a key other than the first. Any failure to open is an
// ErrorInvalidRequest *Error whose cause is
// ErrUnreadableBackchannelSession.
func (s *BackchannelSessionSealer) Open(sealed []byte, owner string) (session BackchannelAuthenticationSession, reseal bool, err error) {
	if len(sealed) > maxSealedBackchannelSession {
		return BackchannelAuthenticationSession{}, false, errUnreadableBackchannelSession()
	}
	plaintext, keyIndex, ok := s.keys.open(backchannelSessionSealVersion, sealed, s.additionalData(owner))
	if !ok {
		return BackchannelAuthenticationSession{}, false, errUnreadableBackchannelSession()
	}
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.DisallowUnknownFields()
	var e sealedBackchannelSession
	if err := dec.Decode(&e); err != nil || e.AuthReqID == "" || e.IntervalMillis <= 0 || e.ExpiresAt.IsZero() {
		return BackchannelAuthenticationSession{}, false, errUnreadableBackchannelSession()
	}
	return BackchannelAuthenticationSession{
		authReqID: e.AuthReqID, interval: time.Duration(e.IntervalMillis) * time.Millisecond,
		expiresAt: e.ExpiresAt, notificationToken: e.NotificationToken,
		openID: e.OpenID, essentialACR: e.EssentialACR,
	}, keyIndex > 0, nil
}

func errUnreadableBackchannelSession() *Error {
	return newError(ErrorInvalidRequest, "the sealed backchannel authentication session doesn't open: begin the backchannel authentication again", ErrUnreadableBackchannelSession)
}

// additionalData binds a sealed session to the format, this client's
// issuer and client ID, and owner, each length-prefixed so no two differ
// only in where one ends and the next begins.
func (s *BackchannelSessionSealer) additionalData(owner string) []byte {
	return sealAdditionalData("fapigo backchannel session", backchannelSessionSealVersion, s.client.cfg.Issuer.String(), s.client.cfg.ClientID.String(), owner)
}
