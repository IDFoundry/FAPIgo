package server

import (
	"crypto/rand"
	"encoding/base64"
	"io"

	fapi "github.com/idfoundry/fapigo"
)

// backchannelAuthenticationHandleSize and authReqIDSize are the byte
// lengths of a generated BackchannelAuthenticationHandle/AuthReqID —
// 256 bits each, matching interactionHandleSize.
const (
	backchannelAuthenticationHandleSize = 32
	authReqIDSize                       = 32
)

// BackchannelAuthenticationHandle identifies one pending CIBA
// backchannel authentication request, for the embedder's own
// out-of-band authentication component to pass to
// CompleteBackchannelAuthentication. It has no public constructor —
// only BeginBackchannelAuthentication can produce one — and must never
// be confused with, or substituted for, AuthReqID: a value safe to hand
// to the OAuth client (AuthReqID) must never double as the value that
// authorizes recording a decision (this handle), the same separation
// InteractionHandle keeps from a request_uri.
type BackchannelAuthenticationHandle struct {
	value string
}

// String returns the handle's opaque wire value.
func (h BackchannelAuthenticationHandle) String() string { return h.value }

func generateBackchannelAuthenticationHandle(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buf := make([]byte, backchannelAuthenticationHandleSize)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// AuthReqID is the client-facing "auth_req_id" a successful
// BeginBackchannelAuthentication call returns. It has no public
// constructor — only this package can produce one.
type AuthReqID struct {
	value string
}

// String returns the auth_req_id's wire value.
func (a AuthReqID) String() string { return a.value }

func generateAuthReqID(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buf := make([]byte, authReqIDSize)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// BackchannelAuthenticationHints are unauthenticated hints a CIBA
// backchannel authentication request may carry, taken directly from
// the request — mirroring AuthenticationHints for the browser flow.
// None of them may be trusted as an authentication outcome.
type BackchannelAuthenticationHints struct {
	LoginHint      LoginHint // "" if the request carried none
	LoginHintToken string    // "" if the request carried none
	IDTokenHint    string    // "" if the request carried none
}

// BackchannelInteractionRequest is what the embedding application needs
// to authenticate/consent the end user out-of-band for a pending CIBA
// request — mirroring InteractionRequest for the browser flow.
type BackchannelInteractionRequest struct {
	ClientID       fapi.ClientID
	Scope          []string
	Hints          BackchannelAuthenticationHints
	ACRValues      []string
	BindingMessage string
}
