package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
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
// CompleteBackchannelAuthentication. Only BeginBackchannelAuthentication
// produces a new one, and it must never be confused with, or
// substituted for, AuthReqID: a value safe to hand to the OAuth client
// (AuthReqID) must never double as the value that authorizes recording
// a decision (this handle), the same separation InteractionHandle
// keeps from a request_uri.
type BackchannelAuthenticationHandle struct {
	value string
}

// String returns the handle's opaque wire value.
func (h BackchannelAuthenticationHandle) String() string { return h.value }

// ParseBackchannelAuthenticationHandle reconstructs the
// BackchannelAuthenticationHandle BeginBackchannelAuthentication
// originally returned, from its own wire value
// (BackchannelAuthenticationHandle.String()) — mirroring
// ParseInteractionHandle for CIBA's own out-of-band authentication
// component: it lets that component persist the value in its own
// distributed storage and hand it back to
// CompleteBackchannelAuthentication from a different request,
// goroutine, or instance than the one BeginBackchannelAuthentication
// ran on. See ParseInteractionHandle's own doc comment for the
// validation contract this mirrors exactly.
func ParseBackchannelAuthenticationHandle(value string) (BackchannelAuthenticationHandle, error) {
	if value == "" {
		return BackchannelAuthenticationHandle{}, fmt.Errorf("server: backchannel authentication handle is empty")
	}
	return BackchannelAuthenticationHandle{value: value}, nil
}

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

	// AuthorizationDetails mirrors InteractionRequest.AuthorizationDetails
	// exactly, for the CIBA flow.
	AuthorizationDetails extension.RARValues
}
