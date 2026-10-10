package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/storage"
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
	IDTokenHint    string    // "" if the request carried none; verified, see BackchannelInteractionRequest.RequiredSubject
}

// BackchannelInteractionRequest is what the embedding application needs
// to authenticate/consent the end user out-of-band for a pending CIBA
// request — mirroring InteractionRequest for the browser flow.
type BackchannelInteractionRequest struct {
	ClientID  fapi.ClientID
	Scope     []string
	Hints     BackchannelAuthenticationHints
	ACRValues []string

	// EssentialACRValues mirrors InteractionRequest.EssentialACRValues
	// for the CIBA flow: authenticate the user at one of these classes.
	// CompleteBackchannelAuthentication records an Authorize whose acr
	// isn't one of them as a failed authentication, so the client's
	// poll gets the same answer as AuthenticationFailed and no tokens.
	EssentialACRValues []string

	// RequiredSubject mirrors InteractionRequest.RequiredSubject for the
	// CIBA flow: the end user the request's id_token_hint, or a "claims"
	// sub value, named. Authenticate that user; when the request carried
	// an id_token_hint, this is who it identifies (Hints.IDTokenHint is
	// the token itself, already verified). CompleteBackchannelAuthentication
	// records an Authorize for anyone else as a failed authentication,
	// so the client's poll gets access_denied and no tokens. "" when the
	// request named no one.
	RequiredSubject string

	// BindingMessage is the client's binding_message (CIBA §7.1), empty
	// when it sent none: show it to the user on the authentication
	// device, so they can tell the request they approve is the one the
	// consumption device shows. FAPI-CIBA §5.2.2 requires the
	// authorization server to ensure a unique authorization context
	// exists in the request, or else require a binding_message: if
	// your users can't tell two requests apart by what you show them
	// (the scope or authorization details alone, say), answer one with
	// an empty BindingMessage as a failed authentication rather than
	// approving it.
	BindingMessage string

	// ClientDisplay mirrors InteractionRequest.ClientDisplay, for the
	// CIBA flow.
	ClientDisplay storage.ClientDisplay

	// AuthorizationDetails mirrors InteractionRequest.AuthorizationDetails
	// exactly, for the CIBA flow.
	AuthorizationDetails extension.RARValues

	// RequestedClaims is the identity claims the client asked for with
	// the "claims" parameter — see InteractionRequest.RequestedClaims.
	RequestedClaims RequestedClaims

	// Extensions mirrors InteractionRequest.Extensions, for the CIBA
	// flow's signed backchannel authentication request.
	Extensions extension.Values
}
