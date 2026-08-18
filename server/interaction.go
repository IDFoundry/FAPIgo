package server

import (
	"crypto/rand"
	"encoding/base64"
	"io"

	fapi "github.com/idfoundry/fapigo"
)

// interactionHandleSize is the byte length of a generated
// InteractionHandle — 256 bits, well beyond what's needed to make it
// unguessable, and deliberately unsuitable for reuse as an
// authorization code (a different value, from a different generator,
// bound to a different store record).
const interactionHandleSize = 32

// InteractionHandle identifies one in-progress authorization
// interaction. It has no public constructor — only BeginAuthorization
// can produce one — is high-entropy, bound to a single pushed
// authorization request, and expires per Config.Limits.InteractionLifetime.
// It must never be confused with, or substituted for, a request_uri or
// an authorization code: the login UI receives only this handle, never
// a storage primary key or the underlying PAR reference.
type InteractionHandle struct {
	value string
}

// String returns the handle's opaque wire value.
func (h InteractionHandle) String() string { return h.value }

func generateInteractionHandle(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	buf := make([]byte, interactionHandleSize)
	if _, err := io.ReadFull(random, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// LoginHint is an unauthenticated hint about who might be authenticating,
// taken directly from the authorization request. It must never be
// treated as, or converted into, a verified subject identifier — only
// the application's own authentication result can establish who
// actually authenticated.
type LoginHint string

// AuthenticationHints are unauthenticated hints an interaction's login
// UI may use to streamline authentication (e.g. pre-filling a username).
// None of them may be trusted as an authentication outcome.
type AuthenticationHints struct {
	LoginHint LoginHint // "" if the authorization request carried none
}

// InteractionRequest is what the embedding application needs to render
// an interaction (typically a login/consent UI) for a pending
// authorization.
type InteractionRequest struct {
	ClientID fapi.ClientID
	Scope    []string
	Hints    AuthenticationHints
}
