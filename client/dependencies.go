package client

import (
	"io"

	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// Dependencies are this client's injected collaborators. New rejects a
// nil value for any field — there is no implicit fallback (no default
// clock, no silently-installed in-memory session store).
type Dependencies struct {
	// Sessions persists in-progress authorization-flow state.
	Sessions storage.SessionStore

	// Keys performs this client's own signing operations: client
	// assertion signing, request-object signing (when Config.Profile
	// requires it), and DPoP proof signing.
	Keys keys.KeyManager

	// IssuerKeys resolves the authorization server's verification keys,
	// to verify a JARM response (when Config.Profile requires one) and an
	// issued ID token.
	IssuerKeys keys.IssuerKeySource

	// HTTP performs this client's PAR and token-endpoint calls.
	HTTP fapihttp.HTTPClient

	// Clock supplies the current time.
	Clock Clock

	// Random is the source of randomness for state, nonce and PKCE
	// verifier generation.
	Random io.Reader

	// Decryption recovers the content-encryption key of an encrypted ID
	// token, using the keys.IDTokenDecryption purpose. Required exactly
	// when Config.Algorithms.IDTokenKeyManagement is set; nil otherwise
	// — most deployments never register for encrypted ID tokens, so
	// this stays an opt-in dependency rather than a mandatory one every
	// embedder has to wire up.
	Decryption keys.Decrypter
}
