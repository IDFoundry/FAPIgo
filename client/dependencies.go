package client

import (
	"io"

	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// Dependencies are this client's injected collaborators. New always
// requires HTTP, Clock and Random, and each other field when the Config
// uses what it's for (see each field) — there is no implicit fallback
// (no default clock, no silently-installed in-memory session store).
type Dependencies struct {
	// Sessions persists in-progress authorization-flow state, until
	// Limits.SessionLifetime. Required when Endpoints.Authorization is
	// set; a client that only uses CIBA or client credentials may leave
	// it nil. Under AssuranceProduction it must declare
	// Durable and AtomicConsume (storage.StoreAssurance). A native app's
	// own on-device store: see "Native apps" in the package doc, and
	// Config.CallbackBinding.
	Sessions storage.SessionStore

	// Keys performs this client's own signing operations: client
	// assertions (ClientAuthMethodPrivateKeyJWT), attestation PoPs
	// (ClientAuthMethodAttestation), DPoP proofs (SenderConstrainDPoP),
	// request objects (ProfileFAPISecurityWithMessageSigning or
	// PushedRequestEncodingRequestObject), CIBA authentication requests
	// (Endpoints.BackchannelAuthentication) and its federation Entity
	// Configuration (Federation.EntityID). Required when the Config uses
	// any of those; leave it nil for a client that signs nothing — one
	// authenticating with a TLS client certificate
	// (ClientAuthMethodTLSClientAuth and its siblings, or
	// ClientAuthMethodSelfSignedTLSClientAuth) whose tokens are bound to
	// that certificate (SenderConstrainMTLS).
	Keys keys.KeyManager

	// IssuerKeys resolves the authorization server's verification keys,
	// to verify a JARM response (when Config.Profile requires one), an
	// issued ID token, and signed UserInfo responses/VerifyIssuerJWS.
	// Required, except that a Config.OAuthOnly client verifying neither
	// JARM nor signed UserInfo leaves it nil — see Config.OAuthOnly.
	IssuerKeys keys.IssuerKeySource

	// HTTP performs this client's PAR, token-endpoint and other POST
	// calls, and ResourceClient's requests. It must not follow redirects
	// itself — a redirect would resend a client assertion, access token
	// or DPoP proof to a target this client never chose — so New uses a
	// copy of an *http.Client whose CheckRedirect never follows, and a
	// response from any other HTTPClient that followed one is refused.
	//
	// That copy can't be made of an HTTPClient that isn't an
	// *http.Client (a metrics or tracing wrapper around one, say), so
	// the client sends such an HTTPClient every request body once: an
	// *http.Client inside the wrapper can't resend a POST body — the
	// client assertion, a code and its PKCE verifier — across a 307 or
	// 308, and the call fails instead. A wrapper can still follow a redirect of a
	// body-less request (a ResourceClient GET), or a 301, 302 or 303,
	// which net/http turns into a body-less GET: that hop receives the
	// request's headers, and the response is then refused. net/http
	// drops Authorization for a hop to a host that isn't the original
	// or a subdomain of it, but not the DPoP header. Prefer an
	// *http.Client, or a wrapper whose own *http.Client never follows.
	HTTP fapihttp.HTTPClient

	// Clock supplies the current time.
	Clock Clock

	// Random is the source of randomness for state, nonce and PKCE
	// verifier generation. Under AssuranceProduction it must be
	// crypto/rand.Reader itself.
	Random io.Reader

	// Decryption recovers the content-encryption key of an encrypted ID
	// token (the keys.IDTokenDecryption purpose) or UserInfo response
	// (keys.UserInfoDecryption). Required exactly when
	// Config.Algorithms.IDTokenKeyManagement or
	// Config.Algorithms.UserInfoKeyManagement is set; nil otherwise
	// — most deployments never register for encrypted ID tokens, so
	// this stays an opt-in dependency rather than a mandatory one every
	// embedder has to wire up.
	Decryption keys.Decrypter

	// DPoPNonceCache lets this client proactively reuse a DPoP nonce a
	// server already handed it, instead of always paying the challenge
	// round trip RFC 9449 §8/§9 otherwise requires on every call — see
	// its own doc comment. Nil (the zero value) disables the
	// optimization entirely; pass NewInMemoryDPoPNonceCache() to enable
	// it, the same deliberate opt-in Clock: SystemClock{} already is.
	DPoPNonceCache DPoPNonceCache

	// Attestation supplies the pre-issued Client Attestation JWT this
	// client attaches to every PAR/token/CIBA request under
	// storage.ClientAuthMethodAttestation — see AttestationSource's own
	// doc comment. The Client Instance Key each request's own fresh
	// Client Attestation PoP JWT is signed with instead comes from Keys
	// above, under the keys.ClientAttestationPoPSigning purpose, the
	// same "keys are handles and operations, never raw private keys"
	// convention every other signing need in this struct already
	// follows. Required exactly when Config.ClientAuthMethod is
	// storage.ClientAuthMethodAttestation; nil otherwise, the same
	// opt-in shape as Decryption above.
	Attestation AttestationSource
}
