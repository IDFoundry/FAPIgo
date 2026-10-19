package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/idfoundry/fapigo/internal/clientattestation"
	"github.com/idfoundry/fapigo/internal/par"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"
)

// AttestationSource supplies the pre-issued Client Attestation JWT this
// client attaches under storage.ClientAuthMethodAttestation
// (draft-ietf-oauth-attestation-based-client-auth-12 §10.2) — an
// opaque, out-of-band-issued, reusable credential this package never
// constructs itself. A real implementation typically wraps a wallet
// app's own OS/hardware attestation API or its backend Attester,
// refreshing the held JWT once it nears whatever validity window the
// Attester gave it; CurrentAttestation is called fresh on every
// request rather than cached by this package, so the refresh policy
// lives entirely in the implementation.
type AttestationSource interface {
	// CurrentAttestation returns the Client Attestation JWT to present
	// on this request. Its own "sub" claim must equal Config.ClientID,
	// and its "cnf.jwk" claim must name the public half of the Client
	// Instance Key Dependencies.Keys signs Client Attestation PoP JWTs
	// with under keys.ClientAttestationPoPSigning — this package never
	// checks either correspondence itself.
	CurrentAttestation(ctx context.Context) (string, error)
}

// StaticAttestation returns an AttestationSource that presents the same
// Client Attestation JWT on every request — the simple case of a wallet
// holding one attestation for its session. It never refreshes: once
// the attestation expires the authorization server rejects it, so a
// wallet that outlives its attestation should implement
// AttestationSource itself and obtain a new one from its Attester. An
// empty jwt fails every request with an error rather than sending an
// empty header.
func StaticAttestation(jwt string) AttestationSource {
	return staticAttestation(jwt)
}

type staticAttestation string

func (s staticAttestation) CurrentAttestation(context.Context) (string, error) {
	if s == "" {
		return "", errors.New("client: StaticAttestation has no attestation JWT")
	}
	return string(s), nil
}

// ChallengeSource optionally supplies a Challenge (draft-12 §6) to embed
// in the next Client Attestation PoP JWT — such as one fetched from the
// authorization server's challenge_endpoint (§6.3). An AttestationSource
// may additionally implement this to opt in.
//
// This package doesn't need it to follow an authorization server's
// Challenges: it keeps the most recent one the server provides in an
// OAuth-Client-Attestation-Challenge response header (§6.1, §6.2) and
// puts that in every PoP (§6: "A Client MUST include the most recently
// received Challenge"), and it retries a request once when the server
// answers use_attestation_challenge with a fresh one. CurrentChallenge
// is consulted only until the server has provided a Challenge that way;
// it is called fresh on every request that builds a PoP until then, so
// single-use-vs-reusable policy for a fetched challenge lives in the
// implementation. With neither, no challenge claim is sent, matching an
// authorization server that doesn't issue challenges and relies on iat
// freshness alone.
type ChallengeSource interface {
	CurrentChallenge(ctx context.Context) (string, error)
}

const (
	// attestationHeader carries the held Client Attestation JWT
	// (draft-12 §4) — never sent as a client_id/client_assertion*
	// form field (see addClientAuthentication's own doc comment).
	attestationHeader = "OAuth-Client-Attestation"

	// attestationPoPHeader carries the freshly signed Client
	// Attestation PoP JWT (draft-12 §5.1) — see attestationHeaders'
	// own doc comment.
	attestationPoPHeader = "OAuth-Client-Attestation-PoP"

	// attestationChallengeHeader carries a Challenge an authorization
	// server provides, on an error response or any other (draft-12
	// §6.1, §6.2).
	attestationChallengeHeader = "OAuth-Client-Attestation-Challenge"

	// maxAttestationChallengeBytes bounds a Challenge this client keeps
	// from a response header. The value is opaque (§6), but one larger
	// than this is no use in a PoP sent in a request header.
	maxAttestationChallengeBytes = 1024
)

// latestChallenge is the most recent Challenge the authorization server
// provided, safe for concurrent use. A nil *latestChallenge holds none.
type latestChallenge struct {
	mu    sync.Mutex
	value string
}

func (l *latestChallenge) set(value string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.value = value
	l.mu.Unlock()
}

func (l *latestChallenge) get() string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.value
}

// recordAttestationChallenge keeps the Challenge header carries, if any,
// as the one to put in this client's next PoP (draft-12 §6), when this
// client authenticates by attestation. A value that's empty, too long,
// or not visible ASCII is ignored.
func (c *Client) recordAttestationChallenge(header http.Header) {
	if c.cfg.ClientAuthMethod != storage.ClientAuthMethodAttestation {
		return
	}
	if value := header.Get(attestationChallengeHeader); isUsableChallenge(value) {
		c.challenge.set(value)
	}
}

func isUsableChallenge(value string) bool {
	if value == "" || len(value) > maxAttestationChallengeBytes {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// isAttestationChallengeError reports whether a response asks for a
// retry with the Challenge it carries: a use_attestation_challenge error
// with an OAuth-Client-Attestation-Challenge header (draft-12 §6.1),
// which postForm has already recorded for the rebuilt PoP to carry.
func isAttestationChallengeError(header http.Header, body []byte) bool {
	if header.Get(attestationChallengeHeader) == "" {
		return false
	}
	errResp, err := par.DecodeErrorResponse(body)
	return err == nil && errResp.Code == "use_attestation_challenge"
}

// challengeRetry reports whether a failed response from a DPoP-proofed
// request is a challenge the request is retried once for (RFC 9449 §8,
// draft-12 §6: "a Client SHOULD retry the request once"), and the DPoP
// nonce the retry carries: the one a use_dpop_nonce error supplies, or,
// for an attestation challenge, the server's newest or else nonce, the
// one the failed request carried.
func challengeRetry(header http.Header, body []byte, nonce string) (string, bool) {
	next := header.Get(dpopNonceHeader)
	if next != "" && isDPoPNonceError(body) {
		return next, true
	}
	if !isAttestationChallengeError(header, body) {
		return "", false
	}
	if next == "" {
		next = nonce
	}
	return next, true
}

// postFormWithAttestationChallenge posts form, and once more as rebuild
// builds it if the response is an attestation challenge (draft-12 §6.1)
// — for the senders that present no DPoP proof, and so have no nonce
// challenge to retry for.
func (c *Client) postFormWithAttestationChallenge(ctx context.Context, url string, form []byte, headers map[string]string, rebuild func() ([]byte, map[string]string, error)) ([]byte, int, http.Header, error) {
	body, status, header, err := c.postForm(ctx, url, form, headers)
	if err != nil || !isAttestationChallengeError(header, body) {
		return body, status, header, err
	}
	retryForm, retryHeaders, buildErr := rebuild()
	if buildErr != nil {
		return nil, 0, nil, fmt.Errorf("rebuild request for the attestation challenge: %w", buildErr)
	}
	return c.postForm(ctx, url, retryForm, retryHeaders)
}

// attestationHeaders builds the two Attestation-Based Client
// Authentication headers for one outbound request: the held Client
// Attestation JWT, fetched fresh via Dependencies.Attestation since
// this package never caches it itself, plus a freshly signed,
// single-use Client Attestation PoP JWT signed with the Client
// Instance Key (Dependencies.Keys, keys.ClientAttestationPoPSigning) —
// carrying a Challenge too: the server's most recent, or else one from
// Dependencies.Attestation, if it also implements ChallengeSource. The PoP is
// exactly as single-use as a DPoP proof or a private_key_jwt client
// assertion is (see ExchangeCode's own buildTokenForm doc comment), so
// this is called again for every retry rather than reused.
func (c *Client) attestationHeaders(ctx context.Context) (map[string]string, error) {
	attestation, err := c.deps.Attestation.CurrentAttestation(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve client attestation: %w", err)
	}
	challenge, err := c.currentAttestationChallenge(ctx)
	if err != nil {
		return nil, err
	}
	instanceSigner, _, err := c.newSigner(ctx, keys.ClientAttestationPoPSigning, c.cfg.Algorithms.ClientAttestationPoP)
	if err != nil {
		return nil, fmt.Errorf("resolve client attestation instance key: %w", err)
	}
	pop, err := clientattestation.CreatePoP(clientattestation.PoPCreateRequest{
		Signer: instanceSigner, Algorithm: c.cfg.Algorithms.ClientAttestationPoP,
		ClientID: c.cfg.ClientID, Audience: c.cfg.Issuer.String(),
		Now: c.deps.Clock.Now(), Random: c.deps.Random,
		Challenge: challenge,
	})
	if err != nil {
		return nil, fmt.Errorf("build client attestation PoP: %w", err)
	}
	return map[string]string{
		attestationHeader:    attestation,
		attestationPoPHeader: pop,
	}, nil
}

// currentAttestationChallenge returns the Challenge to put in the next
// PoP: the server's most recent, or else ChallengeSource's, or none.
func (c *Client) currentAttestationChallenge(ctx context.Context) (string, error) {
	if challenge := c.challenge.get(); challenge != "" {
		return challenge, nil
	}
	cs, ok := c.deps.Attestation.(ChallengeSource)
	if !ok {
		return "", nil
	}
	challenge, err := cs.CurrentChallenge(ctx)
	if err != nil {
		return "", fmt.Errorf("resolve attestation challenge: %w", err)
	}
	return challenge, nil
}

// ClientAttestationHeaders returns the OAuth-Client-Attestation and a
// fresh OAuth-Client-Attestation-PoP header values for a request this
// client sends to the authorization server outside the flows it
// implements — such as an OpenID4VCI pre-authorized_code token request —
// built exactly as its own PAR and token requests build them: the
// attestation from Dependencies.Attestation, and a single-use PoP signed
// with the Client Instance Key (keys.ClientAttestationPoPSigning) for
// this client's issuer, carrying a Challenge as attestationHeaders does.
// Call it again for every request, including retries. A Challenge the
// authorization server sends on a response to that request reaches the
// next PoP only through ObserveAttestationChallenge, since this client
// doesn't see the response.
//
// It requires Config.ClientAuthMethod to be
// storage.ClientAuthMethodAttestation.
func (c *Client) ClientAttestationHeaders(ctx context.Context) (attestation, pop string, err error) {
	if c.cfg.ClientAuthMethod != storage.ClientAuthMethodAttestation {
		return "", "", newError(ErrorInvalidRequest, "this client doesn't use attestation-based client authentication", nil)
	}
	headers, herr := c.attestationHeaders(ctx)
	if herr != nil {
		return "", "", newError(ErrorInternal, "failed to build the client attestation headers", herr)
	}
	return headers[attestationHeader], headers[attestationPoPHeader], nil
}

// ObserveAttestationChallenge keeps the Challenge an authorization
// server sent in header, the headers of a response to a request this
// client didn't send itself — one built with ClientAttestationHeaders —
// so the next PoP carries it (draft-12 §6.2). A response with no
// OAuth-Client-Attestation-Challenge header changes nothing, and so does
// one for a client that doesn't use attestation-based client
// authentication. On a use_attestation_challenge error, call it with the
// error response's headers, then ClientAttestationHeaders again for the
// one retry the draft allows.
func (c *Client) ObserveAttestationChallenge(header http.Header) {
	c.recordAttestationChallenge(header)
}
