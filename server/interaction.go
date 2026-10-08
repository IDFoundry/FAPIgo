package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/storage"
)

// interactionHandleSize is the byte length of a generated
// InteractionHandle — 256 bits, well beyond what's needed to make it
// unguessable, and deliberately unsuitable for reuse as an
// authorization code (a different value, from a different generator,
// bound to a different store record).
const interactionHandleSize = 32

// InteractionHandle identifies one in-progress authorization
// interaction. Only BeginAuthorization produces a new one — is
// high-entropy, bound to a single pushed authorization request, and
// expires per Config.Limits.InteractionLifetime. It must never be
// confused with, or substituted for, a request_uri or an authorization
// code: the login UI receives only this handle, never a storage
// primary key or the underlying PAR reference.
//
// Bind it to the browser that started the interaction. The handle
// identifies a pending authorization, not who may complete it, and
// CompleteAuthorization accepts it from whoever presents it. If the
// login UI round-trips it through a form field and authenticates the
// user from an existing session cookie, a malicious client can start
// its own authorization, place its handle in a form on its own page
// that submits itself, and have a victim's already-signed-in browser
// approve that authorization, so the client receives a code for the
// victim's account (consent CSRF, the authorization-server side of RFC
// 9700 §4.7's login CSRF). Keep the handle in an HttpOnly, Secure,
// SameSite cookie set when the browser reaches the authorization
// endpoint, read it back from that cookie (ParseInteractionHandle) when
// the login or consent form is submitted, and protect that form with
// the application's usual CSRF defence. Never accept the handle from
// a form field or query parameter alone. Package
// server/interactioncookie does this, carrying the InteractionRequest
// in the same encrypted cookie.
type InteractionHandle struct {
	value string
}

// String returns the handle's opaque wire value.
func (h InteractionHandle) String() string { return h.value }

// ParseInteractionHandle reconstructs the InteractionHandle
// BeginAuthorization originally returned, from its own wire value
// (InteractionHandle.String()) — for a consent-UI bridge that persists
// that value in its own distributed storage (a database, a signed
// cookie, a queue) rather than keeping it in this process's own
// memory, and needs to hand it back to CompleteAuthorization from a
// different request, goroutine, or instance than the one
// BeginAuthorization ran on. value must be exactly what
// InteractionHandle.String() produced; ParseInteractionHandle applies
// no format validation beyond rejecting an empty value — an
// unrecognized or expired handle is instead reported by
// CompleteAuthorization itself, the same as any other invalid one.
func ParseInteractionHandle(value string) (InteractionHandle, error) {
	if value == "" {
		return InteractionHandle{}, fmt.Errorf("server: interaction handle is empty")
	}
	return InteractionHandle{value: value}, nil
}

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
// authorization. BeginAuthorization returns it once; to show or complete
// the interaction on another instance, store it with MarshalText and
// restore it with ParseInteractionRequest, alongside the
// InteractionHandle's String form.
type InteractionRequest struct {
	ClientID fapi.ClientID
	Scope    []string
	Hints    AuthenticationHints

	// ACRValues are the Authentication Context Class References the
	// client asked for with "acr_values" (OIDC Core §3.1.2.1), most
	// preferred first: how strongly it wants the user authenticated.
	// They're a request, not a requirement: the application decides
	// which class its authentication satisfies, and reports it as the
	// acr of NewAuthenticationContext, which the ID token carries.
	ACRValues []string

	// EssentialACRValues are the Authentication Context Class
	// References the client requested as an essential "acr" claim for
	// the ID token, through the "claims" parameter (OIDC Core
	// §5.5.1.1), most preferred first. Unlike ACRValues they are a
	// requirement: authenticate the user at one of these classes and
	// report it as NewAuthenticationContext's acr. CompleteAuthorization
	// enforces it: an Authorize whose acr isn't one of them answers the
	// client with login_required, the failed authentication OIDC Core
	// §5.5.1.1 calls for, and issues no code. Nil when the request made
	// no such demand.
	EssentialACRValues []string

	// MaxAge is the client's "max_age" (OIDC Core §3.1.2.1), when
	// HasMaxAge: the most time that may have passed since the user last
	// actively authenticated. If the application's last authentication
	// of this user is older, it must authenticate them again before
	// authorizing. CompleteAuthorization enforces it: an Authorize whose
	// authentication time is older than MaxAge plus Limits.MaxClockSkew
	// answers the client with login_required. HasMaxAge distinguishes
	// max_age=0, which asks for a fresh authentication every time, from
	// no max_age at all.
	MaxAge    time.Duration
	HasMaxAge bool

	// Prompt is the client's "prompt" (OIDC Core §3.1.2.1): how the
	// application should interact with the end user. The server can't
	// tell what the application showed, so honouring it is the
	// application's job:
	//
	//   - PromptNone: show no authentication or consent page. Complete
	//     with Authorize only if the end user already has a session and
	//     has already consented to this; otherwise complete with
	//     InteractionNeeded (NeedLogin, NeedConsent, NeedAccountSelection
	//     or NeedInteraction), which answers the client with the matching
	//     error. A pushed request combining "none" with another value is
	//     refused, so it never reaches here.
	//   - PromptLogin: authenticate the end user again even if they have
	//     a session, and report that authentication's time in
	//     NewAuthenticationContext; if they can't be, complete with
	//     AuthenticationFailed (login_required). CompleteAuthorization
	//     enforces it: an Authorize whose authentication time is earlier
	//     than when the request was pushed, less Limits.MaxClockSkew,
	//     answers the client with login_required, as an existing
	//     session's time would.
	//   - PromptConsent: ask for consent even if it was given before.
	//   - PromptSelectAccount: let the end user choose an account.
	//
	// Values another specification defines arrive as sent.
	Prompt Prompt

	// ClientDisplay is what the consent screen can show about the client
	// (name, logo, policy and terms links) — from its registration, or,
	// for a client registered automatically through OpenID Federation,
	// from its own published metadata. See storage.ClientDisplay: the
	// client chose these values, so show ClientID alongside them.
	ClientDisplay storage.ClientDisplay

	// AuthorizationDetails holds the request's own validated Rich
	// Authorization Requests (RFC 9396) detail objects, if any were
	// requested and Config.RAR is configured — zero value otherwise. A
	// consent UI reads a specific type back out with
	// extension.RARGet(interaction.AuthorizationDetails, YourRARDefinition)
	// to render exactly what's being authorized (e.g. "Approve submission
	// of Tax Return TX-12345") instead of a bare scope string.
	AuthorizationDetails extension.RARValues

	// RequestedClaims is the identity claims the client asked for with
	// the "claims" parameter. None is released unless the application
	// approves it in GrantedAuthorization.ApprovedIdentityClaims.
	RequestedClaims RequestedClaims

	// Extensions holds the request's registered extension parameter
	// values (Config.Extensions), validated at the pushed authorization
	// request — whether they arrived as plain parameters or inside a
	// signed request object. A consent step reads one back with
	// extension.Get(interaction.Extensions, YourDefinition): an OID4VCI
	// Credential Issuer's issuer_state, for example, to know which
	// pending issuance is being approved. Every registered value is
	// readable here, independent of ReturnInTokenClaims, which governs
	// only what leaves the server in a token.
	Extensions extension.Values
}

// interactionExtensions reads back the registered extension values in
// params — validated when the request was made — for the interaction
// step, as source (request object or plain parameters) validated them.
// It parses a copy, since Registry.Parse drops unregistered names in
// place. A zero source, from a record stored before the source was
// recorded, yields no values rather than failing a request in flight
// across an upgrade.
func (s *Server) interactionExtensions(params map[string]json.RawMessage, core map[string]struct{}, source extension.Source) (extension.Values, error) {
	if source == 0 {
		return extension.Values{}, nil
	}
	copied := make(map[string]json.RawMessage, len(params))
	for k, v := range params {
		copied[k] = v
	}
	return s.cfg.Extensions.Parse(copied, core, source)
}
