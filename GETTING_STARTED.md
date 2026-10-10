# Getting started: standing up an authorization server, resource server and client

This walks through wiring `server.Server` end to end — configuration,
dependencies, client registration, and the one piece every integration
has to build itself: the login/consent flow — then through wiring
`resource.Verifier`, the separate role that actually verifies a
presented access token against a protected API (step 7), and finally a
`client.Client` that calls them (step 10). `cmd/conformance-as`
is a complete, working reference implementing every piece described
here (step 6 shows a minimal HTTP surface — PAR, authorize, token,
JWKS, metadata — and it has the full one); read it alongside this doc,
or just study it directly and treat this as the map.

## 1. Dependencies: use the reference implementations to start

`server.New` requires eleven dependencies — a client repository,
transaction/grant/replay stores, a key manager, a client key source, an
access-token issuer, a revocation sink, a client-certificate trust
choice, a clock, a randomness source — with no implicit defaults for
any of them (plus an audit sink, required
only under `AssuranceProduction` — see step 2's `Assurance` field).
Writing real, production-shaped persistence and key management for all
of that is real work, and not the place to start. Two packages exist
specifically so you don't have to do it before you can run anything:

- **`storage/memstore`** — in-memory `ClientRepository`, `TransactionStore`,
  `GrantStore`, `ReplayStore`, `RevocationStore`, and `AccessTokenStore`
  (only needed for opaque access tokens — see step 4), plus the stores
  for features you turn on later: `BackchannelAuthenticationStore` (CIBA),
  `NonceStore` (DPoP nonces) and, on the relying-party side,
  `SessionStore`.
- **`keys/ephemeral`** — in-memory `KeyManager` and `ClientKeySource`.

**Both are development/testing only. Never production** — see each
package's own doc comment for exactly why (non-durable, no expiry GC,
keys regenerated and lost on every restart). `server.New` already
refuses both under `server.AssuranceProduction` — `memstore`'s stores
don't implement `storage.StoreAssurance` and `ephemeral`'s key manager
doesn't implement `keys.KeyCustodyAssurance`, which that assurance
level requires — and `client.New` refuses `ephemeral` keys the same way.
That's not a gap, it's what stops them from being used in production
by accident. When you're ready for a real deployment, this
is the seam: implement the same interfaces (`storage.ClientRepository`
and friends, `keys.KeyManager`, `keys.ClientKeySource`) against real
persistence and a real key store (KMS/HSM), and swap them in — nothing
else in this guide changes. For `keys.KeyManager` specifically, you may
not need to implement anything at all: `keys.NewKeyManagerFromSigners`
adapts any `crypto.Signer` — what most HSM/KMS Go client wrappers
already implement — directly into a `KeyManager`, one `keys.SignerSpec`
per signing purpose (its algorithm, signer and kid, and any previous
keys still to be published during a rotation); see `keys/doc.go`.
Pass it `keys.DeclareCustody(keys.KeyCustody{Durable: true})` (plus
`CrossInstanceConsistent` if every instance shares the keys) to state
how those keys are held — production assurance requires the
declaration, and only you know the answer.

## 2. Build a `Config`

Every field below is required — `server.New` rejects a zero value for
any of them, on purpose (see `server/doc.go`: "no implicit defaults, no
silently-installed in-memory store"). `Algorithms` and `Limits` hold
many fields with no sane universal default, so
`server.RecommendedAlgorithms()` and `server.RecommendedLimits()` exist
as an explicit, deliberate starting point — each field is documented
with exactly how it's grounded (a direct FAPI 2.0 Security Profile Final
or RFC 9449 requirement, versus this module's own conservative
operational choice, clearly labeled either way — see `server/presets.go`).
Calling them is as much a choice as writing the values yourself; `New`
never reaches for them on its own. Override any field your own security
policy calls for.

```go
cfg := server.Config{
	Issuer: issuer, // fapi.ParseIssuerURL("https://as.example.com")
	Endpoints: server.Endpoints{
		Authorization:              authorizeURL,
		Token:                      tokenURL,
		PushedAuthorizationRequest: parURL,
		JWKS:                       jwksURL,
	},
	Profile:    server.ProfileFAPISecurity, // or ProfileFAPISecurityWithMessageSigning
	Algorithms: server.RecommendedAlgorithms(),
	Limits:     server.RecommendedLimits(),
	Assurance:  server.AssuranceDevelopment, // AssuranceProduction once your real deps are ready
	// Deployment: server.DeploymentSingleInstance, // required under AssuranceProduction: or DeploymentHorizontallyScaled for a fleet
}
```

Under `ProfileFAPISecurityWithMessageSigning`, `Algorithms.JARM` is
required too.

Most `Limits` fields are lifetimes and clock tolerances. One is a size:
`Limits.MaxIDTokenClaimsBytes` (4096 in `RecommendedLimits()`) caps the
total size of the non-standard claims in an ID token, so the server
never issues one larger than relying parties accept — this module's own
client rejects a compact token over 16 KiB by default. See [Adding
claims to tokens](#adding-claims-to-tokens) for what counts against it,
and raise it only alongside your relying parties' own limits.

## 3. Register at least one client

```go
client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
	ID:                       "demo-client",
	RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example.com/callback"},
	ClientAssertionAlgorithm: fapi.ES256,
	AllowedScopes:            []string{"openid", "accounts"},
})
```

`"openid"` isn't required by this library at all: an ID token is only
ever issued alongside the access token when the *granted* scope happens
to include `"openid"` (see `server`'s own package doc comment) — this
walkthrough includes it, and wires `keys.IDTokenSigning` in step 4,
purely because that's the more complete example to show. A deployment
that only needs access tokens — no identity layer — can drop `"openid"`
from `AllowedScopes` entirely and run as plain OAuth 2.0 + FAPI 2.0;
nothing else here changes.

A mobile or desktop app — a wallet, say — registers with
`ApplicationType: storage.ApplicationTypeNative`. It may then use the
redirect URIs RFC 8252 gives native apps, in production too: a
private-use scheme in reverse-domain form
(`com.example.wallet:/callback`), or loopback http to `127.0.0.1` or
`[::1]`, which matches on whatever port the app listens on. Write the
private-use form with a single slash, as RFC 8252 §7.1 does:
`com.example.wallet:/callback`, not `com.example.wallet://callback`,
which is refused. In
production a web client can use neither; under development assurance
it may use loopback http, matched exactly. On the relying-party side, a desktop app
that listens on a port the operating system picks for each flow sets
`Config.RedirectURI` to the port-less loopback URI and passes the port
as `client.BeginAuthorizationRequest.RedirectPort`. A native client still authenticates like any
other: give each app instance its own credentials, as attestation-based
client authentication does. The rest of the native app's side — keys in
the platform key store, an on-device session store, completing after
the app is relaunched, token storage — is in `client`'s package doc,
under "Native apps".

## 4. Wire `Dependencies` and construct the server

```go
keyManager, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
	keys.AccessTokenSigning: fapi.ES256,
	keys.IDTokenSigning:     fapi.ES256,
})

clientKeys, err := ephemeral.NewClientKeySource(fetcher, []ephemeral.ClientKeySpec{
	{ClientID: "demo-client", JWKS: theClientsJWKSDocument},
	// or JWKSURI: "https://rp.example.com/.well-known/jwks.json" to fetch live instead
})

// JWT (RFC 9068) is the default, ship-in-the-box access-token format —
// self-contained, verified locally by a resource server against this
// AS's published JWKS, with no callback to this AS at verify time.
// server.NewOpaqueAccessTokens(store) is the storage-backed
// alternative — e.g. a resource server co-located with this AS, or one
// with live access to the same storage backend. This is not a
// revocation-related choice: Dependencies.Revocation below is required
// and wired identically either way.
accessTokens, err := server.NewJWTAccessTokens(keyManager, fapi.ES256)

deps := server.Dependencies{
	Clients:      memstore.NewClientRepository([]storage.RegisteredClient{client}),
	Transactions: memstore.NewTransactionStore(),
	Grants:       memstore.NewGrantStore(),
	Replay:       memstore.NewReplayStore(),
	ClientKeys:   clientKeys,
	Keys:         keyManager,
	AccessTokens: accessTokens,
	// Lets this server revoke a token it already issued when it later
	// detects the authorization code that produced it being reused
	// (RFC 6749 §4.1.2), and revoke a whole grant with RevokeGrant
	// (step 5). Pass server.NoRevocation{} instead to explicitly
	// decline — see its doc comment for why declining must be a
	// conscious choice, not a silent default; RevokeGrant then refuses.
	Revocation: memstore.NewRevocationStore(),
	// Whether this package re-verifies an mTLS client certificate's
	// chain itself. NoClientCertificateChainTrust{} declines — right when
	// no client uses mTLS, or when your TLS termination already verifies
	// the chain; server.TrustedClientCAs{Roots: pool, Revocation: ...}
	// has this package check it against pool, and whether it has been
	// revoked (server.ClientCertificateCRLs, for example), instead.
	ClientCertificateTrust: server.NoClientCertificateChainTrust{},
	Clock:                  server.SystemClock{},
	Random:                 rand.Reader, // crypto/rand; production assurance requires exactly this reader
}

srv, err := server.New(cfg, deps)
```

(`fetcher` is a `*fapihttp.Client` — only needed if any client's keys
are fetched live via `JWKSURI` rather than supplied inline; pass `nil`
if every client uses inline `JWKS`. Build one with
`fapihttp.New(transport, fapihttp.RecommendedConfig())`, where
`transport` comes from
`fapihttp.NewClient(fapihttp.RecommendedTransportConfig())`.)

**Whichever access-token format you pick here, the resource server that
verifies these tokens must be wired to match** — `resource.JWTAccessTokens`
for `server.JWTAccessTokens`, `resource.OpaqueAccessTokens{Store: ...}`
(the same `Store` instance, if co-located) for
`server.OpaqueAccessTokens` — see step 7. The two sides agreeing on
format isn't checked for you: nothing stops you from constructing an AS
that issues opaque tokens and a resource server that only knows how to
verify JWTs, and every verification will fail with no compile-time
signal that they were ever mismatched. `cmd/conformance-as/wiring.go`
shows both sides wired consistently, switched on one runtime flag.

## 5. The one piece that's genuinely yours: the login flow

Everything above is config and plumbing. This is the actual decision
point, and the library deliberately has zero opinion about it — no
bundled login page, no assumed auth method. `BeginAuthorization`
(called from your `/authorize` handler once a client's pushed request
has been redeemed) returns one of three outcomes; the one that matters
here is `InteractionRequired`:

```go
// The request's client_id and request_uri, refusing a repeated one:
// render that error locally, never as a redirect.
req, err := server.BeginAuthorizationRequestFromHTTP(r)
if err != nil {
	// render err locally
}
action, err := srv.BeginAuthorization(ctx, req)

switch a := action.(type) {
case server.InteractionRequired:
	// Render whatever UI you want here — a password form, an SSO
	// redirect, WebAuthn, a magic link. a.Interaction carries the
	// client ID, requested scope, an unauthenticated login_hint to
	// help pre-fill it, and the client's authentication requirements:
	// ACRValues (how strongly to authenticate) and, when HasMaxAge,
	// MaxAge (how recent the authentication must be — re-authenticate
	// a user whose existing session is older). a.Interaction.Prompt is
	// the client's "prompt": for server.PromptLogin, authenticate the
	// user again even if they have a session; for server.PromptNone,
	// show nothing, and if you'd need to, complete with
	// server.InteractionNeeded(server.NeedLogin, ...) (or NeedConsent,
	// NeedAccountSelection, NeedInteraction). When
	// a.Interaction.RequiredSubject isn't empty, the client named the
	// user (by id_token_hint or a "sub" claims value): authenticate
	// that user, or CompleteAuthorization answers login_required.
	// a.Interaction.UILocales, ClaimsLocales and Display are the
	// client's presentation preferences: render the page in the first
	// UILocales language you have. a.Handle must come back to
	// CompleteAuthorization once the user is done.
case server.RedirectResponse:
	// no interaction needed — redirect the browser to a.Destination
case server.LocalErrorResponse:
	a.Error.WriteText(w) // render locally: code and public description only
}
```

Treat the request_uri in the authorization URL as a bearer value
until the interaction completes: whoever holds it can begin the
client's authorization, and complete it as themselves (FAPI 2.0
Security Profile §6.4). `BeginAuthorization` accepts it more than once,
so a reload or a browser's prefetch doesn't use it up, but only one
interaction for it can complete. Serve the login page with
`Referrer-Policy: no-referrer` and no third-party scripts or images,
and don't log full `/authorize` URLs.

Once you've actually authenticated the user (checked their password,
verified their SSO assertion, whatever), conclude the interaction:

```go
subjectID, _ := server.NewSubjectID(theRealAuthenticatedUserID)
subject, _ := server.NewAuthenticatedSubject(subjectID)
// When the user actually authenticated — not time.Now() when you reuse
// an existing session: CompleteAuthorization answers login_required
// when this is older than the client's max_age, or, for prompt=login,
// earlier than the request itself.
authCtx, _ := server.NewAuthenticationContext(userAuthenticatedAt, acr, amr)

result := server.Authorize(subject, authCtx, server.GrantedAuthorization{
	Scope: whateverScopesTheUserActuallyApproved,
	// Optional: extra claims for the ID token only (never the access
	// token), each value already JSON-encoded. Server-managed names
	// (iss, sub, aud, nonce, acr, ...) are rejected.
	IDTokenClaims: map[string]json.RawMessage{"sub_type": json.RawMessage(`"user"`)},
	// Identity claims the client asked for with the OIDC "claims"
	// parameter (a.Interaction.RequestedClaims) that the user agreed to
	// release. Nil releases none.
	ApprovedIdentityClaims: whicheverRequestedClaimsTheUserApproved,
	// Optional: your own ID for this grant, to withdraw it later with
	// srv.RevokeGrant — for a "connected apps" page, say. It refuses
	// the grant's refresh token and every access token issued from it.
	GrantID: yourOwnIDForThisGrant,
})
// or: server.Deny("user declined") / server.AuthenticationFailed("bad credentials")

authResult, err := srv.CompleteAuthorization(ctx, server.CompleteAuthorizationRequest{
	Handle: handle, // the same InteractionHandle from step above
	Result: result,
})

switch res := authResult.(type) {
case server.AuthorizationRedirect:
	// carries the code (or an error); 303, never 307, after the form's POST
	http.Redirect(w, r, res.Destination().String(), http.StatusSeeOther)
case server.AuthorizationLocalError:
	res.Error.WriteText(w) // render locally: code and public description only
}
```

Redirect with **303 See Other** after the login or consent form's POST,
so the browser follows with a GET (FAPI 2.0 Security Profile §5.3.2.2).
A 307 would make it re-send the form, password included, to the
client's redirect URI (RFC 9700 §4.12). And never render a
`*server.Error`'s `Error()`: it carries internal causes, such as a
store's own error, and is meant for logs. `WriteText` (or `WriteJSON`
at a JSON endpoint) writes only its `Code` and `PublicDescription`.

**Carry the interaction to the form's submission.** The consent form's
submission needs two things from `/authorize`: the handle, bound to this
browser, and `a.Interaction`. `server/interactioncookie` carries both in
one encrypted cookie:

```go
cookie, err := interactioncookie.New(cookieKeys, interactioncookie.Options{}) // once; cookieKeys shared by every instance

// GET /authorize, on server.InteractionRequired:
tag, err := cookie.Set(w, a, now) // render tag in the form, as interactioncookie.FormField

// POST, the form's submission (behind your CSRF protection), after r.ParseForm():
handle, interaction, err := cookie.Read(r, now, r.PostForm.Get(interactioncookie.FormField))
// ...CompleteAuthorization with handle, then cookie.Clear(w)
```

The cookie expires with the handle (`a.ExpiresAt`), so pass `now` from
the clock the server uses. The tag matters because a browser holds one
cookie of a name: a second authorization in the same browser — another
tab, or a page that sends the browser to `/authorize` for a client of
its own — replaces the first's cookie, and without the tag the first
page's form would approve the second authorization. With it, that form
gets `ErrNoInteraction` and the user starts again. It's AES-GCM under
keys every instance shares (the first seals, all open, so keys rotate),
with the `__Host-` prefix. An interaction too large for a cookie —
large authorization details, say — gets `ErrTooLarge`: keep that one in
a server-side session instead. It's no CSRF defence: the form still
needs one. The demos under `examples/` use it.

Keeping the interaction somewhere else — a server-side session — means
doing yourself the two things the package does:

**Bind the interaction handle to the browser.** `CompleteAuthorization`
accepts a handle from whoever presents it, so a login UI that carries it
in a form field and signs users in from an existing session cookie is
open to consent CSRF: a malicious client starts its own authorization,
puts its handle in a self-submitting form on its own page, and a
signed-in victim's browser approves it, sending that client a code for
the victim's account. Set the handle (`a.Handle.String()`) in an
HttpOnly, Secure, SameSite cookie when the browser reaches `/authorize`,
read it back with `server.ParseInteractionHandle` when the form is
submitted, and protect that form with your usual CSRF defence. Tie the
form to the handle it was rendered for, too, as the package's tag does:
a second authorization in the same browser replaces the cookie, and the
first page's form mustn't complete the second. See
`server.InteractionHandle`'s doc comment.

**Keep the interaction until the form comes back.** The submission
needs `a.Interaction` again: the scope, the requested claims and any
authorization details the user is approving. Encode it with
`a.Interaction.MarshalText()` and keep it with the handle, somewhere only
your application can write: a server-side session, or a cookie you
seal. Restore it with `server.ParseInteractionRequest`. Then any
instance can handle the submission, not only the one that began the
authorization. A modified copy can't widen the grant, since
`CompleteAuthorization` checks it against the request the server
stored.

`cmd/conformance-as/authorize.go` is a complete, working version of
exactly this — read it for the full picture of the GET (render the
form) and POST (handle the submission) halves of a real HTTP flow. Its
handle bridge is not one to copy: it carries the handle in a hidden form
field, which is only tolerable because it authenticates nobody — use
the cookie binding above instead. Its own login form
(`consent_template.go`) is a deliberate non-example: a free-text "type
any username" field with no real authentication behind it, because this
binary exists to drive OIDF conformance testing, not to demonstrate
login UI. Building the real authentication step is the one part of this
whole guide that's actually yours to write.

### Adding claims to tokens

Beyond the standard claims (`iss`, `sub`, `aud`, `acr`, `amr`, ...),
there are three ways a claim gets into a token. They differ in who
decides and where the claim lands, so pick by what you need:

| You want to... | Use | Lands in |
|---|---|---|
| Add claims you decide at login (e.g. a subject type, or who is acting on an entity's behalf) | `GrantedAuthorization.IDTokenClaims` | ID token only |
| Return identity claims (`name`, `email`, ...) the client asks for via the OIDC `claims` parameter, once the user approves them | `Dependencies.IdentityClaims` (`server.IdentityClaimsSource`) plus `GrantedAuthorization.ApprovedIdentityClaims` | ID token and/or UserInfo, per request |
| Carry a value the client sent as a custom authorization request parameter | `extension.Definition` with `ReturnInTokenClaims` | Access token and ID token |

`IDTokenClaims` values are JSON-encoded, and server-managed names
(`iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `auth_time`, `acr`, `amr`,
`at_hash`, `azp`, `c_hash`, `s_hash`, `jti`, `nbf`, `cnf`), along with
names that change how a relying party processes the token
(`_claim_names`, `_claim_sources`, `sub_jwk`, `events`), are rejected.
Identity claims only ever add the names the client requested and the
user approved, never a server-managed one. On a name
collision the more specific source wins: `IDTokenClaims` over identity
claims over extension claims. All three are carried forward to ID
tokens re-issued on refresh, with no storage change on your side.

All three share one size budget, `Limits.MaxIDTokenClaimsBytes` (each
claim's name plus its JSON-encoded value). `CompleteAuthorization`
rejects `IDTokenClaims` that exceed it on their own, before anything is
stored; the token endpoint rejects the merged total, as `server_error`,
if identity or extension claims push it over — identity claims are only
resolved there.

## 6. The rest of the HTTP surface

`server.Server` has no built-in HTTP layer — every endpoint is a plain
handler you write, calling the corresponding method
(`PushAuthorizationRequest`, `ExchangeAuthorizationCode`,
`RefreshAccessToken`, `Metadata`, `PublicJWKS`, and, when you enable
them, `RequestClientCredentialsToken` and the CIBA methods). `cmd/conformance-as/router.go`
shows the complete routing table on a bare `net/http.ServeMux` — no
framework dependency required, though nothing here stops you from using
one. `cmd/conformance-as/token.go`, `par.go`, `metadata.go` and
`jwks.go` are the corresponding handler implementations to read
alongside `authorize.go`.

A minimal version, for a server whose `Config.Endpoints` use these
paths — every handler reads its request with a `*FromHTTP` constructor
and writes its response with the result's own `WriteJSON` (or
`server.WriteError`):

```go
func routes(srv *server.Server, login func(http.ResponseWriter, *http.Request, server.InteractionRequired)) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /par", func(w http.ResponseWriter, r *http.Request) {
		req, err := server.PushAuthorizationRequestFromHTTP(r)
		if err != nil {
			server.WriteError(w, err)
			return
		}
		result, err := srv.PushAuthorizationRequest(r.Context(), req)
		if err != nil {
			server.WriteError(w, err)
			return
		}
		result.WriteJSON(w) // 201 with request_uri and expires_in
	})

	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		req, err := server.BeginAuthorizationRequestFromHTTP(r)
		if err != nil {
			http.Error(w, "invalid authorization request", http.StatusBadRequest) // a local page, never a redirect
			return
		}
		action, err := srv.BeginAuthorization(r.Context(), req)
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		switch a := action.(type) {
		case server.InteractionRequired:
			login(w, r, a) // step 5: authenticate, then CompleteAuthorization(a.Handle, ...)
		case server.RedirectResponse:
			http.Redirect(w, r, a.Destination.String(), http.StatusFound)
		case server.LocalErrorResponse:
			a.Error.WriteText(w) // render locally; nothing here is safe to redirect to. Never a.Error.Error(): it carries internal causes
		}
	})

	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		req, err := server.TokenEndpointRequestFromHTTP(r)
		if err != nil {
			server.WriteError(w, err)
			return
		}
		var result server.TokenResult
		switch req.GrantType() {
		case "authorization_code":
			result, err = srv.ExchangeAuthorizationCode(r.Context(), req.AuthorizationCodeExchange())
		case "refresh_token":
			result, err = srv.RefreshAccessToken(r.Context(), req.RefreshToken())
		default:
			err = server.NewError(server.ErrorUnsupportedGrantType, http.StatusBadRequest, "")
		}
		if err != nil {
			server.WriteError(w, err)
			return
		}
		result.WriteJSON(w)
	})

	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		set, err := srv.PublicJWKS(r.Context())
		if err != nil {
			server.WriteError(w, err)
			return
		}
		set.WriteJSON(w)
	})

	// Where client.Discover looks: the issuer plus this suffix.
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		srv.Metadata(r.Context()).WriteJSON(w)
	})
	return mux
}
```

Add `POST /authorize/complete` (or wherever your login page posts) for
`CompleteAuthorization` from step 5, and the CIBA, client credentials and
revocation routes when you enable them.

**What the HTTP layer owes FAPI 2.0.** These are yours, not the
package's (FAPI 2.0 Security Profile §5.2):

- **TLS everywhere**, version 1.2 or later with BCP 195's recommended
  cipher suites. `&tls.Config{MinVersion: tls.VersionTLS12,
  CipherSuites: server.FAPIRWTLSCipherSuites}` is what
  `cmd/conformance-as` serves: a narrower list, the one the OpenID
  conformance suite checks. Behind a proxy that terminates TLS, the
  proxy must follow them instead.
- **HSTS** on every endpoint a browser reaches: the authorization
  endpoint and your login and consent pages
  (`Strict-Transport-Security: max-age=31536000`, say).
- **No CORS on the authorization endpoint** or the pages behind it.
  They are navigations, never fetches, so send no
  `Access-Control-Allow-Origin` there. (The token, PAR, JWKS and
  discovery endpoints may allow CORS for browser-based clients.)

**Serving a grant this package doesn't.** To serve another grant type
at the same token endpoint — OpenID4VCI's `pre-authorized_code`, say —
read the request once with `server.TokenEndpointRequestFromHTTP` and
switch on `GrantType()`. For your own grant, take its form with
`Parameters()`, authenticate the client with `AuthenticateAttestedClient`
(`req.AttestedClientAuthentication()`) — the only client authentication
offered for a grant you serve, so its clients register for
attestation-based client authentication — and check its DPoP proof or
client certificate with `VerifyTokenRequestBinding`: the same checks,
and the same replay records, as this package's own grants. List the
grant type in `Config.AdditionalGrantTypes` so `Metadata` advertises
it. Whether the client may use the grant, and the grant itself, stay
yours. To let the client refresh what it was granted, pass the
authenticated client and the binding to `IssueRefreshToken` and return
the token as `refresh_token`: `RefreshAccessToken` then redeems it like
its own, bound to the client's instance key. Such a grant may not
include `openid`, since no user authenticated.

**Letting clients revoke their refresh tokens.** Set
`Config.Endpoints.Revocation` and serve it with `RevokeToken`, reading
the request with `server.TokenRevocationRequestFromHTTP`: a nil error
is a 200 with an empty body, otherwise write the `*Error`. `Metadata`
then advertises `revocation_endpoint`, and a `client.Client` revokes
with `RevokeToken`, which `Discover` wires up. A client can only revoke
its own refresh tokens (and, when authenticated by Client Attestation,
only its own installation's); revoking one also revokes its grant by
`GrantID`, so give each grant its own ID, and, with a revocation store
your resource servers read, every access token issued from the same
authorization code. The `TokenRevocationResult`
`RevokeToken` returns names that grant when a client ends it, so you can
delete anything you kept for it at once; it's for you only, and the
response stays the same empty 200. Access tokens can't be revoked: one
in JWT form, or a token sent with `token_type_hint=access_token` that
isn't one of the client's refresh tokens, gets `unsupported_token_type`
(an opaque access token sent without a hint is answered like any other
unknown token, with the same empty 200). They expire on their own, and
`RevokeGrant` ends them early.

**Reading an ID token hint elsewhere.** For a flow outside this package
that takes an `id_token_hint`, such as an RP-Initiated Logout endpoint,
`Server.VerifyIDTokenHint` checks that the hint is an ID token this
server issued to the requesting client and returns its subject. It
accepts an expired hint, as OpenID Connect requires, so the subject says
whose session to act on, never that anyone is logged in now.

## 7. Wire the resource server: verifying access tokens

`resource.Verifier` is FAPI 2.0's third role, a deliberately separate
package from `server` rather than a mode of it — verifying a presented
access token is inseparable from the HTTP request it arrived on, so
`Verify(ctx, VerifyRequest{Method, URL, Authorization, DPoPProofs, PeerCertificate})` is
the only entry point, never a bare `VerifyJWT`. In a real deployment
this is usually a wholly separate service protecting its own API;
`cmd/conformance-as` only co-locates it in the same binary because the
OIDF suite's AS test plan needs a protected-resource endpoint to call
(`resource.go`) — read that file alongside this section either way.

### Build a `Config`

```go
cfg := resource.Config{
	Limits: resource.Limits{
		MaxDPoPProofAge: time.Minute,     // how old a DPoP proof's iat may be
		MaxClockSkew:    5 * time.Second, // tolerance either direction
	},
	Assurance: resource.AssuranceDevelopment, // AssuranceProduction once your real deps are ready
	// Deployment: resource.DeploymentSingleInstance, // required under AssuranceProduction: or DeploymentHorizontallyScaled for a fleet
}
```

All three are required — `NewVerifier` rejects a zero `MaxDPoPProofAge`,
a negative `MaxClockSkew` or a zero `Assurance`, the same "no implicit
default" discipline `server.Config` follows. As with the server,
`resource.AssuranceProduction` refuses `memstore`'s stores and
`keys/ephemeral`'s key sources: it requires the issuer key source to
declare `keys.KeySourceAssurance` (`keys.LocalIssuerKeys` does, and so
does `keys.JWKSIssuerKeySource` on a `fapihttp` client without a loopback
exception), the opaque-token, replay, nonce and
revocation stores to declare `storage.StoreAssurance` (unless revocation
is `resource.NoRevocation{}`), and `crypto/rand.Reader` when DPoP
nonces are on. It also requires `Deployment`:
`resource.DeploymentSingleInstance`, or
`resource.DeploymentHorizontallyScaled` when more than one instance
shares the stores, which then must also declare
`CrossInstanceConsistent`.

### Wire `Dependencies`

**Hosting the protected endpoints in the authorization server's own
process** (a UserInfo endpoint, say)? Then skip the rest of this
section: `serverresource.NewVerifier` builds the verifier from the
`server.Config` and `server.Dependencies` step 4 built, taking the
access-token format, revocation store, replay store, clock and DPoP
limits from them so they always match, and failing if the revocation
store can't be checked from the resource side:

```go
// cfg and deps: the server.Config and server.Dependencies from steps 2 and 4.
verifier, err := serverresource.NewVerifier(cfg, deps, serverresource.Options{})
```

It checks the verifier at the server's own `Assurance` and
`Deployment`, so a production server gets a production verifier.

A resource server deployed on its own wires `Dependencies` itself:

**The access-token format must match whatever the authorization server
actually issues** — this is exactly the coupling step 4 flagged, and
the reason this section exists at all. Pick the side matching your AS:

```go
// If the AS issues JWTAccessTokens: resolve its verification key(s),
// typically by fetching its published JWKS live (or, for a resource
// server in the AS's own process, keys.NewLocalIssuerKeys(issuer,
// keyManager), which reads the AS's key manager directly).
issuerKeys, err := keys.NewJWKSIssuerKeySource(fetcher, asJWKSURL, 10*time.Minute)
accessTokens, err := resource.NewJWTAccessTokens(
	issuerKeys, asIssuer, asIssuer.String(), // audience: matches server/accesstoken.go's own self-addressed aud claim
	fapi.ES256, 5*time.Minute, // must be >= the AS's own Limits.AccessTokenLifetime
	8, // max candidate keys tried per token — size to your AS's own key-rotation overlap, not a library default
)

// If the AS issues OpaqueAccessTokens instead: the *same*
// storage.AccessTokenStore instance the AS writes to — only realistic
// if this resource server shares that storage backend with the AS
// (co-located, or a real shared database).
// accessTokens, err := resource.NewOpaqueAccessTokens(sameAccessTokenStore)
```

`asIssuer`/`asJWKSURL` are the authorization server's own issuer/JWKS
`fapi.URL` values — the same `issuer`/`Endpoints.JWKS` step 2 built, if
this resource server is co-located with that AS; otherwise wherever
that AS's own metadata publishes them.

`Dependencies.Revocation` needs the same care as the access-token
format: if the AS revokes a token on detected authorization-code reuse
(RFC 6749 §4.1.2 — step 4's `Revocation` field), or revokes a whole
grant with `RevokeGrant`, this resource server must see that revocation
too, or it will keep accepting a token the AS has already disowned. Wire it to the *same* `RevocationSink`/
`RevocationChecker` pair the AS uses — `memstore.NewRevocationStore()`
already implements both, if co-located — or `resource.NoRevocation{}`
to explicitly decline (matching `server.NoRevocation{}`'s own
reasoning for why declining must be a conscious choice).

```go
deps := resource.Dependencies{
	AccessTokens: accessTokens,
	Replay:       memstore.NewReplayStore(), // DPoP proof jti reuse — its own instance; may differ from the AS's
	Revocation:   revocationStore,           // the same instance the AS writes to
	Clock:        resource.SystemClock{},
}

verifier, err := resource.NewVerifier(cfg, deps)
```

### Verify a request

```go
// protectedResourceURL: this endpoint's own fixed external URL — see
// below, never r.URL.
authCtx, err := verifier.Verify(ctx, resource.VerifyRequestFromHTTP(r, protectedResourceURL))
```

On success, `authCtx.Subject`/`ClientID`/`Scopes`/`Claims` are what your
API handler needs to authorize the call. Call
`authCtx.SetDPoPNonce(w.Header())` on the response, so a client's next
call already carries a fresh DPoP nonce when you've enabled them. A
UserInfo endpoint hosted with the authorization server builds its
response with `serverresource.UserInfoClaims(ctx, authCtx,
identityClaims)`: only the claims the client requested and the user
approved, plus `sub`. On failure, `err` is always a
`*resource.Error`, and `resource.WriteError` sends it as the RFC 6750 /
RFC 9449 response: the status, a `WWW-Authenticate` challenge in the
scheme the request used, and the error body. A request with no
credentials at all gets 401 and a challenge with no error code, as RFC
6750 §3.1 asks. `Unwrap()` is for logs only, never the response:

```go
if err != nil {
	resource.WriteError(w, err)
	return
}
```

With Rich Authorization Requests, the details the token was granted are
in its `authorization_details` claim. Read them with the same
`RARDefinition` the authorization server registered, rather than
decoding the claim by hand:

```go
granted, err := extension.ParseGrantedRAR(authCtx.Claims[extension.AuthorizationDetailsClaim])
// ...
payments, err := extension.RARGet(granted, paymentInitiation) // []RARDetail[T], only this type
```

A token without the claim was granted nothing. A malformed one is an
error, not an empty grant to wave through. Check the request against
what's granted before acting on it, as `examples/payment-consent`'s
payments API does, and refuse one the grant doesn't cover with
`resource.WriteError(w, resource.NewInsufficientScopeError(authCtx,
"..."))`: a 403 `insufficient_scope` whose challenge uses the scheme
the token was presented with (DPoP or Bearer).

`resource.VerifyRequestFromHTTP` fills in every field of the
`VerifyRequest` from `r`: the method, the `Authorization` header, every
`DPoP` header and the TLS client certificate. Building the struct by
hand compiles just as well with a field left out, and then fails only
for the clients that need it — which is why the constructor exists.

The one thing it takes from you is the URL: this endpoint's own fixed,
externally-visible URL (it's the DPoP proof's expected `htu`) — never
inferred from the incoming request's `Host` header, the same reasoning
`server.Endpoints` is never inferred from a request either. For a route
with path parameters, copy a fixed origin and set its `Path` from
`r.URL.Path`.

`DPoPProofs` carries every raw "DPoP" header value the request
carried — `r.Header.Values("DPoP")`, never `r.Header.Get("DPoP")`,
which silently returns only the first of several duplicate headers.
`Verify` itself rejects a request that carried more than one (RFC 9449
§4.3, which §7.1 applies to resource servers), so there's no
adapter-side check to write here.

`PeerCertificate` is the TLS client certificate the request arrived
with: an access token bound to a certificate (RFC 8705) is refused
without it. The constructor reads it from `r.TLS`; behind a proxy that
terminates TLS, set it afterwards from however the proxy forwards the
certificate. Take it only from your own proxy, over a hop clients can't
reach, and have the proxy remove any copy of that header a client sent: a
certificate is public, and only the TLS handshake proves the client holds
its key, so a header a client can set lets anyone present a stolen
certificate-bound token.

That's the whole surface: `resource.Verifier` has no other public entry
point. Everything above `Verify` — routing, and what the protected API
actually returns — is your own handler, same as step 5's login flow was
yours to build for `server`.

## 8. Run it

`cmd/conformance-as` is the complete version of all of the above,
runnable directly:

```sh
./conformance/server/scripts/generate-server-cert.sh   # a throwaway TLS cert/key in conformance/server/certs/ (gitignored)
go run ./cmd/conformance-as \
	-config conformance/server/oidf-config/baseline.config.json \
	-cert conformance/server/certs/server.crt \
	-key conformance/server/certs/server.key
```

It listens on the config's `listen_addr` (`-listen` overrides it) and
serves its discovery document at `/.well-known/openid-configuration`.
The other `conformance/server/oidf-config/*.config.json` files are the
other profiles (message signing, mTLS, CIBA, ...). `go run
./conformance/server/scripts/setup-config` regenerates those files'
client keys and the conformance-suite plans that go with them; it
rewrites the tracked files in place, so run it only when you're driving
the conformance suite. See `conformance/server/scripts/README.md` for
the full local setup procedure (it's written for conformance-suite
testing, but the binary it runs is the same one this guide has been
describing).

## 9. Rotating a signing key

`keys.KeyManager` never dictates a key's lifecycle — that's your
`Dependencies.Keys` implementation's own concern — but doing it without
a verification gap needs your implementation to also satisfy
`keys.RotatingKeyManager` (see `keys/doc.go`), and needs the steps done
in the right order:

1. Provision the new key wherever your `KeyManager` sources keys from
   (a new KMS key version, a new HSM slot, …). Don't touch `Sign` or
   `PublicKey` yet — both should still resolve to the outgoing key.
2. Implement `keys.RotatingKeyManager` on your `KeyManager` (if it
   doesn't already) so `PublicKeys` returns **both** the outgoing and
   the new key. Deploy this alone first: `PublicJWKS()` now advertises
   both kids, but `Sign` still uses the outgoing one, so nothing a
   verifier does today changes yet — this step is purely "let every
   consumer's JWKS cache catch up before it matters."
3. Wait out whatever cache TTL the parties verifying your tokens use
   for your JWKS — this module's own `keys.NewJWKSIssuerKeySource` (a
   client resolving your keys) refetches on an unrecognized kid at most
   once per its minimum refresh interval (`keys.WithMinRefreshInterval`,
   by default its cache TTL), so it picks up a new key within one TTL,
   and you may have consumers you don't control caching longer.
   When in doubt, wait longer than you think you need to; this step
   costs nothing but time.
4. Cut `Sign`/`PublicKey` over to the new key. New ID tokens, JWT
   access tokens, and (under `ProfileFAPISecurityWithMessageSigning`)
   JARM responses are now signed with it. Keep `PublicKeys` returning
   both keys — this is the step every already-issued-but-not-yet-
   expired token depends on.
5. Keep publishing the outgoing key from `PublicKeys` for at least as
   long as the longest-lived artifact signed under it can still be
   presented for verification, counted from the moment you cut over in
   step 4, not from when you started: `Limits.IDTokenLifetime`, and
   `Limits.AccessTokenLifetime` too if `Dependencies.AccessTokens` is
   `JWTAccessTokens` (opaque access tokens aren't signed, so they don't
   count). `Limits.JARMResponseLifetime` bounds the same thing for JARM,
   though in practice a JARM response is verified once at the redirect
   callback and essentially never again later in its nominal lifetime,
   so it's the lowest-risk of the three. Drop the outgoing key from
   `PublicKeys` any sooner than this and you'll reject a token that's
   still legitimately valid.
6. Only after that window has fully elapsed, stop returning the
   outgoing key from `PublicKey`/`PublicKeys`, and only then destroy or
   retire it in your KMS/HSM — never the other way around.

The mirror case — a **client** rotating its own ID-token/UserInfo
decryption key (`keys.Decrypter`, `keys.ECDHAgreer`/`KeyDecrypter` — see
`keys/doc.go`) — isn't covered by this guide (it's `client`'s
dependency, not `server`'s), but the direction of control is reversed
in a way worth knowing about: there's no `Limits` field to bound the
overlap by, because it isn't this server's own artifact aging out —
it's whichever authorization server(s) the client talks to, and how
long *they* cache the client's registered encryption key before
picking up its new one. A rotating client should keep decrypting under
its outgoing key (a backend that selects by the `keyID`
`UnwrapRequest` carries) for as long as it's willing to assume some AS
might still hold a stale cached copy of its JWKS — inherently a guess,
not a number this module can compute for you.

## 10. The client side: calling a FAPI 2.0 authorization server

The steps above build an authorization server and a resource server.
The `client` package is the other end — a relying party that pushes an
authorization request, handles the callback, exchanges the code and
calls protected resources, with PAR, PKCE, DPoP (or mTLS) and
`private_key_jwt` throughout. A minimal web client, discovering its
authorization server and keeping its sessions in `memstore` (a durable
store in production):

```go
// Two HTTP types: the transport (an *http.Client that refuses private
// and loopback addresses when it dials) for the client's own requests,
// and a fetcher wrapping it for discovery and the issuer's JWKS.
transport, err := fapihttp.NewClient(fapihttp.RecommendedTransportConfig())
if err != nil {
	return err
}
fetcher, err := fapihttp.New(transport, fapihttp.RecommendedConfig())
if err != nil {
	return err
}

issuer, err := fapi.ParseIssuerURL("https://as.example.com")
if err != nil {
	return err
}
discovered, err := client.Discover(ctx, fetcher, issuer)
if err != nil {
	return err
}
issuerKeys, err := discovered.IssuerKeySource(fetcher, 10*time.Minute)
if err != nil {
	return err
}

c, err := client.NewFromDiscovery(discovered, client.Config{
	ClientID:                       "my-client",
	RedirectURI:                    "https://rp.example.com/callback", // checked at New
	Profile:                        client.ProfileFAPISecurity,
	Algorithms:                     client.RecommendedAlgorithms(),
	Limits:                         client.RecommendedLimits(),
	Assurance:                      client.AssuranceProduction,
	AuthorizationResponseIssPolicy: client.RequireAuthorizationResponseIss,
	SenderConstrain:                storage.SenderConstrainDPoP,
	ClientAuthMethod:               storage.ClientAuthMethodPrivateKeyJWT,
}, client.Dependencies{
	Sessions:   sessions,   // storage.SessionStore
	Keys:       clientKeys, // keys.KeyManager: client authentication and DPoP keys
	IssuerKeys: issuerKeys,
	HTTP:       transport,
	Clock:      client.SystemClock{},
	Random:     rand.Reader, // crypto/rand
})
if err != nil {
	return err
}
```

`NewFromDiscovery` fills in the issuer and endpoints from the discovered
metadata and checks them against your `Config`; `New` takes them
explicitly instead. Then, in your handlers:

```go
// 1. Start: push the request, remember the session, send the browser on.
session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
if err != nil {
	return err
}
setSessionCookie(w, session.Handle().String()) // e.g. client/sessioncookie
http.Redirect(w, r, session.URL().String(), http.StatusFound)

// 2. Callback: validate the response and exchange the code in one call.
handle, err := client.ParseSessionHandle(sessionCookie(r))
if err != nil {
	return err
}
result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: r.URL.RawQuery, Session: handle})
if err != nil {
	return err // a refused response: forged, replayed, or for another session
}
var tokens client.TokenSet
switch v := result.(type) {
case client.CompletionSuccess:
	tokens = v.Tokens // tokens.Issuer records who issued them
case client.CompletionDenied:
	return fmt.Errorf("authorization denied: %s", v.Code) // e.g. access_denied
}

// 3. Call a protected resource: Do adds the access token and a DPoP
// proof, retries once on a use_dpop_nonce challenge, and never follows
// a redirect.
req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/accounts", nil)
if err != nil {
	return err
}
res, err := c.ProtectedResource(tokens).Do(ctx, req)
if err != nil {
	return err
}
defer res.Body.Close()

// 4. Later: refresh, and keep token sets at rest only sealed.
tokens, err = c.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: tokens})
if err != nil {
	return err
}
sealer, err := client.NewTokenSetSealer(c, [][]byte{sealingKey}) // a 32-byte key; rotate by prepending
if err != nil {
	return err
}
sealed, err := sealer.Seal(tokens, userID)
```

`HandleAuthorizationResponse` followed by `ExchangeCode` is the same
flow in two steps, for when you want the validated response before
redeeming the code; its result is a `CallbackSuccess` or a
`CallbackDenied`. For a native app, see the
[native wallet guide](docs/guides/native-wallet.md); for CIBA, the
[CIBA guide](docs/guides/ciba.md), whose stored sessions are sealed with
`client.NewBackchannelSessionSealer`.
