# Upgrading

This page covers every breaking change from v0.30.0 onward: who each one
affects and what to change. Releases with no breaking changes aren't
listed. [CHANGELOG.md](CHANGELOG.md) has the full history.

`New` fails at startup when a new requirement isn't met, and the error
names the missing field, so a skipped step can't slip through to
runtime. If you're several versions behind, work through the sections
from oldest to newest.

Most production-assurance changes only affect `Config.Assurance =
AssuranceProduction`. A development-assurance setup built on `memstore`
and `keys/ephemeral` needs only the steps not marked *production only*.

## v0.39.0

### `federation.Limits.MaxAuthorityHints` is required

**Affects:** every `federation.NewResolver` caller, and servers setting
`server.Config.AutomaticRegistration` (its new `MaxAuthorityHints`
field).

**Why:** automatic registration resolves an unknown `client_id`'s Trust
Chain before the request can be authenticated, and the resolver fetched
every superior an Entity Configuration listed in `authority_hints`. One
Entity Configuration listing thousands of hints could turn a single
unauthenticated request into thousands of outbound fetches.

```go
federation.Limits{
	MaxPathLength:        5,
	MaxAuthorityHints:    5, // an entity listing more is rejected
	MaxStatementLifetime: 24 * time.Hour,
	MaxClockSkew:         30 * time.Second,
}
```

An Entity Configuration listing more hints than the limit now fails
resolution. Real ones list one, or a handful for an entity in several
federations. Concurrent automatic-registration requests for the same
`client_id` now also share one resolution. Rate-limit PAR per client
address in front of the server too: each distinct unknown `client_id`
still costs one resolution.

### `backchannelhttp.New` builds its own guarded client

**Affects:** CIBA ping deployments using `backchannelhttp`.

**Why:** a client's notification endpoint can come from an OpenID
Federation relying party's own metadata under automatic registration,
and `New` accepted any HTTP client. Passing a plain `http.Client` made
every notification a server-side request forgery that could reach
internal hosts and follow redirects.

```go
notifier, err := backchannelhttp.New(backchannelhttp.Config{
	Timeout: 5 * time.Second,
	Transport: fapihttp.TransportConfig{
		DialTimeout:         5 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	},
})
```

`New` no longer takes a client: it builds one with
`fapihttp.NewClient(cfg.Transport)`, which blocks loopback, private and
link-local addresses at connect time and never follows a redirect. Use
`Transport.AllowedPrivateHosts` for a notification endpoint that really
is on a private network.

### Identity claims need the user's approval (server)

**Affects:** servers with `Dependencies.IdentityClaims` configured, whose
clients request identity claims with the OIDC `claims` parameter.

**Why:** requested claim names went straight to the claims source, with
no scope check, no consent step and no client context, so any
registered client could obtain any identity attribute the source holds.

Show `InteractionRequest.RequestedClaims` (or
`BackchannelInteractionRequest.RequestedClaims`) on the consent screen,
and pass the names the user approves:

```go
server.GrantedAuthorization{
	Scope:                  approvedScope,
	ApprovedIdentityClaims: approvedClaims, // a subset of RequestedClaims.Names()
}
```

Only claims both requested and approved are resolved, for the ID token
or UserInfo wherever each was requested. Leaving the field nil releases
none, and approving a claim that wasn't requested fails
`CompleteAuthorization`/`CompleteBackchannelAuthentication`.

## v0.38.0

### `Dependencies.Random` must be `crypto/rand.Reader` (production only)

**Affects:** `server.New` and `client.New` under `AssuranceProduction`
with any other `Random`, including a wrapper around `crypto/rand.Reader`.

**Why:** codes, tokens, `state`, `nonce`, PKCE verifiers and every `jti`
are only as unguessable as this reader, and an `io.Reader` can't declare
that it is a CSPRNG.

```go
deps.Random = rand.Reader // crypto/rand
```

`resource.Dependencies.Random` is unchanged.

### JOSE and metadata member names are case-sensitive

**Affects:** nobody talking to a conforming peer. A JWS or JWE header,
JWK, JWK Set, DPoP proof, client assertion, client attestation, access
token `cnf` claim or AS metadata document whose member names only
case-fold to a known name (`"ALG"` for `"alg"`) is now rejected instead
of being read as that member. No code change is needed.

### Scope errors are `invalid_scope` (server)

**Affects:** anything matching on the error code. A pushed
authorization request or CIBA backchannel authentication request naming
a scope the client isn't allowed (or `openid` under `Config.OAuthOnly`)
now gets `invalid_scope` instead of `invalid_request`, as RFC 6749 and
CIBA Core §13 define. A missing or non-string scope is still
`invalid_request`.

### Server error text is character-checked (client)

**Affects:** callers reading server-supplied error text. `error`,
`error_description` and `error_uri` values outside RFC 6749 §5.2's
character set are now dropped from `Error.PublicDescription`,
`CallbackDenied.Description` and `BackchannelAuthenticationDenied.Description`,
and an authorization error redirect whose `error` code is malformed is
rejected as `invalid_response` rather than returned as `CallbackDenied`.
Well-formed responses are unaffected. `Error.ServerResponse()` is new in
this release and exposes the code, description, URI and HTTP status.

## v0.37.0

### `AuthorizationCallback.Session` is required (client)

**Affects:** every client using the browser flow
(`HandleAuthorizationResponse` or `CompleteAuthorization`).

**Why:** a callback's `state` only identifies a session, and anyone can
deliver a callback URL to someone else's browser. Binding the callback to
the browser that started the flow stops login CSRF (RFC 9700 §4.7).

Store the handle with the user agent when you redirect, and pass it back
at the callback:

```go
// Starting the flow.
session, err := rp.BeginAuthorization(ctx, req)
if err != nil { /* ... */ }
http.SetCookie(w, &http.Cookie{
	Name:     "fapi_session",
	Value:    session.Handle().String(),
	HttpOnly: true,
	Secure:   true,
	SameSite: http.SameSiteLaxMode, // Lax, so the cookie survives the AS's top-level redirect back
})
http.Redirect(w, r, session.URL().String(), http.StatusFound)

// At the redirect URI.
cookie, err := r.Cookie("fapi_session")
if err != nil { /* reject: no session for this browser */ }
handle, err := client.ParseSessionHandle(cookie.Value)
if err != nil { /* reject */ }
result, err := rp.CompleteAuthorization(ctx, client.AuthorizationCallback{
	RawQuery: r.URL.RawQuery,
	Session:  handle,
})
```

A callback whose `Session` doesn't match its `state` is rejected before
the session is consumed. Tests using `fapitest.RunAuthorizationCodeFlowWithCallback`
now pass the session handle as its second argument.

### Signing and decryption keys must declare custody (production only)

**Affects:** `server.Dependencies.Keys`, `JWTAccessTokens.Keys`,
`client.Dependencies.Keys` and `client.Dependencies.Decryption` under
`AssuranceProduction`.

Declare how the keys are held when you build the key manager or
decrypter:

```go
km, err := keys.NewKeyManagerFromSigners(signers, algorithms, kids,
	keys.DeclareCustody(keys.KeyCustody{
		Durable:                 true, // keys survive a restart (KMS, HSM, or your own durable storage)
		CrossInstanceConsistent: true, // every instance uses the same keys (needed with HorizontallyScaled)
	}))
```

`keys.NewDecrypter` and `keys.NewSingleKeyDecrypter` take the same
option. A custom `KeyManager` or `Decrypter` implements
`keys.KeyCustodyAssurance` instead. `keys/ephemeral` never declares
custody and is rejected in production.

## v0.36.0

### `X5CAttesterChain.IssuerBinding` is required (server)

**Affects:** servers using `X5CAttesterChain` for attestation-based
client authentication.

**Why:** a client attestation's `iss` is chosen by the attester. Without a
binding, any attester certified under a shared trust anchor could
authenticate as another attester's clients.

```go
deps.AttesterTrust = server.X5CAttesterChain{
	TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: pool},
	IssuerBinding: server.AttesterIssuerInCertificate,
}
```

- `AttesterIssuerInCertificate`: the signing certificate carries a URI
  SAN exactly equal to the client's `ExpectedAttesterIssuer`. Use this
  whenever anchors are shared between attesters.
- `AttesterIssuerByTrustAnchors`: your `AttesterTrustAnchors` returns
  anchors belonging to each client's attester alone, so the chain itself
  identifies the attester.

## v0.34.0

### `Dependencies.AttesterTrust` is required with attestation auth (server)

**Affects:** servers with `Config.AttestationBasedClientAuthentication`
set.

- To keep the previous behavior (attester key looked up by `kid` in
  `ClientKeys`), pass `server.RegisteredAttesterKeys{}`.
- To verify the attestation's `x5c` certificate chain (HAIP 1.0 §4.4.1),
  pass `server.X5CAttesterChain` with trust anchors and, from v0.36.0,
  an `IssuerBinding` (see above).

## v0.33.0

### `Limits.MaxIDTokenClaimsBytes` is required (server)

**Affects:** servers building `Limits` by hand, unless `Config.OAuthOnly`
is set. `server.RecommendedLimits()` already sets it to 4096.

### Stores persist an opaque `Request` or `Grant` value (storage)

**Affects:** custom `TransactionStore`, `GrantStore` and
`BackchannelAuthenticationStore` implementations. `memstore` is already
updated.

- Replace the removed per-field columns with the single `Request` or
  `Grant` value, and persist and return it unmodified. The server owns
  its format, so future fields never touch your schema.
- Run `storage.TestTransactionStoreContract`, `TestGrantStoreContract`
  and `TestBackchannelAuthenticationStoreContract` against your store.
- Records written by an earlier version can't be read after upgrading.
  Pushed requests, authorization codes and CIBA requests are
  short-lived. Refresh tokens are not, so clients will need to
  re-authorize once.

## v0.31.0

### `AuthorizationResponseIssPolicy` is required (client)

**Affects:** every client. `Config.RequireAuthorizationResponseIss`
(bool) is replaced by `Config.AuthorizationResponseIssPolicy`, with no
default:

- `client.RequireAuthorizationResponseIss` matches the former `true`.
- `client.TolerateAbsentAuthorizationResponseIss` matches the former
  `false` or unset.

### Key sources must declare `KeySourceAssurance` (production only)

This one wasn't flagged as breaking in the v0.31.0 changelog.

**Affects:** `server.Dependencies.ClientKeys`, `ClientEncryptionKeys`
and `client.Dependencies.IssuerKeys` under `AssuranceProduction`. A
custom key source implements `keys.KeySourceAssurance` and declares
`LiveFetchHardened`: every live fetch goes through `fapihttp`, or there
is no live fetch at all. `keys.JWKSIssuerKeySource` and
`keys.NewLocalIssuerKeys` already declare it.

## v0.30.0

### `ClientCertificateTrust` replaces `MTLSClientCAs` (server)

**Affects:** every server. `Dependencies.MTLSClientCAs` is renamed to
`Dependencies.ClientCertificateTrust` and is now required:

- `server.TrustedClientCAs{Roots: pool}` if you previously set
  `MTLSClientCAs` (this package verifies the chain).
- `server.NoClientCertificateChainTrust{}` if you left it unset and
  verify client certificate chains yourself (for example, at a
  TLS-terminating proxy).
