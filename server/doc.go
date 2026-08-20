// Package server implements the FAPI 2.0 authorization-server (AS) role:
// pushed authorization requests, the authorization endpoint state
// machine, token issuance, and the server's own discovery metadata and
// published keys.
//
// The package exposes workflow methods — PushAuthorizationRequest,
// BeginAuthorization, CompleteAuthorization, ExchangeAuthorizationCode,
// RefreshAccessToken, Metadata and PublicJWKS — that only ever consume
// client-generated artefacts and validate them against server-held
// state and policy. Metadata and PublicJWKS are the exceptions: Metadata
// describes the server itself rather than processing a request, and is
// derived entirely from Config with no dependency I/O; PublicJWKS
// reports this server's own current public keys rather than validating
// anything a caller supplied. The package must never expose the client
// package's request-building functionality, a generic
// HandleRequest(map[string]any), or a bare ValidateJWT(token string) —
// and must not import client. The two roles are independently usable
// and have distinct trust boundaries, state machines and failure modes.
//
// Shared wire formats and cryptographic primitives (JOSE parsing, JWK
// validation, DPoP proof verification, client assertion and request
// object verification) live under internal/ and are used here on the
// verification side only.
//
// Public API shape rules current code follows (see ARCHITECTURE.md rule
// 7 for the full target list):
//
//   - PushAuthorizationRequest carries a raw, lossless FormRequest
//     (ordered FormParameter list, not url.Values), so the server — not
//     an HTTP adapter — detects duplicate parameters.
//   - RequestURI and InteractionHandle are opaque: no public
//     constructor, only Server can produce one, and each is single-use —
//     a second BeginAuthorization with the same request_uri, or a second
//     CompleteAuthorization with the same handle, fails. An authorization
//     code is likewise single-use: a second ExchangeAuthorizationCode
//     with the same code fails. A refresh token is single-use too, but
//     via rotation rather than outright consumption: every successful
//     RefreshAccessToken call retires the presented token and returns a
//     new one, so a stolen-and-replayed old token is detectable — it
//     will already be consumed by the time it's misused.
//   - AuthorizationAction (from BeginAuthorization) and AuthorizationResult
//     (from CompleteAuthorization) are closed sum types, not structs with
//     optional fields, so a caller can never mistake a local error for a
//     safe redirect. InteractionResult (the input to CompleteAuthorization)
//     is likewise closed, buildable only via Authorize, Deny or
//     AuthenticationFailed — never assembled field-by-field.
//   - Error carries an OAuth ErrorCode and an HTTP status alongside a
//     PublicDescription safe to put in a response body; the underlying
//     cause is available via Unwrap for logs only.
//   - New fails unless every dependency (client lookup, transaction
//     store, grant store, replay store, client key resolution, this
//     server's own signing key manager, clock, randomness) is present,
//     and unless every configured limit, endpoint and algorithm is
//     valid. Config.Assurance additionally requires an AuditSink under
//     AssuranceProduction; Config.Profile additionally requires a JARM
//     algorithm under ProfileFAPISecurityWithMessageSigning. Further
//     production-only checks (store durability/atomicity capabilities,
//     HSM-required keys) will be added once the mechanisms to check them
//     exist.
//   - Every access token this server issues is DPoP sender-constrained
//     (RFC 9449) — ExchangeAuthorizationCode and RefreshAccessToken each
//     require a valid DPoP proof bound to the token endpoint and reject
//     a replayed proof jti the same way they reject a replayed client
//     assertion or request object. A refresh token is itself bound to
//     the DPoP key it was issued under: RefreshAccessToken rejects a
//     proof from any other key, even one belonging to the same client.
//     Bearer (non-sender-constrained) tokens and mTLS binding are not
//     supported.
//   - An ID token is issued alongside the access token exactly when the
//     (possibly refresh-narrowed) granted scope includes "openid";
//     nonce, auth_time, acr and amr come from what CompleteAuthorization
//     originally recorded — a refreshed ID token omits nonce, since that
//     claim only ever bound the *original* ID token to the authorization
//     request that requested it. A refresh token is issued exactly when
//     the granted scope includes "offline_access", matching common OIDC
//     practice.
//   - RefreshAccessToken lets a client narrow, but never widen, the
//     scope it originally received — a widening request fails with
//     ErrorInvalidScope rather than silently clamping to the original
//     grant.
//   - Config.Profile controls whether a pushed authorization request may
//     submit its authorization parameters as a signed request object,
//     as plain form parameters, or (ProfileFAPISecurity) either —
//     ProfileFAPISecurityWithMessageSigning requires a request object at
//     PAR and produces a JARM-signed authorization response;
//     ProfileFAPISecurity produces a plain-query-parameter redirect.
//     Success and error redirects are built by the same code path, so an
//     error response gets the same integrity treatment a success
//     response does.
//   - Config.Algorithms is a server-wide algorithm allow-list, checked
//     in addition to each client's own registered algorithm — a
//     misregistered client cannot use an algorithm the operator has
//     disabled server-wide.
//   - Every non-JARM authorization response carries an "iss" parameter
//     identifying this server (RFC 9207), so a client can detect a
//     response mixed up between two authorization servers; a JARM
//     response's own "iss" claim serves the same purpose instead, so it
//     isn't duplicated as a query parameter.
//   - Metadata reports what this server actually enforces, not a fixed
//     capability list — e.g. RequirePushedAuthorizationRequests is
//     always true (BeginAuthorization never accepts anything but a
//     request_uri), while RequireSignedRequestObject and
//     AuthorizationSigningAlgValuesSupported are populated only under
//     ProfileFAPISecurityWithMessageSigning, matching what
//     PushAuthorizationRequest and CompleteAuthorization actually do
//     for the configured profile.
//   - PublicJWKS returns the union, deduplicated by kid, of
//     Dependencies.Keys' current public key for every signing purpose
//     Config declares active, plus an access-token signing key from
//     Dependencies.AccessTokens if it has one to publish (JWTAccessTokens
//     does, on its own KeyManager, independent of Dependencies.Keys;
//     OpaqueAccessTokens doesn't — nothing to verify a signature
//     against) — never a private key, and never a key for a purpose
//     (e.g. JARM under ProfileFAPISecurity) this server isn't actually
//     configured to use. PublicJWK exposes only KeyID and MarshalJSON;
//     there is no way to extract anything from it this package didn't
//     already treat as public.
package server
