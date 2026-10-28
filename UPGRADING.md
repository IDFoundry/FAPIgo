# Upgrading

This page covers every breaking change from v0.30.0 onward: who each one
affects and what to change. Releases with no breaking changes aren't
listed. [CHANGELOG.md](CHANGELOG.md) has the full history.

`New` fails at startup when a new requirement isn't met, and the error
names the missing field, so a skipped step can't slip through to
runtime. Where it can't — a requirement on stored data, such as a
client's registration — the section says so, and what the failure looks
like. If you're several versions behind, work through the sections
from oldest to newest.

Most production-assurance changes only affect `Config.Assurance =
AssuranceProduction`. A development-assurance setup built on `memstore`
and `keys/ephemeral` needs only the steps not marked *production only*.

## v0.63.0

### RSA keys a caller supplies are limited to 4096 bits, and every parsed RSA JWK to exponent 65537

**Affects:** a client, wallet, attester or federation entity presenting
an RSA key with a modulus over 4096 bits, or any RSA JWK with a public
exponent other than 65537 (`"e":"AQAB"`). Keys with a 2048-, 3072- or
4096-bit modulus and exponent 65537 — what every mainstream key
generator, HSM and KMS produces — need no change.

**Why:** a DPoP proof carries its own key, and the proof is checked
before the access token (resource server) or alongside client
authentication (authorization server), so anyone could send a proof
with an 8192-bit RSA key and exponent 2^31−1 and make the server spend
about 30 times the CPU of an ordinary proof on a signature that was
never going to verify. The same choice of key was open to anyone
publishing a client JWK Set, an attestation `cnf.jwk` or a federation
entity's keys. FAPI 2.0 Security Profile §5.4.1 and RFC 7518 set only a
2048-bit minimum. The library now:

- accepts only exponent 65537 in any RSA JWK it parses. Large
  exponents multiply the cost of every verification, and small ones
  are the classic source of forgery bugs in lax verifiers.
- limits RSA keys a caller supplies to a 4096-bit modulus: a DPoP
  proof's `jwk` (authorization server and resource server), an
  attestation PoP's `cnf.jwk`, a client's JWK Set (a
  `keys/ephemeral` client key source and federation automatic
  registration, signing and encryption keys alike), and every
  federation entity's keys, a Trust Anchor's configured `JWKS`
  included.
- keeps 8192 bits for keys the operator chose: its own signing and
  encryption keys, and an authorization server's issuer keys fetched by
  `keys.JWKSIssuerKeySource` (`client.DiscoveredMetadata.IssuerKeySource`).

Both checks run while the key is parsed, before any RSA operation uses
it. A key returned by your own `keys.ClientKeySource` implementation is
used as you return it, so your registration process sets its limits.

**What fails:** nothing at startup. A DPoP proof or attestation PoP
with such a key is refused (`invalid_dpop_proof` or `invalid_client`).
A JWK Set entry with such a key is skipped as unusable, so a client
whose only key is one of them fails authentication with
`invalid_client`, and a federation entity whose only key is one of them
fails trust-chain resolution.

**What to change:** re-key any such client, attester or federation
entity with a 2048-, 3072- or 4096-bit RSA key and exponent 65537, or
with an EC P-256 or Ed25519 key:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out client.pem
```

### A URL's host must be ASCII: give an internationalized domain name as its `xn--` A-label (fapi, server, client, resource, storage, federation, fapihttp)

**Affects:** an issuer, endpoint or redirect URI written with a
non-ASCII host, such as `https://bücher.example`, and a DPoP proof made
for, or presented at, such a host, at every assurance level.

**Why:** hosts were lowercased with `strings.ToLower` and compared with
`strings.EqualFold`, whose Unicode case mapping folds some non-ASCII
letters onto ASCII ones: `İ` (U+0130) lowercases to `i`, and the Kelvin
sign `K` (U+212A) folds to `k`. `net/http` dials a non-ASCII host
through IDNA instead, as a different DNS name (`İbank.example` is
`xn--ibank-7fd.example`). So `fapi.ParseIssuerURL("https://İbank.example")`
returned `https://ibank.example`, and a DPoP proof for a request to
`https://İbank.example/…`, an attacker's host, carried an `htu` that
verified at `https://ibank.example/…`. Hosts and schemes are now
lowercased and compared in ASCII only, and a non-ASCII host is refused
where it used to be folded.

**What fails:**
- `fapi.ParseIssuerURL`, `ParseEndpointURL` and `ParseRedirectURL`
  return an error saying the host is not ASCII. The server's pushed
  authorization request refuses such a `redirect_uri` with
  `invalid_request`.
- `client.ResourceClient.Do` refuses a request to a non-ASCII host with
  `invalid_request` before sending it, whichever sender constraint the
  client uses.
- An authorization or resource server refuses, as an `htu` mismatch,
  every proof whose `htu` has a non-ASCII host, and every proof when
  its own target URL has one.
- A pairwise client registered with `storage.NewRegisteredClient` whose
  redirect URIs have a non-ASCII host derives no sector from them, so
  it needs `Sector` set.
- Federation naming constraints, a pairwise Relying Party's
  redirect-host check, and `fapihttp`'s `AllowedPrivateHosts`,
  `AllowedLoopbackHosts` and same-origin redirect check no longer match
  a non-ASCII host to an ASCII one.

**What to change:** write the host in its A-label (punycode) form, the
name requests are actually sent to. Convert it once, for example with
`golang.org/x/net/idna`:

```go
host, err := idna.Lookup.ToASCII("bücher.example") // "xn--bcher-kva.example"
if err != nil {
	return err
}
issuer, err := fapi.ParseIssuerURL("https://" + host)
```

ASCII hosts in any letter case are unaffected: `https://AS.Example` is
still accepted, as `https://as.example`.

### Authorization codes are stored under a new digest, and `GrantStore` keeps codes and refresh tokens apart (server, storage)

**Affects:** every server, once, at deploy; and a custom
`storage.GrantStore` that keeps authorization codes and refresh tokens
in one table keyed by digest alone. `memstore` needs no change.

**Why:** a non-attested authorization code and a refresh token were
both stored under the plain SHA-256 of their value, and the grant
record didn't say which it was. A store with one table for both — which
passed every `storage.TestGrantStoreContract` subtest — answered
`RedeemRefreshToken` with a code's record, so a client presenting its
code as `refresh_token` got tokens without PKCE, without its
`redirect_uri`, under any DPoP key, as often as it liked, and without
spending the code. Two independent changes close that:

- A code's digest (`NewAuthorizationCode.CodeHash`) is now the SHA-256
  of the code behind a fixed domain-separation prefix, so it never
  equals a refresh token's digest of the same value. A refresh token's
  digest is unchanged: codes live `Limits.AuthorizationCodeLifetime`
  (a minute at most), so moving them costs only the codes in flight at
  deploy, while moving refresh tokens would have orphaned every live
  one. An attested client instance's code digest is unchanged.
- Each grant record now carries its kind (authorization code, refresh
  token, decided CIBA request), and each redemption refuses a record of
  another kind with `invalid_grant`, as if it were unknown. A record
  written before this release has no kind: a refresh token or CIBA
  grant without one is still accepted when it has none of a code's
  fields (`redirect_uri`, PKCE challenge, `nonce`), which every code
  has and a refresh token never does; a code is never accepted without
  one.

**What fails:**

- An authorization code issued before the deploy and exchanged after it
  is unknown (`invalid_grant`), as is the reuse of such a code: the
  client starts the authorization again. Refresh tokens and CIBA
  requests carry over.
- `storage.TestGrantStoreContract` has two new subtests,
  `RedeemRefreshTokenDoesNotReturnAuthorizationCode` and
  `RedeemAuthorizationCodeDoesNotReturnRefreshToken`, which a store
  keyed by digest alone across both kinds fails. The server refuses the
  crossed record either way; the subtests hold the store to the same
  separation.
- Anything outside the server that computed a code's digest itself as
  `sha256.Sum256([]byte(code))` no longer matches what the store holds.

**What to change:** nothing for a store with separate code and refresh
token tables. A single-table store adds the kind to its key or filter:

```go
// One "grants" table: key by (kind, digest), not digest alone.
func (s *Store) RedeemRefreshToken(ctx context.Context, r storage.RefreshTokenRedemption) (storage.RedeemedRefreshToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT client_id, grant_record, expires_at FROM grants
		 WHERE kind = 'refresh_token' AND hash = $1 AND NOT revoked`, r.TokenHash[:])
	// ...
}
```

### One reserved-claim-name policy for every claim source (server, extension)

**Affects:**

- an `extension.Definition` with `ReturnInTokenClaims` named `roles`,
  `groups`, `entitlements`, `act`, `may_act`, `events`,
  `_claim_names`, `_claim_sources`, `sub_jwk`, `code`, `state` or
  `error`;
- `GrantedAuthorization.IDTokenClaims` setting `code`, `state` or
  `error`;
- claims passed to `Server.SignUserInfoResponse` that set anything
  beyond the user's claims: `events`, `_claim_names`,
  `_claim_sources`, `sub_jwk`, `azp`, `nonce`, `at_hash`, `c_hash`,
  `s_hash`, `code`, `state` or `error` (`iss` and `aud` were already
  refused);
- a custom `server.AccessTokenIssuer` that adds `events`,
  `_claim_names`, `_claim_sources` or `sub_jwk` to
  `AccessTokenParams.Claims` before calling `JWTAccessTokens`.

**Why:** each claim source kept its own list of names it refused, and
the lists disagreed. An extension's value is the client's own, yet an
extension could put a client-chosen `roles: ["admin"]` into the access
token, which a resource server enforcing RFC 9068 §2.2.3.1 roles
trusts as the authorization server's decision, or `events` into the ID
token, the claim that marks a logout token. An ID token or a signed
UserInfo response carrying `code` passes the check a relying party uses
to tell a JARM response apart. Every source now uses one policy, which
differs by token kind and by who chose the value:

- nothing may set the claims the server sets itself, nor `events`,
  `_claim_names`, `_claim_sources` or `sub_jwk`, which change how a
  recipient processes a token;
- an ID token or signed UserInfo response never carries `code`,
  `state` or `error`, and a UserInfo response never carries an ID
  token's `azp`, `nonce` or hashes;
- a client's value (an extension's) may also never use the RFC 9068
  authorization attributes `roles`, `groups` and `entitlements`, the
  RFC 8693 delegation claims `act` and `may_act`,
  `authorization_details`, or an OIDC Core §5.1 standard claim.

The application may still set authorization attributes and delegation
itself: in `GrantedAuthorization.IDTokenClaims`, a signed UserInfo
response, or its own `AccessTokenIssuer`.

**What fails:**

- `extension.NewRegistry` returns an error wrapping the new
  `extension.ErrReservedTokenClaim`. It now also refuses the names
  `server.New` already refused (`email`, `acr` and the like), so that
  error moves from `server.New` to `NewRegistry`;
- `CompleteAuthorization` returns an `AuthorizationLocalError`
  (`invalid_request`), and `CompleteBackchannelAuthentication` an
  `invalid_request` error, for `IDTokenClaims` setting one of the names above;
- `SignUserInfoResponse` returns `server_error`;
- token issuance fails with `server_error` for a custom
  `AccessTokenIssuer` passing one of those names to `JWTAccessTokens`.

A claim an `IdentityClaimsSource` returns under one of these names is
dropped, for the ID token as before and now also by
`serverresource.UserInfoClaims`, rather than failing.

**What to change:** rename the extension, or drop `ReturnInTokenClaims`
if the value only needs to reach the interaction step
(`InteractionRequest.Extensions`). Set roles or delegation from your own
policy instead of a client's parameter:

```go
server.Authorize(subject, authn, server.GrantedAuthorization{
	Scope:         approvedScope,
	IDTokenClaims: map[string]json.RawMessage{"roles": rolesJSON},
})
```

Drop `code`, `state` and `error` from ID token and UserInfo claims.

### ID tokens, JARM responses and signed UserInfo accept only a generic `typ` (client)

**Affects:** a client whose authorization server sends ID tokens, JARM
responses or signed UserInfo responses with a `typ` header other than
absent or `JWT`, or JARM responses carrying an ID token claim.

**Why:** the client refused a `typ` naming one of a fixed list of other
JWT kinds and accepted everything else. A JWT the same issuer signs for
the same audience under a type outside that list (an SD-JWT credential,
a status list token, or `at+jwt; charset=x`) was taken for an ID token,
a JARM response or a UserInfo response. None of the three has a media
type of its own, so `typ` is now an allow-list: absent, or `JWT` in
any case, with or without `application/`. This is what the OpenID
Foundation conformance suite sends. A JARM response is also refused
when it carries a claim only an ID token carries (`sub`, `nonce`,
`auth_time`, `acr`, `amr`, `azp` or a hash), even alongside a `code`.

**What fails:** `ExchangeCode`, `HandleAuthorizationResponse`, a CIBA
or refresh token response, and `FetchUserInfo` return
`invalid_response`.

**What to change:** nothing for a conforming authorization server. If
yours sets another `typ` on these JWTs, have it send `JWT` or no `typ`.

## v0.62.0

### `X5CAttesterChain.Revocation` is required (server)

**Affects:** a server with `Config.AttestationBasedClientAuthentication`
whose `Dependencies.AttesterTrust` is `server.X5CAttesterChain`, at every
assurance level.

**Why:** an attester's signing certificate was checked for its chain and
validity period only, so a certificate revoked after its key was
compromised went on authenticating attestations until it expired, and
the doc said "Revocation isn't checked". `X5CAttesterChain` now asks a
`ClientCertificateRevocation` — the same interface, check and CRL
implementation `TrustedClientCAs.Revocation` uses for client
certificates — about the verified chain, leaf first and ending at the
trust anchor, at the server's `Clock` time. It runs on every
attestation-authenticated request, once the attestation and its PoP
have verified. An error wrapping `server.ErrCertificateRevoked` is
`invalid_client`; any other error, a check that couldn't decide, is
`server_error` — see the next section.

**What fails:** `server.New` returns an error naming
`X5CAttesterChain.Revocation`.

**What to change:** pass the CRLs of the CAs that issue your attesters'
certificates, your own `ClientCertificateRevocation` (OCSP, for
example), or `server.NoClientCertificateRevocationCheck{}` to keep the
previous behavior:

```go
deps.AttesterTrust = server.X5CAttesterChain{
	Anchors:       server.StaticAttesterAnchors{ /* ... */ },
	IssuerBinding: server.AttesterIssuerBoundToAnchor,
	Revocation: server.ClientCertificateCRLs{
		Lists: func(ctx context.Context) ([]*x509.RevocationList, error) {
			return attesterCRLs.Current(), nil // refreshed in the background
		},
	},
}
```

`ClientCertificateCRLs` needs a current CRL from every CA that issues a
certificate in the chain, the intermediates' issuers included, and
fails closed without one, with `server_error`.

### A `ClientCertificateRevocation` reports a revoked certificate with `ErrCertificateRevoked` (server)

**Affects:** a custom `server.ClientCertificateRevocation` (OCSP, a
revocation service of your own) used as `TrustedClientCAs.Revocation`
or `X5CAttesterChain.Revocation`. `server.ClientCertificateCRLs` and
`server.NoClientCertificateRevocationCheck{}` need no change.

**Why:** every error a revocation check returned refused the client
with `invalid_client` (401), so a check that couldn't decide — a CRL
gone stale because its refresh failed, an OCSP responder that didn't
answer — told every mTLS or attested client that its credentials were
bad. A wallet may then discard its attestation or re-register, and
operators see a server-side outage as a wave of client faults. A
revocation check now tells the two apart, as
`ClientAttestationStatusChecker` does with
`ErrClientAttestationRevoked`: an error wrapping the new
`server.ErrCertificateRevoked` is `invalid_client` (401), with the
description "client certificate is revoked" or "attester certificate is
revoked"; any other error is `server_error` (500). Both still refuse the
request: a check that can't decide fails closed. `ClientCertificateCRLs`
wraps `ErrCertificateRevoked` only when a current CRL names a
certificate in the chain; a CA with no current CRL, or a `Lists` that
fails, is now `server_error` instead of `invalid_client`.

**What fails:** nothing at startup. A custom checker that returns a
plain error for a revoked certificate still refuses it, but with
`server_error` (500) instead of `invalid_client` (401).

**What to change:** wrap `server.ErrCertificateRevoked` in the error
your checker returns for a revoked certificate, and leave other errors
as they are:

```go
func (o ocspChecker) CheckRevocation(ctx context.Context, check server.ClientCertificateRevocationCheck) error {
	status, err := o.status(ctx, check.Chain)
	if err != nil {
		return err // undecided: server_error
	}
	if status == ocsp.Revoked {
		return fmt.Errorf("%w: OCSP says revoked", server.ErrCertificateRevoked)
	}
	return nil
}
```

Anything alerting on `invalid_client` from certificate-authenticated
clients to spot a stale CRL should watch for `server_error` instead.

### Attestation-based client authentication needs `Dependencies.ClientAttestationStatus` (server, *production only*)

**Affects:** a server under `AssuranceProduction` with
`Config.AttestationBasedClientAuthentication` set.

**Why:** a Client Attestation that verifies may still have been
withdrawn by its attester. OpenID4VCI 1.0 gives a Wallet Attestation an
optional `status` claim (a Token Status List,
draft-ietf-oauth-status-list) for that, and since every instance of a
wallet shares the attestation's `sub`, a status list is the only way a
Wallet Provider can revoke a single compromised instance. The new
`Dependencies.ClientAttestationStatus`, a
`server.ClientAttestationStatusChecker`, is asked about every verified
attestation, after its PoP has verified and its `jti` has been recorded.
It's given every claim of the attestation, its `iat` and `exp`, the
Client Instance Key's thumbprint, and the attester's key and (under
`X5CAttesterChain`) verified certificate chain, to bind a Status List
Token's signer to. An error wrapping `server.ErrClientAttestationRevoked`
refuses the request with `invalid_client`; any other error with
`server_error`. Whether to check status is an ecosystem decision this
package can't make for you, so production asks for it explicitly.

**What fails:** under `AssuranceProduction`, `server.New` returns an
error naming `client_attestation_status`. Development assurance accepts
nil, which checks nothing; setting a checker there works too.

**What to change:** pass your checker, or
`server.NoClientAttestationStatusCheck{}` when your attesters publish
no status:

```go
deps.ClientAttestationStatus = walletStatusChecker{lists: statusLists}
// or, when the attesters publish no status:
deps.ClientAttestationStatus = server.NoClientAttestationStatusCheck{}
```

[GETTING_STARTED.md](GETTING_STARTED.md#wallet-attestation-status)
sketches a checker.

## v0.61.0

### `NoClientCertificateChainTrust{}` is refused in production (server, *production only*)

**Affects:** a server under `AssuranceProduction` whose
`Dependencies.ClientCertificateTrust` is
`server.NoClientCertificateChainTrust{}`.

**Why:** `NoClientCertificateChainTrust{}` accepts a `tls_client_auth`
(or SAN-variant) client's certificate without verifying its chain, and
the same value served two different deployments: one whose TLS
termination verifies client certificate chains, and one that verifies
nothing at all. In the second, anyone can present a self-signed
certificate naming a statically registered client's subject or SAN and
authenticate as it. `server.New` can't tell the two apart, and can't
list a repository's static clients to see whether any uses
`tls_client_auth`, so the safe one now has a name of its own.

**What fails:** `server.New` returns an error naming
`client_certificate_trust` under `AssuranceProduction`. Development
assurance still accepts `NoClientCertificateChainTrust{}`.

**What to change:** if your TLS termination (or a gateway in front of
the server) verifies every client certificate's chain — Go's
`tls.Config.ClientCAs` with `RequireAndVerifyClientCert` or
`VerifyClientCertIfGiven`, on every listener that serves a
client-authenticating endpoint — pass
`server.ClientCertificateChainVerifiedUpstream{}`. It behaves exactly as
`NoClientCertificateChainTrust{}` did, automatic registration included.
Otherwise pass `server.TrustedClientCAs{...}` to verify chains in this
package, or `server.NoPKIClientAuthentication{}` when no client uses
`tls_client_auth`.

### Authorization codes are bound to the attested client instance (server)

Not a breaking change for a store or an API: it's here because of what
happens during the upgrade itself.

**Affects:** a server with `Config.AttestationBasedClientAuthentication`
whose clients authenticate by Client Attestation (wallet apps, say).

**Why:** every installation of an app shares one `client_id`, and an
authorization code was bound only to that. Another installation holding
an intercepted code could present it with a wrong PKCE verifier: the
code was spent before PKCE was checked, so the user's own exchange
failed, or, once redeemed, the presentation counted as a reuse and
revoked the tokens issued from it. A code is now stored under a digest
that includes the Client Instance Key that pushed its authorization
request, so to any other installation it's unknown: neither spent nor
reused. Refresh tokens were already bound this way.

**What fails:** an attested authorization pushed before the upgrade and
exchanged after it fails with `invalid_grant`, and the app authorizes
again. That only affects flows in progress while the upgrade rolls out.

**What to change:** nothing.

### A client confined by `AllowedResources` no longer gets issuer-audience tokens (server, storage)

**Affects:** a server with resource indicators enabled (`Config.Resources`
or `Dependencies.ResourcePolicy`) where a client registered with
`storage.RegisteredClientConfig.AllowedResources` makes a request that
names no resource: at PAR, in a CIBA request, for client credentials, or
through `IssueAccessToken`/`IssueRefreshToken`. Also such a client's
grants made without resources, at their next code exchange, refresh or
CIBA token request.

**Why:** a request naming no resource got an access token addressed to
the issuer, which `AllowedResources` was never checked against. Every
resource server accepting the issuer as an audience took it — one
migrating with `serverresource.Options.AcceptIssuerAudience` or the
issuer in `AdditionalAudiences`, and the UserInfo endpoint — so a client
refused a resource could get a token it accepts simply by naming none.

**What fails:** for a client with exactly one `AllowedResources` entry, a
request naming no resource is now for that resource: the grant records
it, and its access tokens are addressed to it, not the issuer. It's
checked against `Config.Resources` and the `ResourcePolicy` as a named
one is, so if the server doesn't accept it the request fails with
`invalid_target`. For a client with several entries, a request naming
none fails with `invalid_target` ("a resource is required"). A grant made
without resources before the client was confined gets the same: its
single resource, or `invalid_target`, so the client must authorize
again. Nothing changes for clients without `AllowedResources`, or while
resource indicators are disabled.

**What to change:** a confined client that also calls the UserInfo
endpoint, which accepts only issuer-audience tokens, lists the issuer
identifier in its `AllowedResources` (and the server accepts it, in
`Config.Resources`, say); having more than one entry, it then names a
resource in every request. A confined client with several entries names
the resource it wants on every request. To confine clients registered
through OpenID Federation too, set the new
`AutomaticRegistrationConfig.AllowedResources`.

### A statically registered client authenticates with its static keys only (federation, server)

**Affects:** a server with OpenID Federation automatic registration (or
a `federation.AutomaticClientKeySource` built by hand) where a client in
`Dependencies.Clients` has a `client_id` that is also an Entity
Identifier resolving under one of `AutomaticRegistration.TrustAnchors`,
and that client signs with a key `Dependencies.ClientKeys` doesn't
return for it. Also a client `Dependencies.Clients` doesn't have, for
which `Dependencies.ClientKeys` does return keys.

**Why:** when `Dependencies.ClientKeys` had no matching key for a client,
its keys were looked up in its federation metadata instead, even for a
statically registered client. Any superior in a Trust Chain can set that
metadata's `jwks`, so a key it published authenticated as the static
client, with the static registration's scopes and grants.

**What fails:** a statically registered client's keys now come from
`Dependencies.ClientKeys` alone; an assertion or request object signed
with a key only its federation metadata publishes fails with
`invalid_client`. A client resolved through federation gets its keys from
its federation metadata alone, never from `Dependencies.ClientKeys`.
Whether a client is statically registered is decided as `ResolveClient`
decides it: `Dependencies.Clients` resolves it. If that store fails with
`storage.ErrStoreUnavailable`, key resolution now fails with that error
too.

**What to change:** give each statically registered client's keys to
`Dependencies.ClientKeys`, or remove its static registration so that it
registers automatically (with automatic registration's scopes and
grants).

### Automatic registration holds RP Metadata Choices to the policy on the singular parameter (federation)

**Affects:** a Relying Party registered automatically under a Trust
Anchor or Intermediate whose `metadata_policy` sets `one_of` or `value` on
`token_endpoint_auth_signing_alg` or `token_endpoint_auth_method`, and
which declares algorithms or methods outside it in
`token_endpoint_auth_signing_alg_values_supported` or
`token_endpoint_auth_methods_supported`, or names no algorithm at all.
Also a Relying Party whose `token_endpoint_auth_signing_alg_values_supported`
or `token_endpoint_auth_methods_supported` is an empty array.

**Why:** a policy operator applies only to the parameter it names, and
`one_of` only when that parameter is present (OpenID Federation 1.0
§6.1.3.1.4). A Relying Party could leave out
`token_endpoint_auth_signing_alg` and list a forbidden algorithm in its
RP Metadata Choices sibling, or name none and get the server's defaults,
and register an algorithm or method the policy rules out. An empty array
(which a superior's `subset_of` can leave) was read as not declared, so
the defaults applied there too.

**What fails:** algorithms and methods outside the policy on the singular
parameter are no longer registered, from either parameter or from
`AutomaticRegistrationConfig.ClientAssertionAlgorithms`. A Relying Party
left with none, or declaring an empty array, isn't registered, and its
requests fail with `invalid_client` (`OnResolutionFailure` is told why).
A Relying Party whose `token_endpoint_auth_method` or
`token_endpoint_auth_signing_alg` isn't in its own empty array is refused
too, as RP Metadata Choices requires it to be in the list.

**What to change:** nothing on the OP. A refused Relying Party lists an
algorithm or method its superiors' policy permits.

### Automatic registration refuses empty-string metadata (federation)

**Affects:** a Relying Party registered automatically whose
`openid_relying_party` metadata gives `""` for a string parameter
automatic registration reads, such as `subject_type`, `client_name`,
`logo_uri` or `request_object_signing_alg`. v0.58.0 already refused it
for the ID token and UserInfo encryption parameters.

**Why:** a metadata policy counts `""` as present, so it met an
`essential` policy (OpenID Federation 1.0 §6.1.3.1.7), while automatic
registration read it as left out and applied the OP's default instead,
such as its default `subject_type`.

**What fails:** the Relying Party isn't registered, and its requests fail
with `invalid_client` (`OnResolutionFailure` names the parameter).

**What to change:** nothing on the OP. A refused Relying Party leaves the
parameter out, or gives it a value.

### Opaque access tokens record their issuer, and resource servers check it (resource, server)

**Affects:** a resource server using `resource.OpaqueAccessTokens`
(directly or through `resource.NewOpaqueAccessTokens`; not one built by
`serverresource.NewVerifier`, which sets everything itself), and code
that calls `server.OpaqueAccessTokens.IssueAccessToken` directly rather
than through the server.

**Why:** an opaque access token's record kept no issuer, and
`resource.OpaqueAccessTokens` checked only its audience. Where two
issuers' servers shared an `AccessTokenStore` (forbidden, see the
`storage` package documentation, but the issuer stamp is there as a
backstop for exactly that mistake) and named the same resource, one
tenant's token was accepted by the other's resource server and acted for
that tenant's user with the same internal subject. A JWT access token's
`iss` already prevented this.

**What fails:** `resource.NewOpaqueAccessTokens` now takes the issuer as
a second argument, and `NewVerifier` refuses a `resource.OpaqueAccessTokens`
without `Issuer`. A token whose record names another issuer, or none, is
refused with `invalid_token`. Every opaque access token issued before
this release has no recorded issuer, so it stops working on upgrade:
these are short-lived (`Limits.AccessTokenLifetime`), and a client
holding one gets a new one with its refresh token or by authorizing
again. With `Audience` set, a record with no audience is now refused
too, where it was accepted; every FAPIgo server since v0.57.0 records
one. `server.OpaqueAccessTokens.IssueAccessToken` fails without
`AccessTokenParams.Issuer`, which the server always sets. The record's
issuer is kept in its `Claims`, as its audience already was, so a store
that persists `Claims` needs no change. `ResolvedAccessToken.Issuer`
(and `AuthorizationContext.Issuer`) is now the recorded issuer for an
opaque token, where it was always empty.

**What to change:** pass the authorization server's issuer to
`resource.NewOpaqueAccessTokens(store, issuer)`, or set
`OpaqueAccessTokens.Issuer` on a literal.

### Records written before v0.58.0 are refused (server)

**Affects:** a server holding records written by a version before
v0.58.0 (released 2026-10-20): in practice only refresh tokens, since
pushed requests, authorization codes and CIBA requests from then have
long expired.

**Why:** v0.58.0 began stamping the server's issuer into every request,
grant and CIBA record, and refusing one another issuer wrote, but still
accepted a record without one so an upgrade didn't fail requests in
flight. Such a record can't be told apart from another issuer's, and a
refresh token isn't rotated and can live for months, so the gap in the
backstop stayed open for as long as `Limits.RefreshTokenLifetime`.

**What fails:** a record without an issuer is now treated as unknown
everywhere it's read: a code exchange, refresh, token revocation and
CIBA token request answer `invalid_grant` (revocation answers as for an
unknown token, revoking nothing), `BeginAuthorization` an invalid
`request_uri`, and completing an interaction or a CIBA decision
`invalid_request`. A user whose client holds a refresh token issued
before v0.58.0 must authorize again.

**What to change:** nothing in code. Expect clients holding refresh
tokens from before 2026-10-20 to send their users through authorization
again.

### Grant revocation keys name their issuer (server, resource, storage)

**Affects:** a resource server with its own `resource.AccessTokenResolver`
whose tokens carry a `grant_id` or `code_grant_id` claim; a
`RevocationStore` that restricts the keys it accepts; and anything
reading the revocation store's keys directly.

**Why:** `RevokeGrant` recorded a grant ID as revoked under
`grant:<grant ID>`, and the application chooses grant IDs. Where two
issuers shared a revocation store, revoking one tenant's grant `g1`
revoked every other tenant's grant `g1` too.

**What fails:** a revoked grant is now recorded under `grant:`, the
grant ID, `@` and the server's issuer (`code-grant:` likewise, for a
reused authorization code's grant), so keys are longer and contain the
issuer URL. The server and `resource.Verifier` still also check the old
key, so a grant revoked before the upgrade stays revoked; those records
expire with the grant, and a later release may stop reading them.
`resource.Verifier` needs the token's issuer to build the key: a token
carrying either claim whose `ResolvedAccessToken.Issuer` is empty is
refused with 500 `server_error`. `JWTAccessTokens` and
`OpaqueAccessTokens` always report it.

**What to change:** a custom `AccessTokenResolver` sets
`ResolvedAccessToken.Issuer` to the issuer that issued the token. A
`RevocationStore` with a key length or character limit allows for the
issuer URL; `storage.TestRevocationStoreContract` covers such keys.

### `RevokeToken` takes the `TokenSet` (client)

**Affects:** every caller of `client.Client.RevokeToken`.

**Why:** `RevokeToken` took a bare refresh token, so nothing tied it to
the issuer it came from. In an application with one `Client` per
issuer, one issuer's refresh token passed to another issuer's client was
posted to that other issuer's revocation endpoint, where
`RefreshTokens` would have refused the same token set.

**What fails:** `RevokeToken(ctx, refreshToken)` no longer compiles. It
is now `RevokeToken(ctx, tokens)` with a `client.TokenSet`, and it
refuses, with `ErrorInvalidRequest` and before sending anything, a set
with no refresh token, one from another issuer, or one that records no
issuer (`TokenSet.Issuer`, or its ID token's `iss`), exactly as
`RefreshTokens` does.

**What to change:** pass the `TokenSet` the refresh token came in, as
`ExchangeCode`, `RefreshTokens` or `TokenSetSealer.Open` returned it. If
you kept only the refresh token, build
`client.TokenSet{RefreshToken: rt, HasRefreshToken: true, Issuer: iss}`
with the issuer you got it from.

### `TokenSetSealer.Seal` refuses a set that records no issuer (client)

**Affects:** a client sealing a `TokenSet` built by hand, or kept from
before `TokenSet.Issuer` existed, with neither `Issuer` nor an ID token
carrying `iss`.

**Why:** `Open` sets `Issuer` to the sealing client's issuer, so sealing
an issuer-less set relabelled it: `RefreshTokens`, which refuses a set
that records no issuer, then sent its refresh token to the sealing
client's issuer, whichever issuer the token came from.

**What fails:** `Seal` returns `ErrorInvalidRequest` for such a set, as
it already did for one from another issuer. Sets sealed before the
upgrade still open.

**What to change:** set `TokenSet.Issuer` to the issuer the tokens came
from before sealing. Sets from `ExchangeCode`, `RefreshTokens`, CIBA
and `Open` already record it.

### `ExchangeCode` redeems only its own client's responses (client)

**Affects:** an application with more than one `Client` (one per
issuer, or two registrations at one issuer) that exchanges a
`ValidatedAuthorizationResponse` on a different `Client` from the one
whose `HandleAuthorizationResponse` returned it, and anything calling
`ExchangeCode` with the zero value.

**Why:** the authorization code, PKCE verifier and redirect URI went to
whichever client's token endpoint `ExchangeCode` was called on, so a
routing mistake handed one issuer's code and verifier to another.

**What fails:** `ExchangeCode` returns `ErrorInvalidRequest`, sending
nothing, for a response another issuer's or client ID's `Client`
validated, and for the zero value.

**What to change:** exchange on the `Client` that handled the callback,
or use `CompleteAuthorization`, which does both on one.

### `CallbackBindingDeviceLocalStore` is for native apps only (client, *production only*)

**Affects:** a client under `AssuranceProduction` with
`Config.CallbackBinding = CallbackBindingDeviceLocalStore` whose
`Config.RedirectURI` is https: a web client, typically a single
instance with a durable sessions store that doesn't declare
`CrossInstanceConsistent`.

**Why:** that binding finds a session by the callback's `state` alone.
v0.58.0 refused it only over a store declaring `CrossInstanceConsistent`,
but a single-instance web client's store also holds every browser's
sessions, so a callback for an attacker's own flow, delivered to a
victim's browser, completed there: login CSRF (RFC 9700 §4.7).

**What fails:** `client.New` returns an error naming
`CallbackBindingDeviceLocalStore` unless `RedirectURI` is a native app's:
loopback http to `127.0.0.1` or `[::1]`, or a private-use URI scheme.
The `CrossInstanceConsistent` refusal still applies. Development
assurance is unchanged.

**What to change:** a web client uses `CallbackBindingSessionHandle`, the
default, and passes the `SessionHandle` it kept with the browser
(`client/sessioncookie`) as `AuthorizationCallback.Session`.

### `resource.Limits.MaxClockSkew` is 10 to 60 seconds (resource, *production only*)

**Affects:** a `resource.Verifier` under `AssuranceProduction` whose
`Config.Limits.MaxClockSkew` is under 10 seconds or over 60.
`serverresource.NewVerifier` takes the server's own `MaxClockSkew`,
which `server.New` already holds to that range, so a verifier built
from it is unaffected.

**Why:** `server.New` enforced FAPI 2.0 Security Profile §5.3.2.1's
bounds (accept a JWT whose `iat` is up to 10 seconds in the future,
refuse one more than 60 seconds ahead), but a directly built verifier
accepted any skew, and the skew also extends how long past its `exp` a
token is still accepted: an hour's skew accepted an expired token for
an hour.

**What fails:** `resource.NewVerifier` returns an error naming
`limits.max_clock_skew`. Development assurance accepts any non-negative
skew, as before.

**What to change:** set `MaxClockSkew` between 10 and 60 seconds; 10
seconds is the usual choice.

### DPoP requests need a URL path in normal form (client)

Not a breaking change to an API: it's here because a request that used
to go out now fails.

**Affects:** a client under `SenderConstrainDPoP` that sends
`ResourceClient.Do` a URL whose path has `.` or `..` segments, or
percent-encodes an unreserved character (`%2e`, `%41`, `%7E`).

**Why:** a DPoP proof's `htu` names the path with those normalized away
(RFC 9449 §4.2), but the request goes out with the path as written. A
front end that routes by the raw path delivers `/rs-a/%2e%2e/rs-b/x` to
the resource server at `/rs-a/`, carrying a token and proof the one at
`/rs-b/` accepts: the first can replay them at the second.

**What fails:** `Do` returns `ErrorInvalidRequest` before sending
anything. A token, PAR or CIBA endpoint with such a path fails the same
way, as an internal error. Percent-encoded reserved characters (`%2F`),
trailing slashes and query strings are unaffected, as is
`SenderConstrainMTLS`.

**What to change:** resolve the path before sending (for a link a
server returned, `url.URL.ResolveReference` removes dot segments), and
don't percent-encode unreserved characters.

### DPoP nonces are bounded, and forgotten after a refused request (client, fapihttp)

Not a breaking change to an API: it's here for a custom
`DPoPNonceCache`, and for a server sending very large headers.

**Affects:** a `client.Dependencies.DPoPNonceCache` of your own, and a
`fapihttp.NewClient` transport talking to a server whose response
headers exceed 256 KiB.

**Why:** the client cached any `DPoP-Nonce` header, of any size, from
any response, per origin, and presented it on every later request there.
Another resource on the same origin could hand out a nonce large enough
that the honest resource server refused every request as too large
(431), never answering with the challenge that would replace it.

**What fails:** nothing that worked before. The client now caches a
nonce only from a successful response or a `use_dpop_nonce` challenge,
and only one of RFC 9449's syntax (`1*NQCHAR`) of at most 1024 bytes;
after any other 4xx it calls `DPoPNonceCache.Set` with an empty nonce to
forget the origin's. `fapihttp.NewClient`'s transport refuses a response
whose headers exceed 256 KiB (net/http's default is 10 MiB).

**What to change:** a custom `DPoPNonceCache` treats `Set` with `""` as
forgetting the scope's nonce (storing `""` works too: the client ignores
an empty or malformed cached value).

## v0.58.0

### Automatic registration skips `tls_client_auth` unless chains are verified (server)

**Affects:** a server with OpenID Federation automatic registration
whose `ClientCertificateTrust` isn't `TrustedClientCAs`, where a Relying
Party authenticates with `tls_client_auth` (or a SAN variant) and
`AutomaticRegistration.AllowedClientAuthMethods` is empty.

**Why:** a Relying Party's `tls_client_auth_subject_dn` (or SAN) is
public in its metadata. With nothing verifying the certificate's chain,
anyone could present a self-signed certificate naming it and
authenticate as that RP: get client credentials tokens, redeem a leaked
refresh token, or revoke its tokens.

**What fails:** with an empty `AllowedClientAuthMethods`, automatic
registration no longer registers `tls_client_auth` or its SAN variants
unless `ClientCertificateTrust` is `TrustedClientCAs`. An RP that lists
another method too is registered for that one; an RP offering only
`tls_client_auth` isn't registered, and its requests fail with
`invalid_client` (`OnResolutionFailure` is told why).

**What to change:** if your TLS termination verifies client certificate
chains, keep `NoClientCertificateChainTrust{}` and list the methods you
accept in `AutomaticRegistration.AllowedClientAuthMethods`, including
`storage.ClientAuthMethodTLSClientAuth`. Otherwise use `TrustedClientCAs`,
or leave those RPs on another method.

### `OpaqueAccessTokens.Audience` is required (resource, *production only*)

**Affects:** a `resource.Verifier` under `AssuranceProduction` whose
`Dependencies.AccessTokens` is a `resource.OpaqueAccessTokens` with no
`Audience`. `serverresource.NewVerifier` always sets one, so a verifier
built through it is unaffected.

**Why:** without `Audience`, the verifier accepted an opaque token
issued for any resource server, so restricting a token with RFC 8707
resource indicators had no effect there. RFC 9700 §2.3 says a resource
server "MUST refuse" a token issued for another. `JWTAccessTokens`
already required an audience.

**What fails:** `NewVerifier` returns an error naming
`OpaqueAccessTokens.Audience`.

**What to change:** set `Audience` to this resource server's own
identifier, the resource indicator clients name for it. If clients
don't name one, use the authorization server's issuer, which a FAPIgo
server records as the audience then. During a move from one to the
other, list the old audience in `AdditionalAudiences`.

### Each `Scope` element must be one scope (client)

**Affects:** a client passing more than one scope in a single `Scope`
element, such as `Scope: []string{"openid profile"}`, to
`BeginAuthorization`, `BeginBackchannelAuthentication`,
`RequestClientCredentialsToken` or `RefreshTokens`.

**Why:** the elements are joined with spaces on the wire, so the server
saw every scope while the client's own checks saw one element.
`[]string{"profile openid"}` asked for `openid`, but the client didn't
then require the ID token, so an authorization server could leave it
out unnoticed.

**What fails:** an element that is empty, or isn't one RFC 6749 §3.3
scope-token (a space, a control character, `"`, `\` or a non-ASCII
character), is refused with `invalid_request` before anything is sent.

**What to change:** pass each scope as its own element:
`[]string{"openid", "profile"}`.

### `CallbackBindingDeviceLocalStore` needs an unshared sessions store (client, *production only*)

**Affects:** a client under `AssuranceProduction` with
`Config.CallbackBinding = CallbackBindingDeviceLocalStore` whose
`Dependencies.Sessions` declares `CrossInstanceConsistent`.

**Why:** that binding finds a session by the callback's `state` alone,
which is safe only in a native app's own on-device store. A store
shared between server instances holds many user agents' sessions, and
there it brings login CSRF back (RFC 9700 §4.7).

**What fails:** `client.New` returns an error naming
`CallbackBindingDeviceLocalStore`.

**What to change:** a web client uses `CallbackBindingSessionHandle`, the
default, and passes `AuthorizationCallback.Session`. A native app's
store has no other instance to be consistent with, so it shouldn't
declare `CrossInstanceConsistent`.

### Production clients require `iss` in the authorization response (client, *production only*)

**Affects:** a client under `AssuranceProduction` with
`Config.AuthorizationResponseIssPolicy =
TolerateAbsentAuthorizationResponseIss`.

**Why:** FAPI 2.0 Security Profile §5.3.2.2 item 7 has the authorization
server return `iss` in the authorization response (RFC 9207), and
§5.3.3.2 item 5 has the client check it, against mix-up attacks. A
production FAPI client facing a server that leaves it out isn't facing
a FAPI server.

**What fails:** `client.New` returns an error naming
`TolerateAbsentAuthorizationResponseIss`.

**What to change:** set `RequireAuthorizationResponseIss`.
`NewFromDiscovery` already raises the policy to it when the server's
metadata says it supports `iss`.

### `Limits.RequestObjectLifetime` is at most 60 minutes (client)

**Affects:** a client that signs request objects
(`ProfileFAPISecurityWithMessageSigning` or
`PushedRequestEncodingRequestObject`) with
`Limits.RequestObjectLifetime` over 60 minutes.

**Why:** FAPI 2.0 Message Signing §5.3.2 item 4 has a client send a
request object whose `exp` is at most 60 minutes away, and a server
following §5.3.1 item 4 refuses a longer one.

**What fails:** `client.New` returns an error naming
`request_object_lifetime`.

**What to change:** set it to 60 minutes or less.
`RecommendedLimits` uses 60 seconds.

### The federation entity key must not be a protocol key (server)

**Affects:** a server with `Config.Federation.EntityID` set whose
`Dependencies.Keys` returns the same key for
`keys.FederationEntitySigning` as for any protocol signing purpose (ID
tokens, JARM, UserInfo, or access tokens).

**Why:** the entity key signs this server's Entity Configuration, which
vouches for its protocol keys. Reusing one of those for it lets anything
that key signs be presented as a statement of the entity itself.
`Config.Federation` already said the key is never reused; now `New`
checks.

**What fails:** `server.New` returns an error saying the federation
entity key is also a protocol key.

**What to change:** give `keys.FederationEntitySigning` its own key in
your key manager.

### Sealing keys must not be text (client, server)

**Affects:** a key passed to `client.NewTokenSetSealer`,
`client.NewBackchannelSessionSealer`, `client/sessioncookie` or
`server/interactioncookie` that is made entirely of printable text: a
passphrase, or a hex or base64 key passed without decoding it. Pairwise
keys already refused these.

**Why:** such a key has far less entropy than 32 random bytes, so
everything sealed under it (token sets, CIBA sessions, session and
interaction cookies) is open to anyone who guesses it.

**What fails:** the constructor returns an error saying the key is all
printable text.

**What to change:** generate the key with `crypto/rand`, and decode an
encoded key before passing it. A random key is refused with probability
about 4×10⁻¹⁴.

### Outbound TLS 1.2 uses only ECDHE AES-GCM suites (fapihttp)

**Affects:** a `fapihttp.NewClient` client connecting to a server that
offers, under TLS 1.2, only cipher suites outside the four ECDHE AES-GCM
ones (CBC suites, say). TLS 1.3 servers are unaffected. So is a client
built some other way.

**Why:** FAPI-CIBA §7.9 (as FAPI 1.0 Part 2 §8.5) permits only those
suites under TLS 1.2.

**What fails:** the TLS handshake with such a server. `HardeningOf` also
no longer counts a transport as hardened if its TLS 1.2 suites were
changed to include any other suite, or cleared back to Go's defaults.

**What to change:** nothing on your side; the server needs a TLS 1.2
ECDHE AES-GCM suite, or TLS 1.3.

### Attestation-based client authentication follows draft-12 (server, client)

Not a breaking change: clients built to draft-07 keep working, and so
does a FAPIgo client against a draft-07 server. It's here because a
server now answers a few requests differently.

**Affects:** a server with `Config.AttestationBasedClientAuthentication`,
and clients of it.

**What changes:**

- A Client Attestation or PoP without `iss` is accepted
  (draft-ietf-oauth-attestation-based-client-auth-08 removed it); one
  that has it is still checked. The attester is still established by
  the key that verifies the attestation, never by `iss`.
- An expired attestation is refused with `use_fresh_attestation` (HTTP
  400, §7.4), not `invalid_client` (401), once its signature verifies.
- A `client_id` parameter naming a different client than the
  attestation's `sub` is refused with `invalid_client`, at every
  endpoint and in `AuthenticateAttestedClient` (through
  `TokenEndpointRequest.AttestedClientAuthentication`, or the new
  `AttestedClientAuthenticationRequest.ClientID`).
- For a client registered for attestation and another method, an
  attested installation can no longer redeem or revoke a refresh token
  issued under the other method. Refresh tokens issued before v0.50.0
  aren't affected.
- PoP replay records are now kept per client instance, so a PoP first
  used within `Limits.MaxClientAttestationPoPAge` before the upgrade
  could be accepted once more after it.

**What to change:** nothing, unless an embedder treats a refused
attestation as `invalid_client` only: handle `use_fresh_attestation` by
getting a new attestation. A FAPIgo client follows the server's
attestation challenges by itself.

### Pass `NoPKIClientAuthentication{}` when no client uses `tls_client_auth` (server)

Not a breaking change: nothing stops working. It's here because the
quick start and the demos used to pass
`ClientCertificateTrust: server.NoClientCertificateChainTrust{}` for a
server with no mTLS clients, and that setting isn't safe for one.

**Affects:** a `server.Dependencies` with
`ClientCertificateTrust: server.NoClientCertificateChainTrust{}` whose
TLS termination doesn't verify client certificate chains
(`tls.RequestClientCert`, `RequireAnyClientCert`, or no client
certificates at all).

**Why:** `NoClientCertificateChainTrust{}` accepts a `tls_client_auth`
(or SAN-variant) client's certificate without verifying its chain. If
nothing in front of the server verifies it either, anyone can present a
self-signed certificate naming a registered subject or SAN and
authenticate as that client. (Automatic registration no longer
registers such methods by default; see above.)

**What to change:** if no client authenticates with a CA-issued
certificate, pass `server.NoPKIClientAuthentication{}`. It refuses
`tls_client_auth` and its SAN variants with `invalid_client`, keeps
automatic registration from registering them, and leaves
`self_signed_tls_client_auth` working. `server.New` refuses it together
with an `AutomaticRegistration.AllowedClientAuthMethods` that names one
of those methods. Keep `NoClientCertificateChainTrust{}` only where your
TLS termination verifies the chain (`RequireAndVerifyClientCert` with
`ClientCAs`, or a gateway that does), or use `TrustedClientCAs`.

### Records now carry their issuer; stores are per issuer (server)

Not a breaking change for a store: the records are the opaque JSON the
server already owns. A pushed request, authorization code, refresh token
or CIBA request written by a server with a different issuer is now
treated as unknown, so two tenants sharing one database can no longer
redeem each other's codes or refresh tokens. A record written before
this release carries no issuer and is accepted until it expires. Keep
each issuer's records apart anyway: see the `storage` package
documentation.

### `prompt` is bounded (server)

A pushed authorization request whose `prompt` is longer than 256 bytes,
or carries more than 16 distinct values, is refused with
`invalid_request`. OpenID Connect defines four values, so no real
request is affected.

### JWT timestamps: future `iat`/`nbf` refused, `exp` allows clock skew (server, resource, client)

Not a breaking change for a client with a working clock. Every JWT the
server or a resource server verifies now follows FAPI 2.0 Security
Profile §5.3.2.1 item 13:

- **Refused:** an `iat` or `nbf` further in the future than
  `Limits.MaxClockSkew`, in client assertions, request objects, CIBA
  requests, DPoP proofs and JWT access tokens. Attestations already
  were. A DPoP proof or access token that carries `nbf` or `exp` is now
  held to it, as RFC 7519 requires of any JWT.
- **Accepted that wasn't:** a JWT whose `exp` is up to the maximum
  lifetime *plus* `MaxClockSkew` away. A client or issuer whose clock
  runs ahead by no more than the skew can now use the full lifetime;
  before, the default 60s limits refused one even 1s fast. The client
  checks ID tokens, JARM responses and federation statements the same
  way.
- **Accepted that wasn't:** a non-integer NumericDate (`"exp":
  1800000000.5`), which RFC 7519 §2 allows; it's rounded down to the
  second.

## v0.57.0

### Read `resource` with `Resources()`, not `Parameters()` (server)

**Affects:** an embedder serving its own token-endpoint grant type
(`TokenEndpointRequest`, such as an OpenID4VCI pre-authorized code)
that reads `Parameters()["resource"]`.

**Why:** a client may send `resource` more than once (RFC 8707 §2).
`Parameters()` could hold only one value while `Resources()` returns
them all, so a grant that checked one and issued for the other could be
widened by repeating the parameter.

**What fails:** `Parameters()` no longer includes `resource`, so
`Parameters()["resource"]` is `""` even when the client sent one.
Nothing errors.

**What to change:** read `TokenEndpointRequest.Resources()`, and pass
what you accept to `IssueAccessTokenRequest.Resources` (and
`IssueRefreshTokenRequest.Resources`), which checks each against your
resource configuration.

### RFC 8707 resource indicators (server, resource; opt-in)

Nothing to change: resource indicators are off until you set
`server.Config.Resources` or `server.Dependencies.ResourcePolicy`, and a
request naming no resource still gets an access token addressed to the
issuer. [GETTING_STARTED.md](GETTING_STARTED.md#audience-restricted-tokens-rfc-8707-resource-indicators)
shows how to turn them on. Three things change whether or not you do:

- `server.OpaqueAccessTokens` now records each token's audience with it,
  under the claim name `aud` in `storage.NewAccessToken.Claims`, and
  `resource.OpaqueAccessTokens` returns it as
  `ResolvedAccessToken.Audience` (and `AuthorizationContext.Audience`)
  rather than among the claims. A store that keeps `Claims` needs no
  change.
- `serverresource.NewVerifier` now checks an opaque token's recorded
  audience, as it always checked a JWT's `aud`. A token recorded before
  this release has none and is still accepted, so for up to one access
  token lifetime after the upgrade an opaque token is accepted without
  an audience check; no token issued by this release lacks one.
- A custom `server.AccessTokenIssuer` keeps working: it gets the first
  resource in `AccessTokenParams.Audience`, so its tokens are still
  restricted to a resource the client named, and every resource in the
  new `Audiences` field. Issue `Audiences` as the token's audience to
  restrict it to all of them.

Once on, a grant's resources are checked against the current
configuration at every access token it issues, so removing a resource
from a client's `AllowedResources` or from `Config.Resources`, or
refusing it in the `ResourcePolicy`, takes effect at the client's next
refresh; turning resource indicators off again makes the grants that
named resources unusable until their clients authorize again.

Once a resource server verifies with its own identifier
(`serverresource.Options.Resource`, or `JWTAccessTokens.Audience` /
`OpaqueAccessTokens.Audience`), tokens from clients that don't send
`resource` yet are refused there. Accept them while clients move with
`serverresource.Options.AcceptIssuerAudience`, or the issuer in
`AdditionalAudiences`, and drop it once they all send it.

### Send resource indicators with `Resource`, not an extension (client)

Not a breaking change: nothing stops working. It's here because a
client already sending `resource` as an `Extensions` value only sends
it on the pushed request.

**Affects:** a `client` caller that sends RFC 8707's `resource`
parameter as an `Extensions` value on `BeginAuthorizationRequest`, such
as an OpenID4VCI wallet naming its Credential Issuer.

**Why:** RFC 8707 §2.2 has the token request name the resource again,
and the extension can't reach the code exchange or a refresh.
`BeginAuthorizationRequest.Resource` does: the client sends it on the
pushed request, the code exchange and each refresh (`TokenSet.Resource`
carries it, sealed sets included). `BeginBackchannelAuthenticationRequest.Resource`
does the same for CIBA.

**What fails:** `BeginAuthorization` refuses a request that sets both
`Resource` and an `Extensions` value named `resource`. `Resource` is
also checked before anything is sent: each must be an absolute URI
without a fragment, and none empty or repeated.

**What to change:** move the value from `Extensions` to `Resource`.
Before rolling it out over several instances, finish deploying v0.57.0
to all of them first if you seal CIBA sessions
(`BackchannelSessionSealer`): an older instance can't open a session
sealed with resource indicators. Sealed token sets are read in both
directions.

## v0.56.0

### A production client's HTTP client must be `fapihttp.NewClient`'s (client, *production only*)

**Affects:** a `client.Config` with `Assurance: client.AssuranceProduction`
whose `Dependencies.HTTP` isn't the `*http.Client` `fapihttp.NewClient`
returned.

**Why:** the endpoints a client calls can come from fetched metadata
(`NewFromDiscovery`, `DiscoverViaFederation`), and only
`fapihttp.NewClient`'s transport refuses private, loopback and
link-local addresses when it dials. The docs always said to use it;
`New` now checks, with `fapihttp.HardeningOf`.

**What fails:** `New` refuses, under production only:
- a `Dependencies.HTTP` that isn't an `*http.Client`, or one
  `fapihttp.NewClient` didn't build (`http.DefaultClient`, your own);
- `NewClient`'s client after its transport was changed in a way that
  affects where it connects or how it verifies the server, cloned
  (`Transport.Clone`) or wrapped in another `RoundTripper`. That's:
  - a `Proxy`, a `DialContext` other than its own (including another
    `NewClient` transport's), `Dial`, `DialTLS` or `DialTLSContext`;
  - in `TLSClientConfig`: `InsecureSkipVerify`, a TLS version below 1.2,
    `RootCAs` or `VerifyConnection` other than the ones it was built
    with, or any `VerifyPeerCertificate`, `ServerName`, `Time`,
    `KeyLogWriter` or insecure cipher suite;
- one built with a loopback exception (`AllowLoopbackHosts`,
  `AllowLoopbackHTTP` or `AllowedLoopbackHosts`).

A copy of `NewClient`'s client (`c2 := *c` with its own `Timeout`, say)
and `AllowedPrivateHosts` are accepted. Development assurance is
unchanged.

**What to change:** build `Dependencies.HTTP` with
`fapihttp.NewClient(fapihttp.RecommendedTransportConfig())`. If you
added a client certificate for mutual TLS by changing the transport's
`TLSClientConfig`, set `fapihttp.TransportConfig.Certificates` (or
`GetClientCertificate`) instead; setting `TLSClientConfig.Certificates`
afterwards also still passes. Likewise set a private CA's roots with
`TransportConfig.RootCAs`, and certificate pinning with
`TransportConfig.VerifyConnection`, not on the transport afterwards. An
instrumented, wrapped transport is refused in production.

`NewClient`'s transport also already has `"https"` and `"http"`
registered, so `Transport.RegisterProtocol` for either panics, in every
assurance level: a `RoundTripper` registered for them would send
requests around the address-validating dialer. Requests themselves are
made as before, over HTTP/2 or HTTP/1.1.

### Fetchers must wrap `fapihttp.NewClient`'s client too (keys, server, *production only*)

**Affects:** under `AssuranceProduction`:
- a `keys.JWKSIssuerKeySource` (from `keys.NewJWKSIssuerKeySource` or
  `client.DiscoveredMetadata.IssuerKeySource`) used as a production
  dependency: `client.Dependencies.IssuerKeys`, a resource server's JWT
  issuer keys, or a server key source;
- `server.Dependencies.FederationHTTP`;

whenever its `*fapihttp.Client` fetcher was built by `fapihttp.New` over
anything other than the `*http.Client` `fapihttp.NewClient` returned.

**Why:** `fapihttp.New` accepts any HTTP client, and a fetcher over
`http.DefaultClient` still checks each URL and the addresses its host
resolves to before fetching. But only `NewClient`'s transport checks the
address it actually dials, which is what holds when DNS changes between
the two (DNS rebinding). `fapihttp.Client` now reports this:
`Hardening` (checked at each call) and `HardenedForProduction`, which
also refuses a loopback exception on the transport or the fetcher.

**What fails:**
- A `JWKSIssuerKeySource` over such a fetcher no longer declares
  `LiveFetchHardened`, so every production check that requires it
  refuses the source (it previously required only that the fetcher
  grant no loopback exception).
- `server.New` refuses such a `FederationHTTP`.

Development assurance is unchanged, and `AllowedPrivateHosts` is still
accepted.

**What to change:** build every fetcher from one transport:

```go
transport, err := fapihttp.NewClient(fapihttp.RecommendedTransportConfig())
fetcher, err := fapihttp.New(transport, fapihttp.RecommendedConfig())
```

## v0.55.0

### `Config.Subjects` is required (server)

**Affects:** every `server.Config` that isn't `OAuthOnly`.

**Why:** a user's `sub` is an identifier relying parties store as the
account key. The new `Config.Subjects` (`server.SubjectConfig`) states
which kind it is (OpenID Connect Core §8): the same at every client
(public), or derived per sector of clients so that clients in different
sectors can't correlate the user (pairwise). It has no default, so
choosing between them is never left to the library. `New` refuses a
zero `Subjects` with `subjects.default is required`.

**What to change:** set `Subjects: server.PublicSubjects()`. Every `sub`
stays exactly as it is today, and nothing else is needed: no deriver,
no key, no change to any client.

```go
cfg := server.Config{
	// ...
	Subjects: server.PublicSubjects(),
}
```

An `OAuthOnly` server may leave `Subjects` zero, which means public.

The rest of this release's subject settings are additions: pairwise
subjects (a pairwise `Default`, or a client's `SubjectType` and
`Sector` on `storage.RegisteredClientConfig`, with
`Dependencies.PairwiseSubjects`; see GETTING_STARTED's "Pairwise
subjects"). A client registered with `SubjectType:
fapi.SubjectTypePairwise` must have a sector, set or derived from its
redirect URIs, or `storage.NewRegisteredClient` refuses it. A client
permitted CIBA, or one that may authenticate by attestation, derives
none: its tokens arrive without a redirect proving the client is served
on its redirect URIs' host, so such a pairwise client sets `Sector` (a
host name, which you set; never take it from the client) itself.

### `AuthorizationContext.Subject` is renamed `InternalSubject` (resource)

**Affects:** every resource server, whether or not it uses pairwise
subjects.

`resource.AuthorizationContext.Subject` is now `InternalSubject`, and
it's left out of the struct's JSON encoding. The value is unchanged:
the token's subject as the authorization server knows it. The rename
makes every resource server choose, at each use, between the two
subjects a request now carries:

- **`InternalSubject`**: for your own authorization decisions only.
- **`ClientSubject`**: anything returned to, or compared with what
  comes from, the client. For a public client it's the same value.

```go
// Before
c := customerByID(authz.Subject)
// After
c := customerByID(authz.InternalSubject)
```

Then check every place the old `Subject` reached a client: a `/me`
endpoint, a response body, a UserInfo `sub` built by hand, an error
message or a log the client can read. Use `ClientSubject` there. For a
client with pairwise subjects, `InternalSubject` is exactly what its
`sub` hides.

### A federation Relying Party's `subject_type` is honoured or refused (federation, server)

**Affects:** a server with `Config.AutomaticRegistration`, and code
building `federation.AutomaticClientRepository` itself.

**Why:** an automatically registered Relying Party's `subject_type`
metadata (OpenID Connect Dynamic Client Registration 1.0 §2) used to be
ignored, so one asking for pairwise subjects silently got public ones,
the identifier it asked not to be given. Now the client gets the
`subject_type` it names, or the server's default when it names none,
and a Relying Party asking for a type the server doesn't issue isn't
registered: it gets `invalid_client`, and
`AutomaticRegistration.OnResolutionFailure` hears
`subject_type pairwise is not one this OP issues`. A pairwise Relying
Party's sector is its Entity Identifier's host, which the Trust Chain
binds to it: its redirect URIs must all be https on that host (so it
can't name another Relying Party's host and receive that Relying
Party's sub values), and it must not publish `sector_identifier_uri`,
which this release doesn't fetch (nor may a superior's metadata policy
add one). Relying Parties whose Entity Identifiers share a host share a
sector, and so each user's `sub`.

**What to change:** nothing, unless a Relying Party you federate with
asks for `"subject_type": "pairwise"` while your server issues only
public subjects: it now fails to register until the server can issue
pairwise subjects. `server.New` sets the new
`federation.AutomaticRegistrationConfig.SubjectTypes` and
`DefaultSubjectType` from `Config.Subjects`; code building an
`AutomaticClientRepository` directly can leave them zero, which means
public only. Under a pairwise `Config.Subjects.Default`, federation
Relying Parties are offered pairwise subjects only, so one can't opt
out of the default by asking for public; list both in
`Config.AutomaticRegistration.SubjectTypes` to offer public too. That
setting also narrows what they're offered in other configurations.
`Server.EntityConfiguration` sets its `openid_provider` metadata's
`subject_types_supported` to what federation Relying Parties are offered
(`Server.AutomaticRegistrationSubjectTypes()`).

### Adopting pairwise subjects (server, resource)

**Affects:** only a deployment that gives some client pairwise
subjects. Nothing changes for one that keeps `PublicSubjects()`.

> **Check every resource server before giving any client pairwise
> subjects.** For a pairwise client,
> `resource.AuthorizationContext.InternalSubject` is the user's
> *internal* subject, the very identifier the client's pairwise `sub`
> hides. Code that sends it back to the client (a `/me` endpoint, a
> response body, a UserInfo `sub`, a log the client can read) leaks it.
> Send `ClientSubject` instead, and authorize by `InternalSubject`.

- **Resource servers:** `resource.AuthorizationContext.InternalSubject`
  is the user's internal subject; the new `ClientSubject` is the `sub`
  the client was given. Compare user IDs a client sends (in a path, a
  body, or an ID token) with `ClientSubject`: for a pairwise client
  they're no longer `InternalSubject`. The OP's own standalone resource
  server verifying JWT access tokens from a server with a reversible
  deriver sets `resource.Dependencies.PairwiseSubjects` and
  `Config.PairwisePrefix`; `serverresource.NewVerifier` wires both.
- **A resource server outside the OP** (a third party accepting your
  access tokens) must never get the keys, store or resolver that
  reverse pairwise subs (OpenID Connect Core §8.1 reserves that to the
  OP). It sets `resource.Config.PairwiseResolution` to
  `resource.PairwiseClientSubjectsOnly` instead: `InternalSubject` is
  then `""` for a pairwise sub, and it authorizes by `ClientSubject`
  and `ClientID`.
- **A one-way deriver** (`pairwise.NewHMAC`, `pairwise.NewHMACWith`) requires `server.OpaqueAccessTokens`: a one-way
  `sub` can't be mapped back, so the internal subject must stay in a
  server-side token record. To issue JWT access tokens instead, keep
  your own record of the subs you issue as a `pairwise.SubjectResolver`,
  set it as `server.Dependencies.PairwiseSubjectResolver`, and give the
  same one to every one of the OP's own resource servers
  (`resource.Dependencies.PairwiseSubjectResolver`).
- **A custom `server.AccessTokenIssuer`** gets the pairwise `sub` as
  `AccessTokenParams.Subject` and the internal subject as the new
  `InternalSubject`. Never put `InternalSubject` in a token the client
  can read; an issuer that keeps tokens server-side should record it,
  as `OpaqueAccessTokens` does.
- **Readable access tokens:** a JWT access token's other claims (a
  `GrantID`, extension claims) must not identify the user either.
- **Switching to `SubjectTypesPairwiseOnly`** ends existing grants made
  while their client got public subs: their next refresh (or code or
  CIBA token exchange) fails with `invalid_grant`, and the client
  authorizes again, now with a pairwise `sub`. A grant keeps the `sub`
  it was issued with, so it can't move to a pairwise one in place.
  Under `SubjectTypesPerClient`, existing grants keep their `sub`.
- **Changing `Config.Subjects.Prefix`** later ends every pairwise grant
  the same way, since resource servers resolve a `sub` under the
  current prefix. Choose it once.
- **Changing a client's sector** (its `Sector`, or the redirect host it
  derives one from) gives its users new `sub`s at their next
  authorization; existing grants keep theirs. With an empty prefix,
  though, `Server.SignUserInfoResponse` checks a pairwise `sub` by
  mapping it back under the client's current sector, so signed UserInfo
  for those existing grants fails with `server_error` until they're
  reauthorized. Deployments with a prefix aren't affected.

## v0.54.0

### An authentication time can't be in the future (server, client)

**Affects:** an application that passes `NewAuthenticationContext` an
`authTime` later than now (a session's expiry instead of when the user
logged in, say) or before the Unix epoch; and a relying party using
this library's `client` against a server that issues such an
`auth_time`.

**Why:** `auth_time` is when the user authenticated. One later than now
didn't happen, but passed `max_age=0` and `prompt=login`, which exist to
force a fresh authentication, as the freshest one possible, and reached
the ID token. Now:

- **`CompleteAuthorization` and `CompleteBackchannelAuthentication`**
  refuse an `Authorize` whose authentication time is later than now
  plus `Limits.MaxClockSkew`, with `server_error`, as they already
  refused a zero `AuthenticationContext{}`.
- **`NewAuthenticationContext`** refuses an `authTime` before the Unix
  epoch, which no `auth_time` can express.
- **The client** refuses an ID token whose `auth_time` is later than
  now plus its `Limits.MaxClockSkew`, or negative, with
  `invalid_response`, on every flow.

**What to change:** pass the time the user actually authenticated.

### CIBA request objects live at most 60 minutes in production (server, *production only*)

**Affects:** a server under `AssuranceProduction` with CIBA enabled
(`Endpoints.BackchannelAuthentication`) whose
`Limits.MaxBackchannelAuthenticationRequestLifetime` is over 60 minutes.

**Why:** FAPI-CIBA §5.2.2 requires a signed authentication request's
`nbf` and `exp` to "limit the lifetime of the request to no more than 60
minutes". `New` now refuses a longer limit under production, reported
with the other FAPI limits. Development assurance is unchanged.

**What to change:** set `MaxBackchannelAuthenticationRequestLifetime` to
60 minutes or less. A request object only needs to live long enough to
reach the server, so a minute or two is plenty.

### A CIBA approval keeps `openid` (server)

**Affects:** an application whose CIBA approval grants a scope without
`openid`, such as `GrantedAuthorization{Scope: []string{"accounts"}}`
for a request asking for `openid accounts`.

**Why:** a CIBA request carries `openid` (required since v0.53.0), and
CIBA Core §10.1.1 requires an ID token in its token response. An
approval that dropped `openid` produced a token response with an access
token and no ID token: a CIBA login with no identity.
`CompleteBackchannelAuthentication` now refuses it with
`invalid_request`, as it refuses a scope beyond the request's, and the
request stays pending for a corrected decision.

**What to change:** keep `openid` in `GrantedAuthorization.Scope` when
approving a CIBA request; narrow the other scopes as you like.

## v0.53.0

### A requested subject is enforced (server)

**Affects:** a server whose clients send `id_token_hint`, or a `claims`
parameter requesting a specific `sub` value, such as
`{"id_token":{"sub":{"value":"248289761001"}}}`, to the pushed
authorization request or the CIBA backchannel authentication endpoint.

**Why:** OIDC Core §3.1.2.2 says the server MUST NOT reply with an ID
token or access token for a different user than a requested `sub`
names (§5.5.1), and `id_token_hint` (§3.1.2.1, CIBA Core §7.1) names
the user the same way. The pushed authorization request dropped
`id_token_hint` as an unregistered parameter, CIBA passed it to the
application unverified, and a `sub` value was never read, so a request
for one user could be answered for whoever logged in. Now:

- **`id_token_hint` is verified** at both endpoints, in plain
  parameters or a request object. It must be an ID token this server
  issued: signed with one of its ID-token keys, current or `Previous`,
  under `Algorithms.IDToken`, with this server's `iss`, and an `aud`
  that includes the requesting client (and an `azp`, if present, equal
  to it). Its expiry isn't checked, as OIDC Core allows an expired one.
  An encrypted ID token isn't accepted: the client decrypts it and
  sends the signed ID token inside. Anything else is `invalid_request`,
  as is any hint under `Config.OAuthOnly`.
- **A `sub` value** in the `claims` parameter (`id_token` or
  `userinfo`) is read. One that isn't a non-empty string, a miscased
  `value` member, and a hint and `sub` value (or two `sub` values) that
  name different users are `invalid_request`.
- **The user reaches your login page** as
  `InteractionRequest.RequiredSubject` (kept by `MarshalText`) and
  `BackchannelInteractionRequest.RequiredSubject`.
- **A completion for anyone else is refused:** `CompleteAuthorization`
  answers the client with `login_required` and no code, and
  `CompleteBackchannelAuthentication` records a failed authentication,
  so the client's poll gets `access_denied`. Requests made before
  upgrading aren't checked.

**What to change:** when `RequiredSubject` isn't empty, authenticate
that user. If another user is logged in, ask them to log in as the
required one, or complete with `AuthenticationFailed` (or
`InteractionNeeded(NeedLogin, ...)` for `prompt=none`).

### CIBA requests must include `openid` (server)

**Affects:** a server with CIBA enabled (`Endpoints.BackchannelAuthentication`)
whose clients send a backchannel authentication request without the
`openid` scope, or that sets `Config.OAuthOnly` together with CIBA; and
a ping-mode CIBA client whose `client_notification_token` is longer than
1024 characters or isn't a Bearer token.

**Why:** CIBA is an OpenID Connect authentication flow, and CIBA Core
§7.1 requires the request's scope to include `openid`. A request without
it is now refused with `invalid_scope`. `OAuthOnly` refuses `openid`, so
a CIBA endpoint can no longer be configured with it, and `New` fails
naming `oauth_only`. The same section limits `client_notification_token`
to 1024 characters with RFC 6750 §2.1 Bearer syntax; a token outside
that is now `invalid_request`. The server sends this token back in an
`Authorization` header, so arbitrary characters there could reach the
client's notification request.

**What to change:** send `openid` in every CIBA request's `scope`.
Remove `OAuthOnly` from a configuration that enables CIBA, or disable
CIBA there. This library's `client` already generates valid
notification tokens; if another client sends its own, keep it to
`A-Z a-z 0-9 - . _ ~ + /`, optionally followed by `=` padding.

### FAPI 2.0's fixed limits are enforced under production (server, *production only*)

**Affects:** a server under `AssuranceProduction` whose `Config.Limits`
go outside the FAPI 2.0 Security Profile's numbers.

**Why:** FAPI 2.0 fixes a few numbers: authorization codes live at most
60 seconds (§5.3.2.1), a `request_uri`'s `expires_in` is under 600
seconds (§5.3.2.2), and JWTs with `iat`/`nbf` up to 10 seconds in the
future are accepted but not more than 60 (§5.3.2.1). Out-of-range values
used to be accepted silently, taking a production deployment out of the
profile. `New` now refuses, under `AssuranceProduction`:

- `AuthorizationCodeLifetime` over 60 seconds;
- `PushedRequestLifetime` of 600 seconds or more;
- `MaxClockSkew` under 10 or over 60 seconds;
- `MaxRequestObjectLifetime` over 60 minutes.

It reports every violation at once. `RecommendedLimits()` is within all
of them. Development assurance is unchanged.

**What to change:** start from `server.RecommendedLimits()`, or bring
the named fields within range. The most likely one is `MaxClockSkew`:
a value under 10 seconds (including zero) must now be at least 10
seconds.

### A subject ID is at most 255 printable ASCII characters (server)

**Affects:** an application that passes `NewSubjectID` a value longer
than 255 bytes, or one with non-ASCII or control characters: an email
address with an internationalized local part, say, or a display name.

**Why:** OIDC Core §2 says `sub` "MUST NOT exceed 255 ASCII characters
in length". Longer or non-ASCII values were accepted and issued in ID
tokens that relying parties may refuse. Control characters, never
needed in an identifier, are refused too.

**What to change:** use a stable identifier of your own (a database key
or opaque ID) as the subject, and return names and email addresses as
claims. `NewSubjectID` now returns an error for any other value. Grants
issued before the upgrade keep their subject; only new authentications
are checked.

## v0.52.0

### An essential `acr` request is enforced (server)

**Affects:** a server whose clients send the `claims` parameter with an
essential `acr` request for the ID token, such as
`{"id_token":{"acr":{"essential":true,"values":["urn:example:gold"]}}}`,
and whose application completes such a request with an authentication
at a different class.

**Why:** OIDC Core §5.5.1.1 says that when `acr` is requested as an
Essential Claim with a value or values, the authorization server MUST
return an `acr` matching one of them, or treat the outcome as a failed
authentication. The server kept only the requested claim names, so the
values never reached the application, and an ID token could carry a
lower `acr` than the relying party required for step-up. It now
surfaces them as `InteractionRequest.EssentialACRValues` (and
`BackchannelInteractionRequest.EssentialACRValues` for CIBA), and
refuses a completion whose `acr` isn't one of them:
`CompleteAuthorization` answers the client with `login_required` and no
code, and `CompleteBackchannelAuthentication` records a failed
authentication, so the client's poll gets `access_denied` and no
tokens. A pushed or backchannel request whose id_token `acr` entry is
malformed (not an object, or an `essential`, `value` or `values` of the
wrong type) is now `invalid_request`. A voluntary `acr` request, and
`acr_values`, remain the client's preference only. Requests made before
upgrading aren't checked.

**What to change:** when `EssentialACRValues` isn't empty, authenticate
the user at one of those classes and pass it as the `acr` of
`NewAuthenticationContext`. If you can't, complete with
`AuthenticationFailed` (or `InteractionNeeded` for `prompt=none`), as
the relying party asked for an authentication you can't provide.

### `Resolver.VerifyTrustMark` takes the subject's resolved Trust Chain (federation)

**Affects:** callers of `federation.Resolver.VerifyTrustMark`.

**Why:** a Trust Mark's accreditation (`trust_mark_issuers`) and
delegation requirement (`trust_mark_owners`) were read from whichever
Trust Anchor the mark's *issuer* happened to resolve through. With
several Trust Anchors configured on one `Resolver`, an issuer accredited
only by a lax federation then passed `RequireFederationAccreditation`
for a subject of a strict federation that never accredited it. The
issuer's chain must now end at the subject's own Trust Anchor, and the
accreditation comes from there.

**What to change:** pass the subject's `ResolvedEntity`, as `Resolve`
returned it from the same `Resolver`, instead of its Entity Identifier:

```go
subject, err := resolver.Resolve(ctx, subjectID)
// ...
for _, mark := range subject.TrustMarks {
	claims, err := resolver.VerifyTrustMark(ctx, subject, mark,
		federation.RequireFederationAccreditation)
	// ...
}
```

A `ResolvedEntity` whose `TrustAnchor` isn't one of the `Resolver`'s is
refused. A mark whose issuer is a member only of another federation
configured on the same `Resolver` is now refused even under
`AcceptAnyFederationIssuer`, since its issuer can't be trusted through
the subject's Trust Anchor. With a single Trust Anchor nothing else
changes.

### Client credentials tokens say so, and two token claims are reserved (server, resource)

**Affects:**
- a resource server that authorizes by `resource.AuthorizationContext.Subject` while its authorization server issues client credentials tokens;
- a server whose extension returns a `grant_type` or `code_grant_id` claim in tokens (`ReturnInTokenClaims`);
- a custom `resource.AccessTokenResolver` whose tokens carry a `grant_type` claim.

**Why:** a client credentials token's `sub` is the client's own
`client_id`, so a resource server couldn't tell it from an end user's
token with the same identifier (RFC 9068 §5). A client registered
automatically through OpenID Federation chooses its own `client_id`, so
it could pick one equal to a privileged user's subject. Client
credentials tokens now carry `grant_type: "client_credentials"`, and
every access token from an authorization code carries `code_grant_id`,
which lets a reused code revoke everything issued from it. The server
sets both claims itself.

**What to change:**

- Where both kinds of token reach a resource server, check
  `AuthorizationContext.SubjectKind` before authorizing by `Subject`:

  ```go
  if authz.SubjectKind != resource.SubjectEndUser {
  	return resource.NewInsufficientScopeError(authz, "this endpoint needs an end user's token")
  }
  ```

  `SubjectClient` means `Subject` is the client's own `client_id`.
- Rename any extension returning `grant_type` or `code_grant_id` in
  token claims: `server.New` now refuses one.
- A token whose `grant_type` claim is anything but `client_credentials`
  is now refused with `invalid_token`. A custom resolver must not pass
  through a `grant_type` claim of its own.

Client credentials tokens issued before the upgrade carry no
`grant_type`, so they read as `SubjectEndUser` until they expire, at
most `Limits.AccessTokenLifetime` after the upgrade.

### `HorizontallyScaled` becomes a required `Deployment` (server, resource, *production only*)

**Affects:** a server or resource server that set
`server.Config.HorizontallyScaled` or `resource.Config.HorizontallyScaled`,
and any configuration under `AssuranceProduction`.

**Why:** a forgotten `HorizontallyScaled: true` on a fleet silently
dropped the requirement that stores, and key custody, be consistent
across instances: the fleet was checked as one instance, and nothing
said so. Production now has to say which it is.

**What to change:**

- Replace the field with `Deployment`: `HorizontallyScaled: true`
  becomes `Deployment: server.DeploymentHorizontallyScaled` (or
  `resource.DeploymentHorizontallyScaled`), and `false`, or leaving it
  out, becomes `DeploymentSingleInstance`.
- *Production only:* `server.New` and `resource.NewVerifier` refuse a
  zero `Deployment` under `AssuranceProduction`, naming both values. Under
  `AssuranceDevelopment` it may stay unset.
- `serverresource.NewVerifier` takes the server's `Deployment`, as it
  took `HorizontallyScaled`.

### Extension definitions declare a `Sensitivity` (extension)

**Affects:** every `extension.Definition[T]` registered with
`extension.NewRegistry`.

**Why:** `Definition.Sensitive` was a bool whose zero value, "may be
logged", was also what forgetting it gave, so a secret parameter whose
definition left it out could reach logs and error messages.

**What to change:** replace `Sensitive: true` with
`Sensitivity: extension.Sensitive`, and set
`Sensitivity: extension.NotSensitive` on every other definition, which
used to leave the field out. `NewRegistry` refuses a definition without
one.

### A stored CIBA session is sealed (client)

**Affects:** a client that stores a `BackchannelAuthenticationSession`
with `MarshalText` and restores it with `UnmarshalText` or
`client.ParseBackchannelAuthenticationSession`.

**Why:** the stored session records whether the request asked for
`openid`, which decides whether an approval without an ID token is
refused, and which of the client's requests to poll. It was stored
without integrity protection, so anyone who could edit it could turn
that check off.

**What to change:** seal the session instead, with 32 random bytes the
application keeps secret, for the owner the request is for (a user,
account or connection ID), as `TokenSetSealer` does:

```go
sealer, err := client.NewBackchannelSessionSealer(c, [][]byte{key})
sealed, err := sealer.Seal(session, userID)          // store this, keyed by session.AuthReqID()
session, reseal, err := sealer.Open(sealed, userID)  // on any instance, for the same owner
```

A sealed session opens only for the owner it was sealed for, so one
leaked from another user's storage doesn't open under this user's.

`MarshalText`, `UnmarshalText` and `ParseBackchannelAuthenticationSession`
are removed. A session stored by v0.51 or earlier doesn't open (the
error wraps `client.ErrUnreadableBackchannelSession`): begin the
backchannel authentication again. Sessions last minutes, so draining
in-flight ones before upgrading avoids that.

### `TokenSet.Issuer` (client)

**Affects:** a client that builds a `TokenSet` by hand (rather than
getting one from the client or `TokenSetSealer.Open`) and refreshes it
with `RefreshTokens`, or seals another issuer's set.

**Why:** a set without an ID token wasn't tied to its issuer, so
refreshing it on another issuer's `Client` sent its refresh token to
that issuer's token endpoint.

**What to change:** every `TokenSet` the client returns now records
`Issuer`, and `TokenSetSealer.Open` restores it. `RefreshTokens` refuses
a set whose `Issuer` isn't this client's, and one recording no issuer
unless its ID token's `iss` is this client's issuer.
`TokenSetSealer.Seal` refuses a set from another issuer. A set you
build by hand sets `Issuer` to the issuer it came from.

### `Config.RedirectURI` is checked at `New` (client)

**Affects:** a client whose `Config.RedirectURI` isn't one a FAPI 2.0
authorization server would accept.

**Why:** an unacceptable redirect URI only failed at the server's
pushed authorization endpoint.

**What to change:** `client.New` now refuses a redirect URI that isn't
https, a loopback http URI or a private-use scheme (RFC 8252 §7.1,
§7.3), or that carries a fragment or credentials. Under
`AssuranceProduction`, a loopback redirect names the IP literal
`127.0.0.1` or `[::1]`, not `localhost` (RFC 8252 §8.3).

### `client.ErrorAuthorizationDenied` is removed (client)

**Affects:** code that compares an error's code with
`client.ErrorAuthorizationDenied`.

**Why:** no function returned it: a denial is a result, not an error.
It was deprecated in v0.50.1.

**What to change:** check the result instead: `CompletionDenied` from
`CompleteAuthorization`, `CallbackDenied` from
`HandleAuthorizationResponse`, or `BackchannelAuthenticationDenied` from
`PollBackchannelAuthentication`, each carrying the server's error `Code`
and `Description`.

### `keys.NewKeyManagerFromSigners` takes one `SignerSpec` per purpose (keys)

**Affects:** every call to `keys.NewKeyManagerFromSigners`.

**Why:** it took three parallel maps — signers, algorithms and kids,
each keyed by purpose — so a purpose present in one map and missing from
another compiled, and a kid map entry for a purpose with no signer was
silently ignored. One value per purpose can't drift that way. The
manager it returns is now a `keys.RotatingKeyManager`, so publishing an
outgoing key through a rotation's overlap window no longer needs a
KeyManager of your own.

**What to change:** pass a `[]keys.SignerSpec`, one per purpose, with
the options as before:

```go
km, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{
	{Purpose: keys.IDTokenSigning, Algorithm: fapi.ES256, Signer: signer, KeyID: "as-key-1"},
	{Purpose: keys.AccessTokenSigning, Algorithm: fapi.ES256, Signer: signer, KeyID: "as-key-1"},
}, keys.DeclareCustody(keys.KeyCustody{Durable: true}))
```

- An empty `KeyID` is no longer published as an empty kid (which
  `/jwks` refused): it's derived from the key's RFC 7638 thumbprint.
  Keep setting `KeyID` if clients or resource servers already pin your
  current kid.
- To rotate, build the manager with the incoming key as `Signer` and
  the outgoing key's public half in `Previous`
  (`[]keys.PublicKeyInfo{{KeyID: "as-key-1", PublicKey: old.Public()}}`);
  both are published until you drop it from `Previous`.
- It refuses what used to fail later: the same purpose twice, a spec
  without a purpose or algorithm, a kid naming two different keys, and
  a previous key that doesn't suit the purpose's algorithm.

### An attester trust-anchor source declares its hardening (server, *production only*)

**Affects:** a server under `AssuranceProduction` with
`Config.AttestationBasedClientAuthentication`, whose
`Dependencies.AttesterTrust` is an `X5CAttesterChain` with a
`TrustAnchors` or `Anchors` source of your own.

**Why:** the anchors an attestation chain must end at decide which
attesters this server trusts. `RegisteredAttesterKeys`' key source
already had to declare `keys.KeySourceAssurance` under production, but
`X5CAttesterChain`'s anchor source didn't, so a trust list fetched
without fapihttp's SSRF and size protections passed unnoticed.

**What to change:**

- `StaticAttesterTrustAnchors` and `StaticAttesterAnchors` declare it
  already: nothing to change.
- A source of your own implements `keys.KeySourceAssurance`, declaring
  `LiveFetchHardened` only when it fetches nothing, or fetches only
  through a `fapihttp` client with no loopback exception:

  ```go
  func (l *TrustList) Capabilities() keys.KeySourceCapabilities {
  	return keys.KeySourceCapabilities{LiveFetchHardened: true}
  }
  ```

  Without it, `New` refuses the configuration, naming
  `attester_trust trust_anchors` or `attester_trust anchors`.

## v0.50.0

### `ResolveViaEndpoint` names the resolver it trusts (federation)

**Affects:** a caller of `federation.Resolver.ResolveViaEndpoint`.

**Why:** OpenID Federation 1.0 lets any Federation Entity run a resolve
endpoint, and leaves choosing a trusted resolver to the caller (§17.2.3).
`ResolveViaEndpoint` trusted a Resolve Response signed by any entity it
could resolve, so any member of the federation, a leaf included, could
sign a response about any subject, with Resolved Metadata of its
choosing (an attacker's `jwks_uri`, say), and it was accepted.

**What to change:** set `ResolveRequest.ExpectedIssuer` to the Entity
Identifier of the resolver you trust, typically the Trust Anchor
(§17.3 recommends the Trust Anchor also serve as the resolver), and point
`Endpoint` at that resolver's `federation_resolve_endpoint`:

```go
claims, err := resolver.ResolveViaEndpoint(ctx, federation.ResolveRequest{
	Endpoint:       "https://ta.example.org/resolve",
	ExpectedIssuer: "https://ta.example.org",
	Subject:        "https://op.example.org",
	TrustAnchor:    "https://ta.example.org",
})
```

A response issued by anyone else is refused, before its issuer is
resolved. An empty or invalid `ExpectedIssuer` is refused at the call.

### Registered attester keys come from their own key source (server, keys)

**Affects:** a server with `Config.AttestationBasedClientAuthentication`
whose `Dependencies.AttesterTrust` is `server.RegisteredAttesterKeys{}`,
and any `keys.ClientKeySource` that answered
`keys.AttestationVerification` requests.

**Why:** `RegisteredAttesterKeys` looked the attester's key up in
`Dependencies.ClientKeys`, by client ID. A key source that answers by
client returns the client's own keys: `keys/ephemeral` returns the
client's registered JWKS whatever the purpose, and federation automatic
registration returns the relying party's own published keys. A client
could then sign its own client attestation with its own key and pass
attestation-based client authentication without any attester vouching
for it. An attester's keys now come from a source keyed by the
attester, which client registrations never feed.

**What to change:**

- Give `RegisteredAttesterKeys` a `Keys` source holding each trusted
  attester's keys, by the issuer clients are registered with
  (`ExpectedAttesterIssuer`):

  ```go
  deps.AttesterTrust = server.RegisteredAttesterKeys{
  	Keys: keys.StaticAttesterKeys{
  		"https://attester.example.com": {
  			{KeyID: "attester-1", Algorithm: fapi.ES256, PublicKey: attesterPublicKey},
  		},
  	},
  }
  ```

  Or implement `keys.AttesterKeySource` yourself. `New` refuses a
  `RegisteredAttesterKeys` without `Keys`.
- *Production only:* the source must implement
  `keys.KeySourceAssurance`, as `ClientKeys` must. `StaticAttesterKeys`
  does.
- `keys.AttestationVerification` is removed. Delete any case for it in
  your `ClientKeySource`, and move the keys it returned into the
  attester key source.

`X5CAttesterChain` is unchanged.

### Loopback http issuers and endpoints are refused in production (client, server, *production only*)

**Affects:** a client under `Config.Assurance = AssuranceProduction`
whose issuer or any endpoint was parsed with `fapi.AllowLoopbackHTTP`
(plain http to 127.0.0.1, [::1] or localhost), or that calls a
protected resource (`ProtectedResource(...).Do`) at a loopback http URL,
and a server under production whose `Config.MTLSEndpoints` has such a
URL.

**Why:** `fapi.AllowLoopbackHTTP` exists for a local development
authorization server. `server.New` already refused it under production
for its issuer and `Config.Endpoints`, but not for the
`mtls_endpoint_aliases` it advertises to mTLS clients, and `client.New`
didn't apply the rule at all, so a production client could talk to its
authorization server over plain http.

**What to change:** use https issuers and endpoints in production, and
keep `fapi.AllowLoopbackHTTP` for development configurations. A native
app's loopback redirect URI (`Config.RedirectURI`, RFC 8252 §7.3) is
unaffected.

The same goes for `fapihttp`'s loopback exceptions (`AllowLoopbackHosts`,
`AllowLoopbackHTTP`, `AllowedLoopbackHosts`, reported by their configs'
`AllowsLoopback`): a `keys.JWKSIssuerKeySource` whose `*fapihttp.Client`
grants one no longer declares `LiveFetchHardened`, a
`backchannelhttp.Notifier` whose `Config.Transport` grants one no longer
declares `OutboundHardened`, and `server.New` refuses a
`Dependencies.FederationHTTP` with one — each under production only.
`AllowedPrivateHosts` is unaffected.

### A CIBA notifier declares how it sends (server, *production only*)

**Affects:** a server under `Config.Assurance = AssuranceProduction`
with CIBA configured (`Endpoints.BackchannelAuthentication` set) whose
`Dependencies.BackchannelNotifier` is its own type, not
`backchannelhttp.Notifier` or `server.NoBackchannelNotifications`.

**Why:** a ping notification goes to the client's registered
`client_notification_endpoint`, which under OpenID Federation automatic
registration is the relying party's own metadata. A notifier sending
through an ordinary HTTP client can be pointed at internal addresses,
follow redirects, or hang. `New` checked every other outbound extension
point under production, but couldn't see how a notifier sends.

**What to change:** use `backchannelhttp.New`, which sends through
`fapihttp`'s guarded client (with no loopback exception in its
`Config.Transport`). Or implement
`server.BackchannelNotifierAssurance` on your notifier and declare
`OutboundHardened`, which promises it sends the same way: a dialer that
refuses non-public addresses, no redirects, https, timeouts and a
bounded response read (`fapihttp.NewClient` builds such a client):

```go
func (n myNotifier) BackchannelNotifierCapabilities() server.BackchannelNotifierCapabilities {
	return server.BackchannelNotifierCapabilities{OutboundHardened: true}
}
```

`NoBackchannelNotifications` needs nothing. Development assurance is
unchanged.

### A resource server declares its assurance level (resource)

**Affects:** every `resource.NewVerifier` call. A verifier built with
`serverresource.NewVerifier` is unaffected: it takes the server's own
`Assurance` and `HorizontallyScaled`.

**Why:** the server and client refuse a production deployment built on
stores and key sources that declare no capabilities, but the resource
server accepted anything. A production resource server could check DPoP
replay against an in-memory store each instance keeps for itself, or
fetch issuer keys through an unhardened source, and nothing said so.

**What to change:**

- Set `resource.Config.Assurance`. `NewVerifier` refuses the zero value:

  ```go
  cfg := resource.Config{
  	Limits:    resource.Limits{MaxDPoPProofAge: time.Minute, MaxClockSkew: 5 * time.Second},
  	Assurance: resource.AssuranceProduction, // or AssuranceDevelopment with memstore and keys/ephemeral
  }
  ```

- *Production only:* `resource.AssuranceProduction` requires:
  - the issuer key source of `resource.JWTAccessTokens` to implement
    `keys.KeySourceAssurance` and declare `LiveFetchHardened`.
    `keys.JWKSIssuerKeySource` (on a `fapihttp` client without a loopback
    exception) and `keys.LocalIssuerKeys` do.
  - the `resource.OpaqueAccessTokens` store and the revocation checker
    to implement `storage.StoreAssurance` and declare `Durable`. Pass
    `resource.NoRevocation{}` to decline revocation explicitly instead.
  - `Replay`, and `Nonces` when set, to declare `Durable` and
    `AtomicConsume`.
  - `Random` to be `crypto/rand.Reader` itself when `Nonces` is set.
  - with `Config.HorizontallyScaled`, every store above to also declare
    `CrossInstanceConsistent`.
- *Production only:* an `AccessTokenResolver` of your own must
  implement `resource.AccessTokenResolverAssurance`, naming the issuer
  key source or store it relies on, as a custom
  `server.AccessTokenIssuer` does.

### `prompt=login` is enforced (server)

**Affects:** a server whose clients send `prompt=login`, and whose
application completes such an authorization with an existing session's
authentication time rather than authenticating the user again.

**Why:** OIDC Core §3.1.2.1 says `prompt=login` asks the authorization
server to "reauthenticate the End-User even if the End-User is already
authenticated", and to return `login_required` if it can't. The server
used to leave this to the application without checking. It now surfaces
the request's prompt as `InteractionRequest.Prompt`, and
`CompleteAuthorization` answers the client with `login_required`, and
no code, when the request carried `prompt=login` and the authentication
time passed to `NewAuthenticationContext` is earlier than when the
request was pushed, allowing `Limits.MaxClockSkew`. A pushed request
combining `prompt=none` with another value is now `invalid_request`.
Requests pushed before upgrading aren't checked.

**What to change:** when `InteractionRequest.Prompt.Has(server.PromptLogin)`,
authenticate the user again before calling `Authorize`, and pass the
time they actually authenticated, never an earlier session's. For
`server.PromptNone`, show nothing: authorize from an existing session
and consent, or complete with the new `server.InteractionNeeded`
result, which answers `login_required`, `consent_required`,
`account_selection_required` or `interaction_required`.

### `TolerateUserInfoSubjectEqualsClientID` is removed (client)

**Affects:** a client that set `client.Config.TolerateUserInfoSubjectEqualsClientID`.

**Why:** it worked around an authorization server defect, a UserInfo
response whose `sub` was the client's own `client_id` instead of the
end-user's subject. Accepting that meant the client could no longer
tell one user's UserInfo claims from another's for that server, the
substitution OIDC Core §5.3.2's exact `sub` match exists to catch. The
server it was added for has been fixed.

**What to change:** remove the field from your `client.Config`.
`FetchUserInfo` now always requires the UserInfo response's `sub` to
exactly match the ID token's `sub`, and refuses anything else with
`invalid_response`. If an authorization server you use still returns
its client's `client_id` as `sub`, that server needs fixing; there is
no client-side workaround.

### Records written before upgrading keep their old limits (server)

**Affects:** a server upgraded with codes, CIBA requests or refresh
tokens still outstanding, or deployed as a rolling update.

**Why:** v0.50.0 records when each code, CIBA decision, refresh token
and pushed request was issued, and checks that time against the current
`Limits` (a shortened lifetime now also shortens what was already
issued), against `prompt=login` and against the CIBA request's own
expiry. Records written before the upgrade, or by an instance still on
v0.49 during a rolling deploy, don't carry those times and are judged
only as before, by the expiry stored with them. Codes and CIBA requests
are short-lived, so this passes within minutes; a refresh token isn't
rotated, so one issued before the upgrade keeps its original lifetime
for as long as it lasts.

**What to change:** nothing, unless you shorten
`Limits.RefreshTokenLifetime` and need it to apply to refresh tokens
issued before the upgrade. Then revoke those grants with
`Server.RevokeGrant` *before* shortening it: a revocation record lasts
as long as the `Limits` in force when it's written allow, so one written
after shortening can lapse while such a token, still judged by its
original expiry, works again. Or wait until refresh tokens issued
before the upgrade have expired. `Server.RevokeToken` also works, given
the token itself.

## v0.49.0

### A custom access token issuer declares what it relies on (server, *production only*)

**Affects:** a server under `Config.Assurance = AssuranceProduction`
whose `Dependencies.AccessTokens` is its own `AccessTokenIssuer`, not
`JWTAccessTokens` or `OpaqueAccessTokens` (or a type embedding
`JWTAccessTokens`).

**Why:** under production assurance, `New` checks the custody of the
keys that sign access tokens and the capabilities of the store that
keeps opaque ones. It could only see into `JWTAccessTokens` and
`OpaqueAccessTokens` values, so a custom issuer, and a pointer
`*OpaqueAccessTokens`, skipped those checks entirely: a production
server could run on ephemeral signing keys or an in-memory token
store without being told. `New` now checks pointers too, and refuses
an issuer it can't see into.

**What to change:** implement `server.AccessTokenIssuerAssurance` on
your issuer, returning an `AccessTokenAssurance` that names what it
relies on: `SigningKeys`, the `keys.KeyManager` that signs the tokens,
and/or `Store`, where it keeps them. Those are then checked as
`JWTAccessTokens`' keys and `OpaqueAccessTokens`' store are:

```go
func (i myIssuer) AccessTokenAssurance() server.AccessTokenAssurance {
	return server.AccessTokenAssurance{SigningKeys: i.keys}
}
```

An issuer that embeds `JWTAccessTokens` needs nothing: its keys are
checked as before. Development assurance is unchanged.

## v0.48.0

### `Server.RevokeToken` returns what it revoked (server)

**Affects:** a server serving the token revocation endpoint added in
v0.47.0 (`Config.Endpoints.Revocation`).

**Why:** an application that keeps data for a grant (keyed by its
`GrantID`) had no way to learn that a client had just ended that grant
through the revocation endpoint, so it couldn't delete the data until
its own deadline. `RevokeToken` now returns a `TokenRevocationResult`:
`Revoked` reports that the call revoked a live refresh token, and
`GrantID` names its grant when it had one.

**What to change:** `RevokeToken` returns `(TokenRevocationResult,
error)` instead of `error`. A handler that doesn't need the result
discards it:

```go
_, err = srv.RevokeToken(r.Context(), req)
```

The endpoint's response is unchanged: write a 200 with an empty body on
a nil error, whatever the result says. The result is for the
application only — never put it in the response — and two concurrent
revocations of one token can both report it, so act on it
idempotently.

## v0.43.0

### Clients list the RAR types they may request (storage, server)

**Affects:** a server using Rich Authorization Requests (`Config.RAR`),
for every client that sends `authorization_details`, including clients
registered automatically through OpenID Federation.

**Why:** RFC 9396 §10 defines `authorization_details_types`, the types a
client may use. The server now enforces it per client, before any
`RARPolicy`: a requested type the client isn't registered for is
`invalid_authorization_details`. The default is the safe one — an empty
list allows no type — so every client that requests RAR must list its
types. Before, any registered type reached the policy, which had to
check the client itself.

**What to change:** set `storage.RegisteredClientConfig.AuthorizationDetailsTypes`
to the types each client may request, and
`server.Config.AutomaticRegistration.AuthorizationDetailsTypes` to the
types every automatically registered client may (`New` refuses one
`Config.RAR` doesn't register). If you build a
`federation.NewAutomaticClientRepository` yourself rather than through
`server.Config`, set `federation.AutomaticRegistrationConfig.AuthorizationDetailsTypes`
there. A `RARPolicy` that only checked
which types a client may use can then become
`server.AllowRequestedAuthorizationDetails{}`; keep your own where it
checks the details themselves. Note one difference from a policy that
dropped disallowed details: the server refuses the whole request.

The types list doesn't replace the policies:
`Dependencies.AuthorizationCodeRARPolicy`, `CIBARARPolicy` and
`ClientCredentialsRARPolicy` are still required for their grants, and a
nil one still refuses every `authorization_details` request on it.

`New` can't catch a client registered without its types: they live in
your `ClientRepository`. A client that's missing them is refused at
runtime, at PAR, CIBA or the token endpoint, with
`invalid_authorization_details`; the error's cause, for your logs, reads
`authorization_details type "…" is not registered for this client`.
`Server.CheckClientRegistration(client)` catches a registration listing a
type `Config.RAR` doesn't register (a typo, usually): call it when you
register a client, or over every client at startup. Grants made before
the upgrade aren't checked again: a refresh keeps the authorization
details the grant already holds.

### Custom `SessionStore`s persist an opaque `Record` (client)

**Affects:** a client whose `Dependencies.Sessions` is your own
`storage.SessionStore`, not `memstore`.

**Why:** the client now checks the ID token's `auth_time` against a
requested `max_age` (OIDC Core §3.1.3.7), which means remembering
`max_age` from `BeginAuthorization` to `ExchangeCode`. Rather than add
another field every store has to learn — and that one which isn't
updated would silently drop, skipping the check — `NewSession` now
carries only `State`, `ExpiresAt` and one opaque, versioned `Record`
the client owns, and `ConsumedSession` only `Record` and `ExpiresAt`,
as the server's grant records do (v0.33.0). The nonce, PKCE verifier, expected issuer, redirect URI and
response mode moved into it. A future client feature changes only the
record.

**What to change:** persist `NewSession.Record` as is and return it as
`ConsumedSession.Record`, in any column type that returns equivalent
JSON; drop the `Nonce`, `PKCEVerifier`, `ExpectedIssuer`,
`ExpectedRedirectURI` and `ExpectedResponseMode` columns.
`storage.TestSessionStoreContract` checks the round trip. A store that
returns no record fails every callback with an internal error naming
`NewSession.Record`, never silently.

An authorization in progress when you deploy — its session written by
the previous version — fails at the callback, and the user starts
again; sessions last `Limits.SessionLifetime`.

For a rolling deploy, where old and new instances share the store for a
while: add the `Record` column first, keeping the old ones, and deploy.
A callback that reaches the other version fails as above until every
instance is new. Drop the old columns once `Limits.SessionLifetime` has
passed since the last old instance stopped. Use a column type without a
small length limit (text or JSON): the record holds the nonce, PKCE
verifier, issuer and redirect URI.

### `ExchangeCode` checks `auth_time` against `max_age` (client)

**Affects:** a client that sets `BeginAuthorizationRequest.HasMaxAge`.

**Why:** OIDC Core §2 makes `auth_time` REQUIRED in the ID token when
the request carried `max_age`, and §3.1.3.7 has the client check it.
This package used to leave that to the caller.

**What to change:** nothing, unless you were relying on an
authorization server that ignores `max_age`: `ExchangeCode` (and
`CompleteAuthorization`) now fail with `invalid_response` when the ID
token has no `auth_time`, or when it's older than `MaxAge` plus
`Limits.MaxClockSkew`. Remove any check of your own, or keep it as a
stricter policy.

## v0.42.0

### `TrustedClientCAs` needs `Revocation` (server)

**Affects:** a server whose `Dependencies.ClientCertificateTrust` is
`server.TrustedClientCAs`. `NoClientCertificateChainTrust{}` is
unaffected.

**Why:** a client certificate's validity period alone can't stop a
compromised key before it expires; revocation can, and many mTLS
ecosystems require it. `TrustedClientCAs` had no way to check it, so a
revoked certificate was accepted until it expired. Its new
`Revocation` field is required, so a server built without a revocation
check says so in its own code.

`New` now also rejects a `TrustedClientCAs` with nil `Roots`: crypto/x509
falls back to the system roots for a nil pool, which trusted every
public CA to issue client certificates.

**What to change:** set `Revocation` to one of:

- `server.ClientCertificateCRLs{Lists: ...}`, which checks Certificate
  Revocation Lists your `Lists` function returns. Keep them in memory
  and refresh them before their nextUpdate; a missing or stale list
  rejects the certificate.
- your own `server.ClientCertificateRevocation`, for OCSP or another
  revocation source.
- `server.NoClientCertificateRevocationCheck{}` to keep the old
  behaviour.

If your client certificates are issued by an intermediate CA that you
put in `Roots`, move it to the new `Intermediates` pool and put its root
in `Roots` instead. A CA in `Roots` is a trust anchor, so its own
revocation is never checked. In `Intermediates`, it's part of the
verified chain and is checked against its root's CRL like the leaf.

```go
// Before
ClientCertificateTrust: server.TrustedClientCAs{Roots: pool},

// After
ClientCertificateTrust: server.TrustedClientCAs{
	Roots:      pool,
	Revocation: server.ClientCertificateCRLs{Lists: crlCache.Current},
},
```

### Client certificates are checked at `Dependencies.Clock`'s time (server)

**Affects:** a server using `server.TrustedClientCAs` with a
`Dependencies.Clock` that isn't the wall clock, such as a fixed clock
in tests.

**Why:** a client certificate's validity period was checked against
the wall clock, while everything else (tokens, assertions, attester
certificates) uses `Dependencies.Clock`. A test with a fixed clock now
needs client certificates valid at that clock's time.

### An mTLS-bound token without a certificate is invalid_token (resource)

**Affects:** anything that checks the status or error code
`resource.Verifier` returns for a `Bearer` request arriving without a TLS
client certificate.

**Why:** RFC 8705 §3 has a protected resource reject an access token
whose certificate doesn't match the one presented "using an HTTP 401
status code and the "invalid_token" error code", and no certificate
matches none. Such a request was answered 400 `invalid_request`, before
the token was even looked at. Nothing is missing from the HTTP request
itself: the certificate belongs to the connection. The usual cause is a
client calling the resource's plain host rather than its mTLS host, or
a TLS stack that didn't send its certificate.

**What to change:** expect 401 with `WWW-Authenticate: Bearer
error="invalid_token"` instead. The token is now resolved first, so an
invalid or expired token without a certificate gets the same answer. A
`DPoP` request without a `DPoP` header is unchanged: still 400
`invalid_request`.

### `max_age` is enforced (server)

**Affects:** a server whose clients send `max_age`, and whose
application completes an authorization with an earlier authentication,
from a single sign-on session for example, rather than authenticating
the user again.

**Why:** OIDC Core §3.1.2.1 says that when more than `max_age` seconds
have passed since the user last actively authenticated, "the OP MUST
attempt to actively re-authenticate the End-User". The server used to
ignore `max_age`. It now validates it at the pushed authorization
request (a value that isn't a whole number of seconds from 0 to 100
years is `invalid_request`), surfaces it as
`InteractionRequest.MaxAge`/`HasMaxAge`, and has `CompleteAuthorization`
answer the client with `login_required` when the authentication time
passed to `NewAuthenticationContext` is older than that, allowing
`Limits.MaxClockSkew`.

**What to change:** when `InteractionRequest.HasMaxAge` is set and your
user's last authentication is older than `MaxAge`, authenticate them
again before calling `Authorize`, and pass the time they actually
authenticated, never `time.Now()` for an existing session. A `max_age`
of 0 asks for a fresh authentication every time. `InteractionRequest.ACRValues` now carries
the client's `acr_values` too, for deciding how strongly to
authenticate. It's a request, not a requirement.

## v0.41.0

### An invalid DPoP proof is invalid_dpop_proof

**Affects:** anything that checks the error codes of `server` (the PAR,
token and backchannel authentication endpoints) or `resource.Verifier`.

**Why:** RFC 9449 gives an invalid DPoP proof its own error code,
`invalid_dpop_proof`: at the authorization server "If the DPoP proof is
invalid, the authorization server issues an error response ... with
invalid_dpop_proof" (§5), and at a protected resource for a proof
"deemed invalid based on the criteria of Section 4.3" (§7.1). A proof
that fails verification, is replayed, or isn't the only DPoP header was
reported as `invalid_request` by `server` and `invalid_token` (or, for
more than one DPoP header, 400 `invalid_request`) by `resource`. They're
now `server.ErrorInvalidDPoPProof` (HTTP 400) and
`resource.ErrorInvalidDPoPProof` (HTTP 401, in a `DPoP` challenge). A
request with no proof at all is still `invalid_request`.

### A resource request without credentials gets 401, not 400

**Affects:** anyone using `resource.Verifier`, and anything that checks
its errors' status codes or error codes.

**Why:** RFC 6750 §3.1 answers a request that "lacks any authentication
information (e.g., the client was unaware that authentication is
necessary or attempted using an unsupported authentication method)"
with 401 and a challenge carrying no error code; RFC 9449 §7.2 says the
same for a resource server accepting both DPoP and Bearer. `Verify`
answered it with 400 `invalid_request`. It now returns a
`*resource.Error` with an empty `Code()` and status 401, for a missing
Authorization header and for a scheme other than DPoP or Bearer.
`WriteJSON`/`WriteError` send it as `WWW-Authenticate: Bearer, DPoP
algs="ES256 PS256 EdDSA"` with no body. A header with a supported
scheme but no token is still 400 `invalid_request`.

Errors for a request that used the DPoP scheme are now sent in a `DPoP`
challenge, with `algs`, rather than a `Bearer` one (RFC 9449 §7.2).

If you pass `Verify`'s errors to `WriteJSON` or `WriteError`, there's
nothing to change. If you build the response yourself, send no error
code when `Code()` is empty, and use the challenge `WriteJSON` would.

### Entity Identifiers with a query or userinfo are rejected

**Affects:** anyone resolving Trust Chains, registering federation
clients automatically, or passing an Entity Identifier to
`federation.ValidEntityID` or `NewSelfIssuer`.

**Why:** OpenID Federation 1.0 §1.2 defines an Entity Identifier as an
https URL with a host and optionally a port and path, which "MUST NOT
contain query parameter or fragment components". Only a non-empty
fragment was rejected: a query, an empty `?` or `#`, and userinfo
(`https://user@host`) were accepted, and the query and userinfo were
carried into the Entity Configuration fetch. All are now rejected.

Entity Identifiers of the form the specification allows are
unaffected.

### Federation metadata member names are case-sensitive

**Affects:** anyone using `federation.AutomaticClientRepository`,
resolving Trust Chains, or calling `client.DiscoverViaFederation`.

**Why:** OpenID Federation metadata policy applies to parameters by
their exact names, but relying-party and `federation_entity` metadata
were decoded with Go's case-insensitive field matching. An RP could
publish `Token_Endpoint_Auth_Method` instead of
`token_endpoint_auth_method`, escape a superior's policy on that
parameter, and still have its value registered. Metadata with a member
name matching a known parameter only in a different case is now
rejected, as are Entity Statement `jwks` keys whose `kid` is spelled
that way.

Metadata using the specifications' exact parameter names is unaffected.
A federation member publishing case-variant names no longer registers
or resolves; it must correct its metadata.

### Entity Statements need a `kid`, unique key IDs, and no `crit`

**Affects:** anyone resolving Trust Chains, and anyone signing Entity
Statements with `internal/federation`-backed issuers (`SelfIssuer`,
`SubordinateIssuer`, `server.Server.EntityConfiguration`).

**Why:** OpenID Federation 1.0 §3.2 requires an Entity Statement's
header `kid` to be a non-empty string naming a key of its issuer, and
§3.1.1 requires every key in its `jwks` to have a unique `kid`. A
statement without a `kid` was verified against every key of the right
algorithm instead. And a statement whose `crit` claim marked an
extension claim critical was accepted, although §3.2 requires rejecting
one the implementation doesn't understand. All three are now rejected.

Issuers already set `kid` from their `KeyID`; `jwks` passed to them must
give every key a unique `kid` (`keys.PublicJWKS` does). A federation
member publishing statements without `kid`, with duplicate or missing
key IDs, or with `crit`, no longer resolves.

### Trust Chain resolution tries every authority hint

**Affects:** anyone resolving Trust Chains for entities that list more
than one authority hint.

**Why:** `Resolver` followed only the first authority hint whose Entity
Configuration verified, so an entity whose first superior led nowhere
trusted failed to resolve even when another hint reached a configured
Trust Anchor (OpenID Federation 1.0 §10.1 builds chains through every
hint). It now tries each hint, backtracking from dead ends, with a
configured Trust Anchor tried first — which also means an entity listing
both an Intermediate and a configured Trust Anchor now resolves through
the Trust Anchor directly (§10.3's shorter chain), so the Intermediate's
metadata policy no longer applies to it. The search is bounded by
`MaxPathLength × MaxAuthorityHints` superiors in total, and each Entity
Statement is fetched at most once per resolution.

Nothing changes for an entity with one authority hint per level.

### A superior's `metadata` for its subordinate now applies

**Affects:** anyone resolving Trust Chains in a federation where an
Intermediate or Trust Anchor puts a `metadata` claim in a Subordinate
Statement.

**Why:** OpenID Federation 1.0 §3.1.1 lets an Immediate Superior set
metadata values for its subordinate, overriding the subordinate's own,
and §6.1.4.2 applies them before any metadata policy. `Resolver`
ignored them, so `ResolvedEntity.Metadata` carried the subordinate's
self-declared values instead of its superior's. Resolved metadata now
reflects them — only for Entity Types the subordinate itself declares,
and only for the statement's own subject. `SubordinateStatementParams`
gains `Metadata`, so a FAPIgo Intermediate or Trust Anchor can set them.

Nothing changes where no superior uses the claim.

### Metadata policies that combine operators the spec disallows now fail

**Affects:** relying parties and OPs resolving Trust Chains
(`federation.Resolver`, automatic registration), when some statement in
the chain uses a metadata policy with a disallowed operator combination.

**Why:** OpenID Federation 1.0 §6.1.3 fixes which policy operators may
appear together for one metadata parameter, and how their values must
relate (e.g. `add`'s values must be among `value`'s). Only one rule was
enforced, so a statement lower in a chain could loosen what a superior
fixed: an Intermediate's `add` extended a Trust Anchor's `value`, and its
`default` restored a parameter the Trust Anchor had removed with
`value: null`. Every rule is now enforced, for each statement's own
policy and for every merge, and a violation is a policy error that fails
the resolution, as §6.1.4 requires.

Nothing changes for a federation whose policies are valid. If a Trust
Chain that used to resolve now fails with a `policy error`, the error
names the entity type, parameter and rule; the federation's policy needs
correcting — don't work around it.


## v0.40.0

### `fapihttp`'s loopback settings: literal hosts only, split from http

**Affects:** `fapihttp.Config` and `fapihttp.TransportConfig` users that
set `AllowLoopbackHTTP` (development setups fetching from a local
issuer, wallet or test suite).

**Why:** `AllowLoopbackHTTP` lifted the loopback SSRF block for https
as well as http, and for any hostname that *resolved* to a loopback
address, not just literal loopback hosts. A development server with it
set could be made to fetch this machine's own services through any DNS
name an attacker points at 127.0.0.1. And a setup that only needed https
to a local server had to enable a flag named for plain http.

Loopback is now reachable only from:

- **`AllowLoopbackHosts`** (new): https to literal loopback hosts —
  `localhost`, names under `.localhost` (RFC 6761), 127.0.0.0/8 and
  `::1`.
- **`AllowLoopbackHTTP`**: the same hosts, plus plain http.
- **`AllowedLoopbackHosts`** (new): exact hostnames allowed to resolve to
  loopback, e.g. a local test suite with public DNS pointing at
  127.0.0.1.

```go
fapihttp.Config{
	// ...
	AllowLoopbackHosts: true, // https://localhost, https://*.localhost, https://127.0.0.1
	// AllowLoopbackHTTP: true, // only if something is served over plain http
	AllowedLoopbackHosts: []string{"suite.example.test"}, // a name that resolves to 127.0.0.1
}
```

If you only fetch from `localhost`, `*.localhost` or a loopback IP over
https, switch `AllowLoopbackHTTP` to `AllowLoopbackHosts`. If you fetch
from a *name* that resolves to loopback (it now fails with
`ErrSSRFBlocked`), list it in `AllowedLoopbackHosts`. Set the same
fields on `TransportConfig` if you use `NewClient`.

### Custom `SessionStore`s must return `ExpectedIssuer`

**Affects:** relying parties using `client` with their own
`storage.SessionStore` (not `memstore`).

**Why:** completing a callback now checks the consumed session's
`ExpectedIssuer` against the completing client's issuer, so a callback
routed to the wrong client (one client per issuer over a shared store)
can't finish another issuer's flow. Nothing read that field before, so
a store that never persisted it now fails every sign-in with "session
was begun by a client for a different issuer".

Stores that pass `storage.TestSessionStoreContract` already round-trip it.
Otherwise, persist `NewSession.ExpectedIssuer` and return it as
`ConsumedSession.ExpectedIssuer`.

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

### Extensions can't return values under standard claim names (server)

**Affects:** servers whose `Config.Extensions` registers a definition
with `ReturnInTokenClaims` under a name the server or the resource owner
supplies: a claim the server sets itself (`sub`, `acr`, `cnf`,
`authorization_details`, ...) or an OIDC Core §5.1 identity claim
(`email`, `name`, `phone_number`, ...). `server.New` now rejects it.

**Why:** the value is the client's own, copied into the token. Under a
name like `email`, a relying party would read a client-supplied value
as the user's identity claim — for example when the user didn't approve
releasing their real email.

Rename the extension, or drop `ReturnInTokenClaims` if the value only
needs to reach the interaction step (`InteractionRequest.Extensions`).

### `Resolver.VerifyTrustMark` takes an accreditation policy (federation)

**Affects:** callers of `federation.Resolver.VerifyTrustMark`.

**Why:** a verified Trust Mark only proved its issuer was some member of
the federation. Any member, including the entity the mark is about,
could issue itself a mark of any type and have it verify.

```go
claims, err := resolver.VerifyTrustMark(ctx, subjectID, mark,
	federation.RequireFederationAccreditation) // or AcceptAnyFederationIssuer
```

`RequireFederationAccreditation` accepts a mark only when the Trust
Anchor's `trust_mark_issuers` lists its type and names its issuer (or
leaves that type's list empty, meaning anyone may issue it).
`AcceptAnyFederationIssuer` keeps the previous behaviour for marks
accredited out of band; check `claims.Issuer` yourself then. A Trust
Anchor built with `SelfIssuer` publishes the claim through
`SelfIssueConfig.TrustMarkIssuers`. Trust Marks without a `kid` header
are now rejected.

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
