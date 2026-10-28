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
  (For client keys you can skip it: `keys.StaticClientKeys` and
  `keys.NewClientJWKSSource`, shown in step 4, are production-ready.)

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

For `keys.ClientKeySource` you shouldn't need to implement anything
either, and should think twice before you do: it decides whose key
verifies a client assertion or signed request, and the server accepts
whatever key it returns for the client the token names. A source that
looks a `kid` up across every client's keys — a natural JWKS-cache
design — lets any registered client authenticate as any other.
`keys.NewStaticClientKeys` serves keys you register per client up front
(their `jwks`, or `crypto.PublicKey`s, validated once at
construction); `keys.NewClientJWKSSource` resolves each client's
registered `jwks_uri` (or inline `jwks`) through your client registry
and a hardened `fapihttp.Client`, caching per client. Both only ever
look a `kid` up within the requesting client's own keys, refuse an
unknown client, and also serve clients' encryption keys
(`keys.ClientEncryptionKeySource`). If you do write your own, run
`keys.TestClientKeySourceContract` against it in your tests.

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
	Subjects:   server.PublicSubjects(),     // every client sees the same sub for a user
	// Deployment: server.DeploymentSingleInstance, // required under AssuranceProduction: or DeploymentHorizontallyScaled for a fleet
}
```

`AssuranceProduction` holds the limits FAPI 2.0 fixes (authorization
code and pushed request lifetimes, clock skew, request object and CIBA
request lifetimes) to the profile's numbers, and bounds a few it leaves
open (`MaxDPoPProofAge` at most 5 minutes, `DPoPNonceLifetime` 15,
`JARMResponseLifetime` 10, `InteractionLifetime` an hour), but not the
ones it leaves to you: `AccessTokenLifetime`, `RefreshTokenLifetime`,
and how long a client assertion or attestation may live. It also
requires `Dependencies.Clock` to be `server.SystemClock{}` (or a clock
declaring `server.ClockAssurance`) reading the real time. Those are what bound a leaked
token when nothing else does, so keep them short, and shorter still with
`Dependencies.Revocation: server.NoRevocation{}`: then a reused
authorization code no longer revokes what it issued, `RevokeGrant`
refuses, `RevokeToken` removes a refresh token but not the access tokens
issued from it, and a stolen access token works until it expires.

`Subjects` is required: it states what kind of `sub` (OpenID Connect
Core §8) a user gets at each client. `server.PublicSubjects()` gives
every client the same `sub`. A pure OAuth server (`OAuthOnly`) may
leave `Subjects` zero, which means public.

### Pairwise subjects

A pairwise `sub` differs per sector of clients (the host of a client's
redirect URIs, or its registered `Sector`), so clients in different
sectors can't correlate a user by it. A client permitted CIBA, one that
may authenticate by attestation, a native client, and one whose
redirect URIs span several hosts need an explicit `Sector`, a host name
you set at registration (never one the client supplies); an OpenID
Federation Relying Party's is its Entity Identifier's host. A pairwise
client without one is refused at its pushed authorization or
backchannel authentication request, before its user signs in. Every token and response a
pairwise client gets carries it: ID tokens, access tokens and UserInfo.
The server's own records, audit events and your login page keep the
user's internal subject.

The recommended deriver is `pairwise.NewReversible`, over two
independent 32-byte keys from your secret store. Generate each with
`crypto/rand` (`openssl rand 32` will do), and decode a hex or base64
copy back to its 32 bytes before passing it in: a key that is all
printable text, a passphrase or a still-encoded key, is refused.

```go
pairwiseSubjects, err := pairwise.NewReversible(macKey, encKey,
	keys.DeclareCustody(keys.KeyCustody{Durable: true, CrossInstanceConsistent: true}))
if err != nil {
	log.Fatal(err)
}
prefix, err := pairwise.NewPrefix("ppid:") // must be set; "" only with a reversible deriver or a declared resolver
if err != nil {
	log.Fatal(err)
}
cfg.Subjects = server.SubjectConfig{
	Default:     fapi.SubjectTypePairwise,
	Enforcement: server.SubjectTypesPairwiseOnly, // every client, whatever it registered
	Prefix:      prefix,
}
deps.PairwiseSubjects = pairwiseSubjects
```

Choose how a `sub` is derived before the first pairwise client goes
live: changing the deriver, its key or store, the prefix, or a client's
sector gives users new `sub`s at those clients, which relying parties
see as new accounts. Existing grants keep the `sub` they were issued
with, except that changing the prefix ends every pairwise grant at its
next use (`invalid_grant`), since resource servers resolve `sub`s under
the current prefix. One more case fails closed: with an empty prefix,
`Server.SignUserInfoResponse` can only tell a pairwise `sub` from an
internal subject by mapping it back under the client's current sector,
so after a client's sector changes, signed UserInfo for its existing
grants fails with `server_error` until they're reauthorized. A
non-empty prefix avoids this.

To keep public `sub`s for relying parties already integrated while
giving every new one pairwise `sub`s, use a pairwise `Default` with
`SubjectTypesPerClient` instead, and register each legacy client
with `SubjectType: fapi.SubjectTypePublic`; a client registered without
a `SubjectType` gets the pairwise default. Relying parties registering
automatically through OpenID Federation are offered pairwise alone
under a pairwise default, so one can't opt out by asking for `public`
in its metadata: it is refused registration, and one naming no
`subject_type` gets pairwise. To let them choose public too, say so:

```go
cfg.AutomaticRegistration.SubjectTypes = []fapi.SubjectType{fapi.SubjectTypePublic, fapi.SubjectTypePairwise}
```

Discovery still advertises both types, since your legacy clients get
public `sub`s; `Server.EntityConfiguration` sets the `openid_provider`
metadata's `subject_types_supported`, which is what federation relying
parties read, to what they're offered
(`Server.AutomaticRegistrationSubjectTypes()`).

Whether your pairwise `sub`s can be mapped back to their users isn't a
setting: it's whichever deriver you choose, so the configuration can
never promise more unlinkability than the deriver gives.

- **Reversible derivers** (they implement `pairwise.Lookup`): the
  server and its resource servers can map a `sub` back to the user, so
  self-contained JWT access tokens work, and a client's
  `id_token_hint`, `login_hint` or `claims` `sub` value resolves to the
  user. Two derivers do this:
  - **`pairwise.NewReversible`** (recommended) encrypts the internal
    subject into the `sub`, so it needs no storage. Anyone holding both
    keys can map every pairwise `sub` ever issued back to its user, and
    so can every resource server you give them to: guard and back them
    up like signing keys. Internal subjects are limited to 151 bytes
    (`pairwise.MaxReversibleSubjectLength`); `server.NewSubjectID`
    accepts up to 255, so a longer subject fails with `server_error`
    when its user signs in to a pairwise client.

    `NewReversible` uses the keys in process memory, so keep them
    wrapped by your KMS or HSM (envelope encryption): store only their
    ciphertext, and have the KMS decrypt them once at startup, on the
    server and on every resource server that resolves `sub`s. To keep
    them inside an HSM or KMS instead, use
    `pairwise.NewReversibleWith`, which needs a key service offering
    both of the construction's operations: see [Keeping the
    reversible keys in an HSM or KMS](#keeping-the-reversible-keys-in-an-hsm-or-kms).
  - **`pairwise.NewMapping`** keeps a random `sub` per user and sector
    in a `storage.PairwiseSubjectStore`, so there's no key whose leak
    reverses them all, at the cost of a durable, shared store.
- **A one-way deriver** (`pairwise.NewHMAC` over a 32-byte secret key):
  nothing in FAPIgo can map a `sub` back, which is the strongest
  unlinkability. The internal subject then has to stay server-side, so
  `New` requires `server.OpaqueAccessTokens`; and a pairwise hint can
  only be checked against a known user (`Server.ClientSubject`), never
  resolved. If you keep your own record of the `sub`s you issue, give
  it as a `pairwise.SubjectResolver` in
  `Dependencies.PairwiseSubjectResolver`, and the same resolver to every
  one of your own resource servers
  (`resource.Dependencies.PairwiseSubjectResolver`): `New` then accepts
  JWT access tokens too.

**Choosing a deriver.** Each deriver trades privacy against
operational convenience and cost:

| | `NewReversible` (recommended) | `NewMapping` | `NewHMAC` (one-way) |
|---|---|---|---|
| Can the OP map a `sub` back to its user? | Yes, with the keys | Yes, through the store | No |
| If its secret leaks | **Every pairwise `sub` ever issued is de-anonymised at once**, by anyone holding both keys | No key reverses them: an attacker needs the store itself | An attacker can test guesses of internal subjects (cheap if they're predictable, such as account numbers), but can't reverse a `sub` directly |
| Who must hold the secret | The server and every resource server that resolves `sub`s | Every instance and resource server needs the shared store | The server only |
| Storage | None | A durable, shared `storage.PairwiseSubjectStore`, one row per user and sector, kept forever | None |
| Per-request cost at a resource server (JWT access tokens) | Local decryption, or two HSM/KMS calls with `NewReversibleWith` | A store lookup | n/a: opaque access tokens, a token-store lookup |
| Losing the secret | Every user gets new `sub`s at every pairwise client; back the keys up like signing keys | Losing the store does the same; back it up | Losing the key does the same; back it up |
| Rotation | Not possible without changing every `sub` | Not needed (no key) | Not possible without changing every `sub` |

Whichever you choose, it's for good: changing deriver later changes
every pairwise `sub`.

What a one-way deriver gives up is the ability to map a `sub` back to
its user, which several features rely on:

| Needs a `sub` mapped back to its user | `NewReversible`, `NewMapping` | `NewHMAC` (one-way) |
|---|---|---|
| Self-contained (JWT) access tokens, verified by any resource server | Yes | Only with your own `SubjectResolver`; otherwise opaque access tokens, so every resource server reads your token store |
| `id_token_hint` or a `claims` `sub` value at the authorization endpoint | Enforced; `InteractionRequest.RequiredSubject` is the internal subject, so your login page can check who signs in (never render or prefill it: the client chose it) | Enforced, but `RequiredSubject` is only the `sub`: check a candidate user with `Server.ClientSubject` |
| CIBA `id_token_hint` | Yes | Refused, unless you declare a `SubjectResolver` (`login_hint` still works) |
| A `login_hint` carrying a pairwise `sub` | `Server.ResolveClientSubject` | Your own mapping |
| RP-initiated logout with no session to match (`Server.ResolveIDTokenHint`) | Yes | Fails with `server.ErrNoPairwiseSubjectLookup` |
| A relying party naming *another* user by their `sub` in your APIs (account linking, consent dashboards) | `Server.ResolveClientSubject` | Your own mapping; a resource server only knows the `sub` of the token's own user |
| Support, incident and data-subject requests that arrive with a relying party's `sub` | Map it back | Search your own records |

So one-way derivation suits a single authorization server whose own
resource servers can use opaque access tokens, where pairwise `sub`s
only ever come back through a live sign-in, and where even the OP
shouldn't be able to reverse a `sub` offline. Otherwise prefer
`NewReversible` (no storage, but its keys reverse every `sub`) or
`NewMapping` (no such key, but a durable shared store).

Under `AssuranceProduction` the deriver must declare durable custody
(`keys.DeclareCustody` for `NewReversible`, `NewReversibleWith`,
`NewHMAC` and `NewHMACWith`; a `storage.StoreAssurance` store for `NewMapping`), since
every restart and every instance must give a user the same `sub`.

#### Keeping the reversible keys in an HSM or KMS

`pairwise.NewReversibleWith(ops)` is the reversible deriver over a
`pairwise.ReversibleOps` you implement against your key service, so
neither key is ever in your process. For the same two keys it derives
exactly the `sub`s `NewReversible` does. The service has to perform
both of the construction's operations with keys it never releases:

- **MAC:** HMAC-SHA-256, returning the full 32-byte output.
- **Encryption:** raw AES-256-CTR with a caller-supplied 16-byte IV
  used as the whole initial counter block, incremented as one 128-bit
  big-endian integer. A service that generates its own IV, or uses an
  authenticated mode with its own envelope (AES-GCM), can't produce
  these `sub`s.

| Key service | Both keys non-extractable? | MAC | AES-256-CTR | Caveats |
|---|---|---|---|---|
| **PKCS#11 HSMs** (Thales Luna, Entrust nShield, YubiHSM 2 and others) | Yes, if your HSM supports both mechanisms | `CKM_SHA256_HMAC` | `CKM_AES_CTR`, with `CK_AES_CTR_PARAMS.ulCounterBits = 128` | Check that your HSM and firmware support both mechanisms and a 128-bit counter. PKCS#11 lets `ulCounterBits` be smaller, which increments only the low bits and gives different output once they carry: run `NewReversibleWith` against the published test vectors, including the one whose IV ends in `0xfffffffd`. |
| **AWS CloudHSM** (PKCS#11) | Yes | `CKM_SHA256_HMAC` | `CKM_AES_CTR` | Both mechanisms are listed in its PKCS#11 library; set `ulCounterBits` to 128 and check against the test vectors, as above. |
| **Google Cloud KMS** | Yes | A `MAC` key with algorithm `HMAC_SHA256` (`MacSign`) | A `RAW_ENCRYPT_DECRYPT` key with algorithm `AES_256_CTR` (`RawEncrypt` with `initialization_vector`) | AES-CTR keys need the `roles/cloudkms.expertRawAesCtr` role. Google doesn't document the counter width: check against the test vectors, including the `0xfffffffd` one. |
| **AWS KMS** | No | HMAC keys: `GenerateMac` with `HMAC_SHA_256` | Not offered: symmetric keys are AES-256-GCM with a KMS-chosen IV and KMS's own ciphertext format | Use envelope-wrapped keys with `NewReversible` (KMS decrypts them at startup), or AWS CloudHSM. |
| **Azure Key Vault Managed HSM** | No | `HS256` | Not offered: AES keys support only AES-KW, AES-GCM and AES-CBC | Use envelope-wrapped keys with `NewReversible`. |
| **Azure Cloud HSM** | Possibly | HMAC-SHA2-256 is listed | AES-CTR is listed | Not verified here which interface exposes AES-CTR with a caller IV and a 128-bit counter: check, then test against the vectors. |
| **HashiCorp Vault Transit** | No | `hmac` endpoint (output is `vault:v1:`-prefixed base64, which your `ReversibleOps` would decode) | Not offered: AES-GCM, ChaCha20-Poly1305 and (Enterprise) AES-CBC only | Use envelope-wrapped keys with `NewReversible`. |

**Choosing between them.** Both produce identical `sub`s from the same
keys, so a deployment can move between envelope-wrapped keys
(`NewReversible`) and HSM- or KMS-resident ones (`NewReversibleWith`)
without changing any user's `sub`.

- **Envelope-wrapped keys** cost one KMS call per process start, and
  derivation and lookup run in memory. The keys are in the memory of
  the server and of every resource server that resolves `sub`s.
- **HSM- or KMS-resident keys** never leave the key service, but every
  derivation and every lookup is two calls to it. Derivation happens
  once per grant; with self-contained (JWT) access tokens, though, a
  resource server looks the `sub` up on every request it verifies, so
  every API call costs two key operations, in latency and, on a cloud
  KMS, in price. Opaque access tokens avoid the lookup (their record
  holds the internal subject), or put a bounded cache in front of your
  `ReversibleOps`. Every resource server that resolves `sub`s needs
  access to the same two keys.

Sources: [PKCS#11 v2.40 mechanisms (`CK_AES_CTR_PARAMS`)](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html),
[AWS CloudHSM PKCS#11 mechanisms](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html),
[Cloud KMS algorithms](https://docs.cloud.google.com/kms/docs/algorithms),
[Cloud KMS raw encryption](https://docs.cloud.google.com/kms/docs/raw-encryption) and
[`RawEncryptRequest`](https://github.com/googleapis/googleapis/blob/master/google/cloud/kms/v1/service.proto),
[AWS KMS `GenerateMac`](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html) and
[key specs](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html),
[Managed HSM key types and algorithms](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/about-keys-details),
[Azure Cloud HSM algorithms](https://learn.microsoft.com/en-us/azure/cloud-hsm/supported-algorithms),
[Vault Transit API](https://developer.hashicorp.com/vault/api-docs/secret/transit).
Vendors change what they offer: check your service's current
documentation.

#### Keeping the one-way key in an HSM or KMS

`pairwise.NewHMACWith(ops)` is the one-way deriver over a
`pairwise.HMACOps` you implement against your key service: one
operation, HMAC-SHA-256 under a key the service never releases,
returning the full 32-byte output. For the same key it derives exactly
the `sub`s `NewHMAC` does. Unlike the reversible construction it needs
no raw AES, so more services can hold its key:

| Key service | Key non-extractable? | MAC | Caveats |
|---|---|---|---|
| **PKCS#11 HSMs** (including AWS CloudHSM) | Yes | `CKM_SHA256_HMAC` | Check that your HSM supports the mechanism with a 32-byte generic secret key. |
| **AWS KMS** | Yes | An `HMAC_256` key with `GenerateMac`, algorithm `HMAC_SHA_256` | |
| **Google Cloud KMS** | Yes | A `MAC` key with algorithm `HMAC_SHA256` (`MacSign`) | |
| **Azure Key Vault Managed HSM** | Yes | An `oct-HSM` key, `HS256` | |
| **HashiCorp Vault Transit** | Yes | The `hmac` endpoint with `sha2-256` | Its output is `vault:v1:`-prefixed base64: your `HMACOps` decodes it to the 32 bytes. The key is Vault's own, so moving to or from `NewHMAC` changes every `sub`. |

Each derivation is one call, once per grant. A one-way deriver is never
asked to look a `sub` up, so resource servers never call the key
service: they read opaque access tokens' records (or your own
`SubjectResolver`, if you declared one). Check an implementation
against `pairwise/testdata/hmac_vectors.json` (generated independently
by `hmac_vectors.py` beside it). Sources: as above.

Under `ProfileFAPISecurityWithMessageSigning`, `Algorithms.JARM` is
required too.

Most `Limits` fields are lifetimes and clock tolerances. Two are sizes:
`Limits.MaxIDTokenClaimsBytes` (4096 in `RecommendedLimits()`) caps the
total size of the non-standard claims in an ID token, so the server
never issues one larger than relying parties accept — this module's own
client rejects a compact token over 16 KiB by default. See [Adding
claims to tokens](#adding-claims-to-tokens) for what counts against it,
and raise it only alongside your relying parties' own limits.
`Limits.MaxAccessTokenClaimsBytes` (6144) does the same for an access
token's non-standard claims, such as `authorization_details`, against the
16 KiB `resource.JWTAccessTokens` accepts by default; raise it only
alongside your resource servers' `MaxTokenBytes`
(`serverresource.NewVerifier` follows it on its own).

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

// Each client's own public keys: a kid is only ever looked up within
// the requesting client's keys. Also usable as ClientEncryptionKeys.
clientKeys, err := keys.NewStaticClientKeys(map[fapi.ClientID]keys.ClientKeyMaterial{
	"demo-client": {JWKS: theClientsJWKSDocument},
})
// Or, to follow each client's registered jwks_uri (or jwks) live,
// cached per client:
//
//	clientKeys, err := keys.NewClientJWKSSource(fetcher,
//		func(ctx context.Context, id fapi.ClientID) (fapi.URL, []byte, error) {
//			// Look id up in your client registry; error if unknown.
//			return jwksURI, inlineJWKS, nil
//		})

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
	// How a client authenticating with a CA-issued certificate
	// (tls_client_auth) is trusted. NoPKIClientAuthentication{} refuses
	// that method: right when no client uses it.
	// server.TrustedClientCAs{Roots: pool, Revocation: ...} has this
	// package check a certificate's chain against pool, and whether it
	// has been revoked (server.ClientCertificateCRLs, for example).
	// ClientCertificateChainVerifiedUpstream{} skips that check, for when
	// your TLS termination already verifies every client certificate's
	// chain (RequireAndVerifyClientCert), never otherwise: anyone could
	// then present a self-signed certificate naming a client's subject.
	// NoClientCertificateChainTrust{} accepts the certificate with no
	// chain trust at all, outside production only.
	ClientCertificateTrust: server.NoPKIClientAuthentication{},
	Clock:                  server.SystemClock{},
	Random:                 rand.Reader, // crypto/rand; production assurance requires exactly this reader
}

srv, err := server.New(cfg, deps)
```

(`fetcher` is a `*fapihttp.Client` — only needed if any client's keys
are fetched live from a `jwks_uri` rather than supplied inline; pass
`nil` if every client uses an inline `jwks`. Build one with
`fapihttp.New(transport, fapihttp.RecommendedConfig())`, where
`transport` comes from
`fapihttp.NewClient(fapihttp.RecommendedTransportConfig())`. Under
`AssuranceProduction` it must be: a fetcher over any other HTTP client
isn't `HardenedForProduction`, so a JWKS key source fetching through it
doesn't declare `LiveFetchHardened` and `New` refuses it, as it does a
`Dependencies.FederationHTTP` fetcher.)

**Whichever access-token format you pick here, the resource server that
verifies these tokens must be wired to match** — `resource.JWTAccessTokens`
for `server.JWTAccessTokens`, `resource.OpaqueAccessTokens{Store: ..., Issuer: ...}`
(the same `Store` instance, if co-located, and this AS's issuer) for
`server.OpaqueAccessTokens` — see step 7. The two sides agreeing on
format isn't checked for you: nothing stops you from constructing an AS
that issues opaque tokens and a resource server that only knows how to
verify JWTs, and every verification will fail with no compile-time
signal that they were ever mismatched. `cmd/conformance-as/wiring.go`
shows both sides wired consistently, switched on one runtime flag.

### Wallet attestation status

A server with `Config.AttestationBasedClientAuthentication` (wallet
apps, under HAIP or OpenID4VCI) also needs a
`Dependencies.AttesterTrust` and, under `AssuranceProduction`, a
`Dependencies.ClientAttestationStatus`. With
`server.X5CAttesterChain`, set its `Revocation` as for
`TrustedClientCAs`: `server.ClientCertificateCRLs{...}` with the CRLs of
the CAs issuing attester certificates, or
`server.NoClientCertificateRevocationCheck{}` to decline. A certificate
a CRL names is refused with `invalid_client`; a CA with no current CRL
is a check that couldn't decide, refused with `server_error` (500). A
`ClientCertificateRevocation` of your own reports a revoked certificate
by wrapping `server.ErrCertificateRevoked`.

`ClientAttestationStatus` decides whether an attestation that verified
has since been withdrawn by its attester. Every instance of a wallet
shares the attestation's `sub`, so a Wallet Provider revokes one
compromised instance through the attestation's `status` claim, a
Token Status List (draft-ietf-oauth-status-list). This package doesn't
fetch status lists; a checker does, along these lines:

```go
type walletStatus struct {
	lists *statusLists // yours: fetches through a *fapihttp.Client, caches by ttl/exp
}

func (w walletStatus) CheckClientAttestationStatus(ctx context.Context, a server.VerifiedClientAttestation) error {
	raw, ok := a.Claims["status"]
	if !ok {
		return nil // or refuse, if your attesters always set one
	}
	var status struct {
		StatusList struct {
			Index int    `json:"idx"`
			URI   string `json:"uri"`
		} `json:"status_list"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		return fmt.Errorf("%w: unreadable status claim", server.ErrClientAttestationRevoked)
	}
	// A Status List Token for status.StatusList.URI, verified as signed by
	// this attester: a.SignerKey, or a certificate of the same Wallet
	// Provider as a.SignerCertificates[0] — not merely one chaining to a
	// shared trust list.
	list, err := w.lists.Get(ctx, status.StatusList.URI, a.SignerKey, a.SignerCertificates)
	if err != nil {
		return err // server_error: nobody knows, so nothing is accepted
	}
	if list.Status(status.StatusList.Index) != 0 { // 0x00 is VALID
		return fmt.Errorf("%w: wallet instance withdrawn", server.ErrClientAttestationRevoked)
	}
	return nil
}
```

An error wrapping `server.ErrClientAttestationRevoked` refuses the
request with `invalid_client`; any other error with `server_error`. The
checker runs on every attestation-authenticated request, after the PoP
has verified, so cache the lists you fetch. When the attesters you
trust publish no status, pass `server.NoClientAttestationStatusCheck{}`
instead. [The native wallet guide](docs/guides/native-wallet.md) covers
the rest of a wallet's setup, on both sides.

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
	// UILocales language you have. a.Interaction.RedirectURI is where
	// the browser goes afterwards: show its host on the consent page.
	// a.Handle must come back to CompleteAuthorization once the user
	// is done.
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

**Serve the authorization pages with `server.AuthorizationPageHeaders`.**
Wrap `/authorize`, and every login, consent and error page of the
interaction, form submissions included:

```go
mux.Handle("GET /authorize", server.AuthorizationPageHeaders(http.HandlerFunc(authorize)))
mux.Handle("POST /authorize", server.AuthorizationPageHeaders(csrfProtected(http.HandlerFunc(decide))))
```

It sets `Content-Security-Policy: frame-ancestors 'none'` and
`X-Frame-Options: DENY` ("Authorization servers MUST prevent
clickjacking attacks", RFC 9700 §4.16: a consent page framed invisibly
over another site's has the user approve what they can't see),
`Referrer-Policy: no-referrer`, and `Cache-Control: no-store`. A page that
must be framed by a particular origin sets its own
`Content-Security-Policy` in the handler, which replaces the wrapper's.

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
// or, once the user has authenticated: server.Deny("user declined"),
// or server.AuthenticationFailed("not the account the client named").
// Before anyone has authenticated: server.DenyLocally("cancelled").

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

**Redirect only after the user has authenticated.** `Deny` and
`AuthenticationFailed` send the browser back to the client with
`access_denied` or `login_required`. RFC 9700 §4.11.2 says the
authorization server "MUST always authenticate the user first ...
before redirecting the user". Any client can register a phishing page as
its redirect URI and send users to your server only to be bounced
there with your name on it, whatever they choose. That includes a
member of an OpenID Federation registered automatically. So:

- a user who cancels, closes or gives up on the sign-in page before
  authenticating: complete with `server.DenyLocally(reason)`. It ends
  the interaction without a redirect: `CompleteAuthorization` returns
  `AuthorizationLocalError` with `access_denied`, which you render as a
  page of your own. The client's request simply expires.
- a user who authenticated, then declined: `server.Deny(reason)`.
- a user who authenticated but can't meet the request — not the account
  `a.Interaction.RequiredSubject` names, a method below its essential
  acr: `server.AuthenticationFailed(reason)`. A wrong password isn't
  this: let the user try again, or `DenyLocally`.
- a `prompt=none` request you'd have to show something for:
  `server.InteractionNeeded(...)`, which redirects. This is the
  silent-authentication exception §4.11.2 makes.

`CompleteAuthorization` also checks that the redirect URI is still
registered for the client, and answers `AuthorizationLocalError` if it
was removed since the request was pushed.
`server.BuildAuthorizationErrorRedirect`, which builds an error redirect
for a request that never got as far as an interaction, is for test
harnesses and refuses under `AssuranceProduction`.

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
`at_hash`, `azp`, `c_hash`, `s_hash`, `jti`, `nbf`, `cnf`), names
that change how a relying party processes the token (`_claim_names`,
`_claim_sources`, `sub_jwk`, `events`), and the authorization response
parameters `code`, `state` and `error`, which would make an ID token
look like a JARM response, are rejected. Identity claims only ever add
the names the client requested and the user approved, never a
server-managed one.

An extension's value is the client's own, so `extension.NewRegistry`
also refuses `ReturnInTokenClaims` under a name whose meaning a token's
recipient takes from the authorization server or the resource owner:
the RFC 9068 authorization attributes `roles`, `groups` and
`entitlements`, the RFC 8693 delegation claims `act` and `may_act`,
`authorization_details`, and the OIDC standard claims (`email`,
`name`, ...). Set roles or delegation yourself, in `IDTokenClaims` or
your own `AccessTokenIssuer`, from your own policy. On a name
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
(`req.AttestedClientAuthentication()`, which also passes the request's
`client_id`, refused if it names another client than the attestation)
— the only client authentication
offered for a grant you serve, so its clients register for
attestation-based client authentication — and check its DPoP proof or
client certificate with `VerifyTokenRequestBinding`: the same checks,
and the same replay records, as this package's own grants. List the
grant type in `Config.AdditionalGrantTypes` so `Metadata` advertises
it. Whether the client may use the grant, and the grant itself, stay
yours. Issue the access token by passing the authenticated client, the
binding, the subject and what you granted to `IssueAccessToken`, which
returns the token response to write with `WriteJSON`; don't call
`Dependencies.AccessTokens` directly. To let the client refresh what it
was granted, pass the same to `IssueRefreshToken`, and set the result
as the response's `RefreshToken` (with `HasRefreshToken`) before
writing it: `RefreshAccessToken` then redeems it
like its own, bound to the client's instance key. Give both the same
`GrantID`, so `RevokeGrant`, or the client revoking its refresh token,
ends the first access token too, not only the refreshed ones. Such a
grant may not include `openid`, since no user authenticated.

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
response stays the same empty 200. Access tokens can't be revoked: a
live access token the server issued to the client, JWT or opaque, gets
`unsupported_token_type` (RFC 7009 §2.2.1). Anything else that isn't
one of the client's refresh tokens — a JWT-shaped string the server
didn't sign, or a token sent with `token_type_hint=access_token` that's
no token of the client's — is an invalid token, answered with the same
empty 200 (§2.2). Access tokens expire on their own, and `RevokeGrant`
ends them early.

**Reading an ID token hint elsewhere.** For a flow outside this package
that takes an `id_token_hint`, such as an RP-Initiated Logout endpoint,
`Server.VerifyIDTokenHint` checks that the hint is an ID token this
server issued to the requesting client and returns its subject. It
accepts an expired hint, as OpenID Connect requires, so the subject says
whose session to act on, never that anyone is logged in now. For a
pairwise client that subject is the client's pairwise `sub`:
`Server.ResolveIDTokenHint` maps it to the user's internal subject (and
`Server.ResolveClientSubject` does the same for a `sub` sent any other
way, such as a `login_hint`), wherever the server can map pairwise subs
back; otherwise compare a user you know with `Server.ClientSubject`.

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
apiURL, err := fapi.ParseEndpointURL("https://api.example.com")
if err != nil {
	return err
}
cfg := resource.Config{
	Limits: resource.Limits{
		MaxDPoPProofAge: time.Minute,      // how old a DPoP proof's iat may be
		MaxClockSkew:    10 * time.Second, // tolerance either direction: 10 to 60 seconds in production
	},
	Assurance:    resource.AssuranceDevelopment, // AssuranceProduction once your real deps are ready
	ResourceURLs: []fapi.URL{apiURL},             // this API's own external URL(s), as clients call it
	// Deployment: resource.DeploymentSingleInstance, // required under AssuranceProduction: or DeploymentHorizontallyScaled for a fleet
}
```

All four are required — `NewVerifier` rejects a zero `MaxDPoPProofAge`,
a negative `MaxClockSkew`, a zero `Assurance` or no `ResourceURLs`, the
same "no implicit default" discipline `server.Config` follows.

`ResourceURLs` are this resource server's own external URLs: each an
origin, optionally with a path prefix (`https://api.example.com/v1`),
with no query. A DPoP proof's `htu` must name the URL its request was
sent to, and only you know yours: the `Host` header, and whatever path
a front end forwards, are the client's to choose. `Verify` takes the
request's target to be its escaped path at one of these origins, and
refuses a request no `ResourceURLs` prefix covers. List more than one
for an API reachable under several names (an mTLS alias host, say): a
proof naming any of them is accepted. As with the server,
`resource.AssuranceProduction` refuses `memstore`'s stores and
`keys/ephemeral`'s key sources: it requires the issuer key source to
declare `keys.KeySourceAssurance` (`keys.LocalIssuerKeys` does, and so
does `keys.JWKSIssuerKeySource` on a `fapihttp` client without a loopback
exception), the opaque-token, replay, nonce and
revocation stores to declare `storage.StoreAssurance`, and
`crypto/rand.Reader` when DPoP nonces are on. It refuses
`resource.NoRevocation{}`: decline revocation there with
`resource.NoRevocationUntilExpiry{MaxTokenLifetime: ...}` of at most 15
minutes, which `Verify` then holds every token's remaining lifetime
to. It requires `Dependencies.Clock` to be `resource.SystemClock{}` (or
a clock declaring `resource.ClockAssurance`) reading the real time,
`MaxDPoPProofAge` at most 5 minutes, `DPoPNonceLifetime` at most 15,
and a `MaxClockSkew` between 10 and 60 seconds, as
`server.New` does: FAPI 2.0 Security Profile §5.3.2.1 has a JWT whose
`iat` is up to 10 seconds in the future accepted and one more than 60
seconds ahead refused, and here the skew also extends how long past its
`exp` a token is still accepted. It also requires `Deployment`:
`resource.DeploymentSingleInstance`, or
`resource.DeploymentHorizontallyScaled` when more than one instance
shares the stores, which then must also declare
`CrossInstanceConsistent`.

### Pairwise subjects at a resource server

For a client with pairwise subjects, `AuthorizationContext` carries two
subjects:

- **`InternalSubject`** is the user's internal subject, which your API
  authorizes by, through `EndUser` (see "Verify a request" below).
  Never return it to a client: it's exactly what the client's pairwise
  `sub` hides.
- **`ClientSubject`** is the pairwise `sub` the client knows the user
  by. **Compare and return anything client-facing with
  `ClientSubject`**: a user ID in a path (`/users/{id}/accounts`) or a
  body, the `sub` of an ID token the client holds, or a "me" response.

For a public client both are the same. `InternalSubject` is left out of
`AuthorizationContext`'s JSON encoding, so a debug dump can't leak it.

A JWT access token's `sub` is pairwise, so mapping it back takes what
reverses every pairwise `sub`: the server's keys, store or resolver.
OpenID Connect Core §8.1 reserves that to the OpenID Provider, so it
depends on whose resource server it is.

**The OP's own resource server** (a separate service, run as part of
the OP) is given the same means as the authorization server.
`serverresource.NewVerifier` does this for endpoints in the server's
own process; a separate one sets it up itself:

```go
// The OP's own resource server, with a reversible deriver: the same
// two keys and prefix as the authorization server.
deriver, err := pairwise.NewReversible(macKey, encKey,
	keys.DeclareCustody(keys.KeyCustody{Durable: true, CrossInstanceConsistent: true}))
if err != nil {
	log.Fatal(err)
}
cfg.PairwisePrefix = prefix          // the server's Config.Subjects.Prefix
deps.PairwiseSubjects = deriver // *pairwise.ReversibleDeriver implements pairwise.Lookup
// Or pairwise.NewMapping over the server's store; or, with a one-way
// deriver, deps.PairwiseSubjectResolver = the server's resolver.
```

**A resource server outside the OP** (a third party's API that accepts
your access tokens) must never be given those. It accepts pairwise
`sub`s as the client knows them instead:

```go
cfg.PairwiseResolution = resource.PairwiseClientSubjectsOnly
// authz.InternalSubject is then "" for a pairwise sub: authorize by
// authz.ClientSubject together with authz.ClientID, for a token whose
// authz.SubjectKind is resource.SubjectEndUser (a client credentials
// token's ClientSubject is the client's own client_id).
```

A verifier with neither refuses a pairwise JWT access token with
`server_error`, rather than give its pairwise `sub` as
`InternalSubject`. An opaque access token's record already keeps the
internal subject, which only the OP's own resource servers can read
(under `PairwiseClientSubjectsOnly` it isn't reported either).

A JWT access token is readable by the client, so nothing in it may
identify the user beyond its pairwise `sub`: a `GrantID` or extension
claim built from an account number would undo the pairwise subject. Use
opaque random values, or opaque access tokens.

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
// userinfoURL: the endpoint's own external URL, which a DPoP proof's htu names.
verifier, err := serverresource.NewVerifier(cfg, deps, serverresource.Options{
	ResourceURLs: []fapi.URL{userinfoURL},
})
```

`ResourceURLs` is required: the server's configuration names no
protected endpoint of its own (see `resource.Config.ResourceURLs`
below). It checks the verifier at the server's own `Assurance` and
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
	issuerKeys, asIssuer, asIssuer.String(), // audience: the AS's issuer, unless clients name this resource server (see below)
	fapi.ES256, 5*time.Minute, // must be >= the AS's own Limits.AccessTokenLifetime
	8, // max candidate keys tried per token — size to your AS's own key-rotation overlap, not a library default
)

// If the AS issues OpaqueAccessTokens instead: the *same*
// storage.AccessTokenStore instance the AS writes to — only realistic
// if this resource server shares that storage backend with the AS
// (co-located, or a real shared database).
// accessTokens, err := resource.NewOpaqueAccessTokens(sameAccessTokenStore, asIssuer) // a token another issuer recorded is refused
// accessTokens.Audience = asIssuer.String() // required under AssuranceProduction, as for JWTs
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
reasoning for why declining must be a conscious choice). Under
`AssuranceProduction` decline with
`resource.NoRevocationUntilExpiry{MaxTokenLifetime: 10 * time.Minute}`
instead (at most 15 minutes, and at least the AS's
`AccessTokenLifetime`): it bounds how long a token the AS revoked stays
usable here.

```go
deps := resource.Dependencies{
	AccessTokens: accessTokens,
	Replay:       memstore.NewReplayStore(), // DPoP proof jti reuse — its own instance; may differ from the AS's
	Revocation:   revocationStore,           // the same instance the AS writes to
	Clock:        resource.SystemClock{},
}

verifier, err := resource.NewVerifier(cfg, deps)
```

### Audience-restricted tokens (RFC 8707 resource indicators)

By default an access token's `aud` is the authorization server's issuer
identifier, so every resource server verifying with that audience
accepts every token the AS issues. When one AS serves several resource
servers that don't trust each other — an AS shared by several
OpenID4VCI Credential Issuers, say — a resource server that receives a
token could replay it at another. RFC 8707 resource indicators close
that: the client names the resource server in a `resource` parameter,
the AS restricts the token's `aud` to it, and every other resource
server refuses the token.

On the authorization server, list the resource servers it issues
tokens for in `Config.Resources`, or decide them at request time with
`Dependencies.ResourcePolicy`, or both:

```go
cfg.Resources = []string{
	"https://pid-issuer.example.com",
	"https://diploma-issuer.example.com",
}

// Optional: admit resources the list doesn't name, such as each
// Credential Issuer whose metadata lists this AS in
// authorization_servers (OpenID4VCI §12.2.4).
deps.ResourcePolicy = credentialIssuerPolicy{}

type credentialIssuerPolicy struct{ /* your issuer registry */ }

func (p credentialIssuerPolicy) AllowResources(ctx context.Context, client storage.RegisteredClient, resources []string) error {
	for _, r := range resources {
		known, err := p.lookUpIssuer(ctx, r)
		if err != nil {
			return err // couldn't decide: server_error, never read as a refusal
		}
		if !known {
			return fmt.Errorf("%s: %w", r, server.ErrResourceNotAllowed) // invalid_target
		}
	}
	return nil
}
```

A resource is checked against, in order: the client's own
`storage.RegisteredClientConfig.AllowedResources`, if it registered any
(a client registered automatically through OpenID Federation gets
`AutomaticRegistrationConfig.AllowedResources`, the same for all of
them, and without that may name any resource the server accepts); then
`Config.Resources`; then, only for those the list doesn't name,
`ResourcePolicy`. Anything refused is `invalid_target`. The client
names resources at PAR — repeated `resource` form parameters, or a
string or array in the request object — or in the CIBA request object,
and may repeat a subset of them at the token endpoint to narrow one
access token (RFC 8707 §2.2), on the code exchange, the CIBA poll or a
refresh; a refresh token always keeps the grant's whole set. The access
token's `aud` is then the resource (a JSON string), or, for several,
an array of them. A request naming no resource still gets the issuer as
its audience, and with neither `Config.Resources` nor `ResourcePolicy`
set, `resource` is ignored as it always was.

A client confined by `AllowedResources` never gets an issuer-audience
token, though: every resource server accepting the issuer as an
audience would take it, whatever the list says. If it lists exactly one
resource, a request naming none — at PAR, in a CIBA request, for
client credentials, or to `IssueAccessToken`/`IssueRefreshToken` — is
for that one, recorded with the grant as if the client had named it and
checked against `Config.Resources` and `ResourcePolicy` the same way;
if it lists several, the request must name one, or it's
`invalid_target`. A grant made without resources before the client was
confined gets the same treatment at its next token request. For a grant you serve
yourself (`Config.AdditionalGrantTypes`), pass
`TokenEndpointRequest.Resources()` as `IssueAccessTokenRequest.Resources`
and `IssueRefreshTokenRequest.Resources`, and check the resources your
grant may be used for against `Resources()` too: `Parameters()` leaves
`resource` out, since the client may have sent several.

With resource indicators disabled, every token would be addressed to the
issuer, so a client listing `AllowedResources` is refused with
`server_error` rather than given one; `server.New` refuses
`AutomaticRegistration.AllowedResources` then, and
`Server.CheckClientRegistration` reports such a registered client.

A grant's resources are checked again at every access token it issues
— the code exchange, the CIBA poll, each refresh — as its scopes are:
once a resource is removed from the client's `AllowedResources` or from
`Config.Resources`, or the `ResourcePolicy` refuses it, a token request
whose token would still name it gets `invalid_target`. The client can
narrow to the resources it may still use; with none left (resource
indicators turned off, say) it must authorize again. So
`ResourcePolicy` is asked on every refresh, not only when the grant is
made: keep it cheap, caching what it looks up, and don't fetch from a
resource indicator — a client chooses up to 16 a request — before
checking it's one you might serve. Resources are compared exactly, as
strings, both here and at the resource server; a policy that accepts a
resource by normalizing it (host case, a trailing slash, a default
port) still gets a token addressed to the client's own spelling, so
accept only the spelling your resource servers verify with.

Each resource server then verifies with its own identifier as the
audience. A Credential Endpoint in the AS's own process passes it to
`serverresource.NewVerifier`:

```go
verifier, err := serverresource.NewVerifier(cfg, deps, serverresource.Options{
	Resource:     "https://pid-issuer.example.com",
	ResourceURLs: []fapi.URL{credentialEndpointURL},
})
```

and one deployed on its own sets `JWTAccessTokens.Audience` (or
`OpaqueAccessTokens.Audience`) to it in place of `asIssuer.String()`.
A token issued for the diploma issuer is then refused at the PID
issuer. Opaque access tokens carry no `aud` on the wire; the AS records
their audience with the token, and `OpaqueAccessTokens` checks it when
its `Audience` is set.

A token issued for several resources is accepted at each of them, as
RFC 8707 intends: any of those resource servers that receives it could
present it to another. Every FAPIgo access token is sender-constrained
(DPoP or mTLS), so it's useless without the client's key, but a client
that doesn't want its resource servers to share a token narrows each
token request to the one resource it's for.

The consent screen is told which resources the tokens would be for —
`InteractionRequest.Resources` (and `BackchannelInteractionRequest`'s
for CIBA), the client's default included — so where several resource
servers share the AS, show them: the user can then tell which one a
token is for. Approving, `GrantedAuthorization.Resources` can narrow
them to a subset of those; leaving it nil grants all of them, and one
that wasn't requested makes the completion fail, as an unrequested
scope does.

While clients move to sending `resource`, a resource server can also
accept tokens issued without one: `AcceptIssuerAudience: true` in
`serverresource.Options`, or the issuer in `AdditionalAudiences`. Turn it
off once they all do, since until then such a token, which any resource
server verifying the issuer audience accepts, works here too. A UserInfo
endpoint keeps the default (no `Resource`): it accepts only tokens
issued without a resource, so a client that also calls UserInfo names
the AS's issuer as one of its resources (list it in `Config.Resources`)
and narrows each token request to the resource it's for. A client
confined by `AllowedResources` must list the issuer there too to call
UserInfo at all, and then, listing more than one, name a resource in
every request.

### Verify a request

```go
// The target a DPoP proof's htu must name comes from Config.ResourceURLs
// and the request's escaped path — see below.
authCtx, err := verifier.Verify(ctx, resource.VerifyRequestFromHTTP(r))
```

On success, `authCtx.EndUser()`/`ClientID`/`Scopes`/`Claims` are what
your API handler needs to authorize the call (return
`authCtx.ClientSubject`, never the internal subject, to the client).
Authorize anything that belongs to a user by `EndUser`, never by
`InternalSubject` alone: a client credentials token's subject is the
client's own `client_id` (`SubjectKind` is `SubjectClient`), and a client
can be registered with a `client_id` equal to a user's identifier
(automatically, through OpenID Federation, for one). `EndUser` reports
`ok` false for it:

```go
user, ok := authCtx.EndUser()
if !ok {
	resource.NewInsufficientScopeError(authCtx, "the access token wasn't issued for a user").WriteJSON(w)
	return
}
accounts := accountsOf(user)
```

Call `authCtx.SetDPoPNonce(w.Header())` on the response, so a client's
next call already carries a current DPoP nonce when you've enabled them. A
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

It takes no URL from you, and none from `r`'s `Host` header, which the
client controls — the same reasoning `server.Endpoints` is never
inferred from a request either. `Verify` builds the DPoP proof's
expected `htu` from `Config.ResourceURLs` and `r.URL.EscapedPath()`:
the escaped path, never the decoded `r.URL.Path`, under which a request
for `/accounts/a%2Fb` (one segment, `a/b`) would be the different
resource `/accounts/a/b`, and a proof made for that one would verify
here. A handler mounted on a path outside every `ResourceURLs` prefix
has each request refused with 400 `invalid_request`. Behind a proxy
that rewrites the path it forwards (stripping a prefix, say), set
`VerifyRequest.URL` to the absolute URL the client called instead;
`Verify` refuses one that is relative, isn't http(s), or isn't under a
`ResourceURLs` entry.

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
certificate-bound token. For a proxy that forwards RFC 9440's
`Client-Cert` header, `fapihttp.ForwardedClientCertificate` reads it,
and refuses a request its trust check says didn't come from the proxy:

```go
// The proxy connects from 10.0.0.5, and strips and re-sets Client-Cert.
fromProxy := fapihttp.RemoteAddrIn(netip.MustParsePrefix("10.0.0.5/32"))

cert, err := fapihttp.ForwardedClientCertificate(r, fapihttp.ClientCertHeader, fromProxy)
if err != nil {
	http.Error(w, "forbidden", http.StatusForbidden)
	return
}
req := resource.VerifyRequestFromHTTP(r)
req.PeerCertificate = cert // nil: the client presented none
```

The authorization server's `…FromHTTP` requests take it the same way
(`TokenEndpointRequest.SetPeerCertificate`, or the `PeerCertificate`
field).

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
explicitly instead.

Under `AssuranceProduction`, `New` holds `Limits` to bounds
`RecommendedLimits` meets — `MaxClockSkew` from 10 to 60 seconds,
`SessionLifetime` at most an hour, `ClientAssertionLifetime` 5 minutes,
`MaxIDTokenLifetime` 24 hours and `MaxJARMResponseLifetime` 10 minutes —
and requires `Clock` to be `client.SystemClock{}` (or a clock declaring
`client.ClockAssurance`) reading the real time.

Under `AssuranceProduction`, `New` also refuses any `Dependencies.HTTP` but
`fapihttp.NewClient`'s client (or a copy of it): one with a proxy,
another dialer or weaker TLS settings swapped into its transport, a
cloned or wrapped transport, or one allowing loopback addresses, is
refused. For mutual TLS (`storage.SenderConstrainMTLS`, or
certificate-based client authentication), give the client certificate
when you build it, and likewise a private CA's roots or a certificate
pin, rather than changing the transport afterwards:

```go
cfg := fapihttp.RecommendedTransportConfig()
cfg.Certificates = []tls.Certificate{clientCert} // or cfg.GetClientCertificate
// cfg.RootCAs = privateRoots           // only for a server under a private CA
// cfg.VerifyConnection = pinServerKey  // optional pinning
transport, err := fapihttp.NewClient(cfg)
```

Then, in your handlers:

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

### Asking for a token for a particular resource server

When one authorization server issues tokens for several resource
servers, set `Resource` to name the one, or ones, the token is for (RFC
8707 resource indicators). Each is an absolute URI without a fragment.
The client sends them on the pushed request (in the request object,
under a profile that signs one), sends them again when it exchanges
the code, and keeps them in `TokenSet.Resource`. A refresh sends them
again too, unless `RefreshTokenRequest.Resource` narrows it to some of
them. An OpenID4VCI wallet whose Credential Issuer names a separate
authorization server (`authorization_servers` in its metadata) names
the issuer itself (OpenID4VCI §5.1.2):

```go
session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{
	Scope:    []string{"eu.europa.ec.eudi.pid.1"},
	Resource: []string{credentialIssuerMetadata.CredentialIssuer}, // e.g. "https://issuer.example.com"
})

// Later, a refresh repeats it: the new access token is for the same issuer.
tokens, err = c.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: tokens})
```

An authorization server that doesn't support resource indicators
ignores them, so setting `Resource` is safe either way. A server that
does may issue a token only that resource server accepts, and refuse
(`invalid_target`) one it doesn't serve. `BeginBackchannelAuthenticationRequest`
has the same field for CIBA, and `ClientCredentialsTokenRequest` for a
client credentials token. Use `Resource` rather than an `Extensions`
value named `resource`: `BeginAuthorization` refuses a request with both.
