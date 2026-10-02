# Identity check demo

**Fernway**, a fintech, opens a savings account for **Sam** and has to
verify who they are. Instead of a photo-ID upload, Sam signs in at their
bank, **Alder Bank**, acting as an [OpenID Provider](https://openid.net/specs/openid-connect-core-1_0.html):

- Fernway asks for exactly the identity claims it needs, and where it
  wants each one: name and date of birth in the ID token, address, email
  and phone number from UserInfo (the `claims` parameter, OIDC Core
  §5.5).
- It asks for a sign-in approved in the bank's app (`acr_values`), made
  within the last ten minutes (`max_age`).
- Sam sees every claim on the bank's consent page and can untick any of
  them: the bank releases only what's left ticked.
- The ID token and the UserInfo response come back signed by the bank
  and encrypted to Fernway (RSA-OAEP-256 for the ID token,
  ECDH-ES+A256KW for UserInfo), so nothing on the wire between them can
  read the claims.

A second relying party, **Brightline Rentals**, asks for less and gets
its ID token signed but not encrypted. An **attack lab** tries to get
around each protection, and every check shows a protocol trace of what
crossed the wire.

Everything runs in one process, on your machine, each party at its own
`*.localhost` host.

> This is a demo. Every store is in memory, every key is generated at
> startup, and the bank, companies, people and their details are made up.

This is a separate Go module. It builds against this checkout of the
library (`replace` in `go.mod`), and release-please ignores it.

## Running it

```sh
cd examples/identity-check
go run ./cmd/identity-check -open
```

`-open` starts Chrome (or Chromium; `-chrome` gives its path) on
**https://console.localhost:8647/**, in a separate profile under
`.identity-state/chrome-profile` that accepts the demo's certificate —
only that one, identified by its key — without a warning. Use that
window for the whole demo, and only for it: Chrome accepts that key for
*any* host in this profile, and the key sits in `.identity-state/`.
Chrome shows a banner about an unsupported command-line flag; that's
expected. Ctrl-C stops the demo.

It uses port 8647. Every demo has its own port, so they can all run at
once; [the examples overview](../README.md#ports) lists them. `-port`
changes it.

### Other browsers

Every page is served over HTTPS with one certificate from the demo's own
CA. The CA can only vouch for `*.localhost` (an X.509 name constraint),
never a real site or an IP address, and it's kept in `.identity-state/`,
so this is once, not every run. The startup banner prints the command for
your system:

| | Trust | Remove |
|---|---|---|
| macOS (Chrome, Safari) | `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db .identity-state/ca.pem` | `security delete-certificate -c "Identity check demo CA"` |
| Linux (Chrome) | `certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n "Identity check demo CA" -i .identity-state/ca.pem` | `certutil -d sql:$HOME/.pki/nssdb -D -n "Identity check demo CA"` |
| Windows | `certutil -user -addstore Root .identity-state\ca.pem` | `certutil -user -delstore Root "Identity check demo CA"` |
| Firefox | Settings → Privacy & Security → View Certificates → Authorities → Import | Same list → Delete |

`-reset` deletes `.identity-state/` and issues a new CA; remove the old
one from your trust store if you'd trusted it. `-state` moves the
directory.

## Who's who

| Host | Party |
|---|---|
| `console.localhost` | The console: a guided tour and the traffic between the parties |
| `fernway.localhost` | Fernway, and the attack lab |
| `brightline.localhost` | Brightline Rentals |
| `bank.localhost` | Alder Bank's OpenID Provider, with its sign-in and consent page and its UserInfo endpoint |

Sign in at the bank as **sam**, PIN **2468**.

## What to try

The console's **Start here** panel walks through all of this in order.

**1. Verify with Alder Bank.** On Fernway, press **Verify with Alder
Bank**. Fernway's FAPIgo client pushes the request to the bank (PAR),
with its `claims`, `acr_values` and `max_age`, and sends your browser
there with only a `request_uri`. At the bank, sign in with the app and
share everything. Fernway checks the ID token's `acr` and `auth_time`,
fetches UserInfo with its DPoP-bound token, and shows what the bank
confirmed. The **protocol trace** shows the ID token and UserInfo
response as they crossed the wire: encryption headers, and ciphertext.

**2. Share less.** Start again and untick your address and phone number.
The bank leaves them out. The access token records which UserInfo claims
you approved, so asking again gets nothing more.

**3. Sign in too weakly, or too long ago.** Each is refused:

| Choice at the bank | What stops it |
|---|---|
| PIN only | `acr_values` is a request, not a requirement: the bank signs you in and reports `acr` `urn:alder-bank:acr:pin` in the ID token, and Fernway, which needs `urn:alder-bank:acr:app`, refuses it |
| Use my earlier sign-in | `max_age` is a requirement (OIDC Core §3.1.2.1): the sign-in is three hours old, so the bank itself answers Fernway with `login_required` instead of an authorization code |

**4. Attack the verified check.** Each attack is refused:

| Attack | What stops it |
|---|---|
| Read the claims off the wire | The ID token and UserInfo response are encrypted to Fernway (JWE): an observer sees only their headers |
| Swap in Alex's ID token | A genuine ID token from the bank, for Fernway, but from Alex's sign-in: its `nonce` isn't this sign-in's |
| Swap in Brightline's ID token | A genuine ID token from the bank, but Brightline's, and not encrypted, though Fernway registered for encrypted ID tokens |
| Swap in Alex's UserInfo response | Genuine and encrypted to Fernway, but its `sub` isn't the ID token's (OIDC Core §5.3.4) |
| Tamper with the UserInfo response | It no longer decrypts |
| Use the access token from another device | The token is DPoP-bound to Fernway's key |

**5. Compare Brightline Rentals.** It asks only for your name, date of
birth and address, accepts any sign-in, and gets its ID token signed
but not encrypted. You still decide what's released.

## How it's built

Everything here uses FAPIgo's public API only.

| Piece | FAPIgo |
|---|---|
| Alder Bank | `server.Server` with `Dependencies.IdentityClaims` (its customers' verified claims), `Dependencies.ClientKeys` and `Dependencies.ClientEncryptionKeys` both set to an `ephemeral.ClientKeySource` holding each client's registered JWK Set (its client-assertion key and the keys to encrypt to it), and `Algorithms.UserInfo` and the ID token and UserInfo encryption algorithms; clients registered for encrypted ID tokens and UserInfo responses; the consent page reading `InteractionRequest.RequestedClaims`, `ACRValues` and `MaxAge`, and answering with `GrantedAuthorization.ApprovedIdentityClaims` and `NewAuthenticationContext`'s `acr` and authentication time; discovery from `server.Metadata` plus `userinfo_endpoint` and `claims_supported` |
| The UserInfo endpoint | `serverresource.NewVerifier`; the approved claim names from the access token's `server.RequestedUserinfoClaimsKey`; `Server.SignUserInfoResponse`, which signs and, for a client that registered for it, encrypts |
| Fernway, Brightline | `client.NewFromDiscovery`; `BeginAuthorization` with `Claims`, `ACRValues` and `MaxAge`; `ExchangeCode`, with `Dependencies.Decryption` for the encrypted ID token; `TokenSet.IDTokenClaims` (`ACR`, `AuthTime`, the claims); `FetchUserInfo` |

The code:

- [`identity/bank.go`](identity/bank.go) — Alder Bank's OpenID Provider, sign-in and consent page, and UserInfo endpoint.
- [`identity/rp.go`](identity/rp.go) — Fernway and Brightline: the identity check.
- [`identity/attacks.go`](identity/attacks.go) — the attack lab, and the scripted sign-ins it replays.
- [`identity/trace.go`](identity/trace.go) — the protocol trace, and the in-flight substitutions.
- [`identity/e2e_test.go`](identity/e2e_test.go) — the checks, the refusals and every attack, driven end to end.

## What's simplified

- Sign-in is a username and a PIN; "approve in the app" is a radio
  button. A real bank would run its own strong authentication.
- Each client's JWK Set is registered inline, and `keys/ephemeral`'s
  `ClientKeySource` reads it: development only. A production deployment
  supplies its own `keys.ClientKeySource` and
  `keys.ClientEncryptionKeySource`, for registered keys or a client's
  `jwks_uri`.
- The OIDC Core §3.1.3.7 checks of `acr` and `auth_time` are Fernway's
  own code: FAPIgo exposes both on `TokenSet.IDTokenClaims` and leaves
  the decision to the relying party, while the bank enforces `max_age`
  itself.
