# Linked accounts demo

**Pocketwise**, a budgeting app, links **Sam**'s **Alder Bank** accounts
for 90 days. Sam approves once. After that, Pocketwise keeps the
accounts up to date on its own, with nobody signing in:

- Linking asks for `offline_access` and an `account_access` [Rich
  Authorization Request](https://www.rfc-editor.org/rfc/rfc9396) naming
  no accounts, so Sam chooses which to share at the bank.
- Each sync redeems Pocketwise's **refresh token** for a fresh,
  DPoP-bound access token, authenticating as Pocketwise. The refresh
  token isn't rotated: FAPI 2.0 says an authorization server "shall not
  use refresh token rotation except in extraordinary circumstances".
- Sam can withdraw Pocketwise's access at any time from the bank's
  **Connected apps** page, and the consent runs out after 90 days.

A **demo clock** fast-forwards time, and an **attack lab** tries to
misuse the long-lived access.

Everything runs in one process, on your machine, each party at its own
`*.localhost` host.

> This is a demo. Every store is in memory, every key is generated at
> startup, and the bank, apps, people and accounts are made up.

This is a separate Go module. It builds against this checkout of the
library (`replace` in `go.mod`), and release-please ignores it.

## Running it

```sh
cd examples/linked-accounts
go run ./cmd/linked-accounts -open
```

`-open` starts Chrome (or Chromium; `-chrome` gives its path) on
**https://console.localhost:8648/**, in a separate profile under
`.linked-state/chrome-profile` that accepts the demo's certificate —
only that one, identified by its key — without a warning. Use that
window for the whole demo, and only for it: Chrome accepts that key for
*any* host in this profile, and the key sits in `.linked-state/`.
Chrome shows a banner about an unsupported command-line flag; that's
expected. Ctrl-C stops the demo.

It uses port 8648. Every demo has its own port, so they can all run at
once; [the examples overview](../README.md#ports) lists them. `-port`
changes it.

### Other browsers

Every page is served over HTTPS with one certificate from the demo's own
CA. The CA can only vouch for `*.localhost` (an X.509 name constraint),
never a real site or an IP address, and it's kept in `.linked-state/`,
so this is once, not every run. The startup banner prints the command for
your system:

| | Trust | Remove |
|---|---|---|
| macOS (Chrome, Safari) | `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db .linked-state/ca.pem` | `security delete-certificate -c "Linked accounts demo CA"` |
| Linux (Chrome) | `certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n "Linked accounts demo CA" -i .linked-state/ca.pem` | `certutil -d sql:$HOME/.pki/nssdb -D -n "Linked accounts demo CA"` |
| Windows | `certutil -user -addstore Root .linked-state\ca.pem` | `certutil -user -delstore Root "Linked accounts demo CA"` |
| Firefox | Settings → Privacy & Security → View Certificates → Authorities → Import | Same list → Delete |

`-reset` deletes `.linked-state/` and issues a new CA; remove the old
one from your trust store if you'd trusted it. `-state` moves the
directory.

## Who's who

| Host | Party |
|---|---|
| `console.localhost` | The console: a guided tour, the demo clock, and the traffic between the parties |
| `pocketwise.localhost` | Pocketwise: linking, syncing, and the attack lab |
| `bank.localhost` | Alder Bank's authorization server, sign-in and consent page, and Connected apps |
| `api.bank.localhost` | Alder Bank's account information API |

**Thriftly**, another budgeting app with its own valid credentials at
the bank, has no pages: the attack lab borrows them.

Sign in at the bank as **sam**, PIN **2468**.

## What to try

The console's **Start here** panel walks through all of this in order.

**1. Link your accounts.** On Pocketwise, press **Link Alder Bank
accounts**, sign in, choose accounts, and approve. The bank records the
approval under a **grant ID** (`server.GrantedAuthorization.GrantID`)
and lists it on Connected apps. Pocketwise gets a refresh token valid
for 90 days, and a short-lived access token.

**2. Sync without you.** Press **Sync now**: the refresh token buys a
new access token, which reads only the accounts you shared. Rotate
Pocketwise's DPoP key and sync again: a confidential client may rotate
its DPoP key at refresh (RFC 9449 §5), and the new access token is bound
to the new key. Fast-forward a day between syncs if you like.

**3. Misuse the long-lived access.** Each attack is refused:

| Attack | What stops it |
|---|---|
| Redeem the refresh token as Thriftly | Thriftly authenticates fine, but the refresh token wasn't issued to it (`invalid_grant`) |
| Redeem the refresh token without client authentication | Refreshing needs the client's own authentication (`invalid_client`) |
| Refresh asking for more scope | A refresh can narrow the scope, never widen it (`invalid_scope`) |
| Use the access token with another app's DPoP key | The access token is bound to Pocketwise's DPoP key (`invalid_token`) |

**4. Withdraw Pocketwise's access.** On Connected apps, revoke Pocketwise
(`server.Server.RevokeGrant`), then sync in Pocketwise. The refresh is
refused (`invalid_grant`), and so is the access token Pocketwise still
holds: every token from the grant carries its `grant_id`, and the API
checks it (`invalid_token`).

**5. Let the consent run out.** Link again, fast-forward 91 days on the
console, and sync. The refresh token expired 90 days after it was issued
— refreshing never extends it — so Pocketwise has to ask again.

## How it's built

Everything here uses FAPIgo's public API only.

| Piece | FAPIgo |
|---|---|
| Alder Bank | `server.Server` with `Config.RAR`, both apps registered with `AuthorizationDetailsTypes` for `account_access`, and `Dependencies.AuthorizationCodeRARPolicy` set to `server.AllowRequestedAuthorizationDetails`; `Limits.RefreshTokenLifetime` of 90 days; the token endpoint serving `ExchangeAuthorizationCode` and `RefreshAccessToken`; the consent page answering with `GrantedAuthorization.AuthorizationDetails` (the chosen accounts) and `GrantID`; Connected apps calling `Server.RevokeGrant`; `Dependencies.Revocation` a `memstore.RevocationStore` the API reads too |
| The account information API | `serverresource.NewVerifier`, which also refuses an access token whose grant was revoked; the shared accounts from the token's `authorization_details` claim (`extension.ParseGrantedRAR`, `RARGet`) |
| Pocketwise | `client.NewFromDiscovery`; `BeginAuthorization` with `offline_access` and `AuthorizationDetails`; `CompleteAuthorization`; `RefreshTokens` for every sync; `ProtectedResource` for the API |
| The demo clock | one `Now()` behind `server.Dependencies.Clock` and `client.Dependencies.Clock` |

The code:

- [`linked/bank.go`](linked/bank.go) — Alder Bank's authorization server, consent page and Connected apps.
- [`linked/pocketwise.go`](linked/pocketwise.go) — Pocketwise: linking, syncing, DPoP key rotation and the attack lab.
- [`linked/api.go`](linked/api.go) — the account information API.
- [`linked/rar.go`](linked/rar.go) — the `account_access` detail type.
- [`linked/apps.go`](linked/apps.go) — the customer, the two apps, and the rotating DPoP key.
- [`linked/e2e_test.go`](linked/e2e_test.go) — linking, syncing, every attack, revocation and expiry, driven end to end.

## What's simplified

- One customer, signed in by username and PIN; Connected apps assumes
  it's Sam. A real bank would authenticate the customer properly.
- Syncs happen when you press the button, not on a schedule.
- The demo clock moves the bank, its API and Pocketwise together. TLS
  certificates still use real time.
