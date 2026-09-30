# Decoupled checkout demo

**Alder Bank**'s customer, Sam, approves on their phone something that
was started on another device: a €42.50 payment at **Harbour Coffee**'s
till, or linking their accounts to the **Pocketwise** budgeting app.
The flow is [OpenID Connect Client-Initiated Backchannel Authentication
(CIBA)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html),
under the FAPI-CIBA profile. Each request carries [Rich Authorization
Requests (RFC 9396)](https://www.rfc-editor.org/rfc/rfc9396) describing
exactly what's being approved. The phone shows that, and the bank's APIs
then allow exactly what Sam approved.

Everything runs in one process, on your machine, each party at its own
`*.localhost` host.

> This is a demo. Every store is in memory, every key is generated at
> startup, and the bank, businesses, people and account numbers are made
> up.

This is a separate Go module. It builds against this checkout of the
library (`replace` in `go.mod`), and release-please ignores it.

## Running it

```sh
cd examples/decoupled-checkout
go run ./cmd/decoupled-checkout -open
```

`-open` starts Chrome (or Chromium; `-chrome` gives its path) on
**https://console.localhost:8644/**, in a separate profile under
`.checkout-state/chrome-profile` that accepts the demo's certificate —
only that one, identified by its key — without a warning. Use that
window for the whole demo, and only for it: Chrome accepts that key for
*any* host in this profile, and the key sits in `.checkout-state/`.
Chrome shows a banner about an unsupported command-line flag; that's
expected. Ctrl-C stops the demo.

It uses port 8644, so it can run alongside the
[federated-union demo](../federated-union/README.md) (8643). `-port`
changes it.

### Other browsers

Every page is served over HTTPS with one certificate from the demo's own
CA. The CA can only vouch for `*.localhost` (an X.509 name constraint),
never a real site or an IP address, and it's kept in `.checkout-state/`,
so this is once, not every run. The startup banner prints the command
for your system:

| | Trust | Remove |
|---|---|---|
| macOS (Chrome, Safari) | `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db .checkout-state/ca.pem` | `security delete-certificate -c "Decoupled checkout demo CA"` |
| Linux (Chrome) | `certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n "Decoupled checkout demo CA" -i .checkout-state/ca.pem` | `certutil -d sql:$HOME/.pki/nssdb -D -n "Decoupled checkout demo CA"` |
| Windows | `certutil -user -addstore Root .checkout-state\ca.pem` | `certutil -user -delstore Root "Decoupled checkout demo CA"` |
| Firefox | Settings → Privacy & Security → View Certificates → Authorities → Import | Same list → Delete |

`-reset` deletes `.checkout-state/` and issues a new CA; remove the old
one from your trust store if you'd trusted it. `-state` moves the
directory.

## Who's who

| Host | Party |
|---|---|
| `console.localhost` | The console: the till, Sam's phone and Pocketwise side by side, a guided tour, and the traffic between the parties |
| `bank.localhost` | Alder Bank's authorization server: the CIBA and token endpoints |
| `phone.localhost` | Alder Bank's app on Sam's phone, where requests are approved |
| `api.bank.localhost` | Alder Bank's payments and accounts APIs |
| `till.localhost` | Harbour Coffee's till: a CIBA client that polls |
| `pocketwise.localhost` | Pocketwise: a CIBA client the bank pings |

The customer is **sam**, with an Everyday and a Savings account.

## What to try

The console's **Start here** panel walks through all of this in order.

**1. Pay at the till.** Press **Pay with Alder Bank**. The till sends
Alder Bank a signed backchannel authentication request naming Sam by
login hint, with the payment as a `payment_initiation` detail, then
polls. Open the request on Sam's phone. The bank shows the amount, the
payee — its own record of the name behind the account, not the name the
merchant sent — and the account it comes from. Merchant-written text
(the reference, and CIBA's binding message) is shown apart, marked as
unchecked. Approve it, and the till charges the payment with a
DPoP-bound access token.

**2. Misuse the approval.** On the approved order, each attack button is
refused:

| Attack | What stops it |
|---|---|
| Charge €420 instead | The payments API executes only a payment matching the approved `authorization_details` |
| Charge again | The approval is for one payment; the API won't execute it twice |
| Use the token from another device | The token is DPoP-bound to the till's key; another device can't prove possession of it |
| Reuse the `auth_req_id` | The bank issues tokens for a request once |

**3. A misleading message.** Start an order with the attack button: the
till asks for €500 while its binding message calls it a refund. The
phone puts the bank's own description first — €500 from Sam's account
— and the message below it, unchecked. Deny it; the till is told.

**4. Share less with a budgeting app.** In Pocketwise, press **Link
Alder Bank**. It asks, with an `account_information` detail, to read
both accounts' balances, transactions and standing orders. On the
phone, untick the Savings account and standing orders, and approve.
Pocketwise doesn't poll: once Sam decides, the bank pings Pocketwise's
notification endpoint with the token Pocketwise sent in its request,
and only then does Pocketwise collect its tokens. It then tries every
read: only the ones Sam kept succeed.

**5. Ask for more than you're allowed.** Pocketwise's attack button asks
for a payment too. Alder Bank lets Pocketwise ask only to read
accounts, so the request is refused (`invalid_authorization_details`)
before it reaches Sam's phone.

## How it's built

Everything here uses FAPIgo's public API only.

| Piece | FAPIgo |
|---|---|
| Alder Bank | `server.Server` with `Endpoints.BackchannelAuthentication`, `Config.RAR` (an `extension.RARRegistry` of both detail types), `Dependencies.CIBARARPolicy` limiting which types each client may request, and `Dependencies.BackchannelHints` refusing a login hint that names no customer with `unknown_user_id` |
| Sam's phone | `server.BackchannelInteractionRequest` — `AuthorizationDetails`, `BindingMessage`, `ClientDisplay` — and `CompleteBackchannelAuthentication` with `GrantedAuthorization.AuthorizationDetails` |
| Narrowing | `RARDefinition.ValidateGrant`: an account-access grant may drop accounts and actions, never add them; a payment is granted exactly as asked |
| The APIs | `serverresource.NewVerifier`, built from the bank's own server configuration; the granted details from the access token's `authorization_details` claim, and `resource.ErrorInsufficientScope` for a request they don't cover |
| The till and Pocketwise | `client.Discover`, `client.NewFromDiscovery`, `BeginBackchannelAuthentication` with `AuthorizationDetails`, `PollBackchannelAuthentication`, `ProtectedResource` for DPoP-bound API calls |
| Ping delivery | `Config.BackchannelTokenDeliveryMode` ping on Pocketwise, whose endpoint reads the callback with `client.ParseBackchannelNotification` and checks it with `Authenticates`; the bank sends with `server.NewBackchannelNotificationRequest` |

The code:

- [`checkout/world.go`](checkout/world.go) — the parties, Sam and the accounts.
- [`checkout/rar.go`](checkout/rar.go) — the two detail types and who may request which.
- [`checkout/bank.go`](checkout/bank.go) — Alder Bank's authorization server.
- [`checkout/phone.go`](checkout/phone.go) — the approval screens.
- [`checkout/api.go`](checkout/api.go) — the payments and accounts APIs.
- [`checkout/till.go`](checkout/till.go), [`checkout/pocketwise.go`](checkout/pocketwise.go) — the two clients.
- [`checkout/e2e_test.go`](checkout/e2e_test.go) — every step above, driven end to end.

## What's simplified

- Sam is already signed in to the phone app; a real app would ask for a
  biometric or PIN before approving.
- The bank sends ping notifications through the demo's own network. A
  real deployment uses `backchannelhttp.New`, whose hardened client
  refuses loopback and private addresses — exactly what every host here
  is.
- One process plays every party, so the stores the bank and its APIs
  share are simply the same objects. Separate services would share a
  database instead.
