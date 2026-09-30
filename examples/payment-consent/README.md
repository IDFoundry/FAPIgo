# Payment consent demo

**Northgate Outfitters**, a web shop, takes payment by bank from an
**Alder Bank** customer through the [FAPI 2.0](https://openid.net/specs/fapi-security-profile-2_0-final.html)
Message Signing redirect flow:

- a signed request object, pushed to the bank (PAR, RFC 9126);
- a consent screen describing the payment from its Rich Authorization
  Request (RFC 9396);
- a signed authorization response (JARM);
- a DPoP-bound access token (RFC 9449).

An **attack lab** tries to break each of those, and every order page
shows a protocol trace of what was signed, bound and checked.

Everything runs in one process, on your machine, each party at its own
`*.localhost` host.

> This is a demo. Every store is in memory, every key is generated at
> startup, and the bank, shop, people and account numbers are made up.

This is a separate Go module. It builds against this checkout of the
library (`replace` in `go.mod`), and release-please ignores it.

## Running it

```sh
cd examples/payment-consent
go run ./cmd/payment-consent -open
```

`-open` starts Chrome (or Chromium; `-chrome` gives its path) on
**https://console.localhost:8645/**, in a separate profile under
`.payment-state/chrome-profile` that accepts the demo's certificate —
only that one, identified by its key — without a warning. Use that
window for the whole demo, and only for it: Chrome accepts that key for
*any* host in this profile, and the key sits in `.payment-state/`.
Chrome shows a banner about an unsupported command-line flag; that's
expected. Ctrl-C stops the demo.

It uses port 8645, so it can run alongside the
[federated-union](../federated-union/README.md) (8643) and
[decoupled-checkout](../decoupled-checkout/README.md) (8644) demos.
`-port` changes it.

### Other browsers

Every page is served over HTTPS with one certificate from the demo's own
CA. The CA can only vouch for `*.localhost` (an X.509 name constraint),
never a real site or an IP address, and it's kept in `.payment-state/`,
so this is once, not every run. The startup banner prints the command for
your system:

| | Trust | Remove |
|---|---|---|
| macOS (Chrome, Safari) | `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db .payment-state/ca.pem` | `security delete-certificate -c "Payment consent demo CA"` |
| Linux (Chrome) | `certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n "Payment consent demo CA" -i .payment-state/ca.pem` | `certutil -d sql:$HOME/.pki/nssdb -D -n "Payment consent demo CA"` |
| Windows | `certutil -user -addstore Root .payment-state\ca.pem` | `certutil -user -delstore Root "Payment consent demo CA"` |
| Firefox | Settings → Privacy & Security → View Certificates → Authorities → Import | Same list → Delete |

`-reset` deletes `.payment-state/` and issues a new CA; remove the old
one from your trust store if you'd trusted it. `-state` moves the
directory.

## Who's who

| Host | Party |
|---|---|
| `console.localhost` | The console: a guided tour and the traffic between the parties |
| `shop.localhost` | Northgate Outfitters, and the attack lab |
| `bank.localhost` | Alder Bank's authorization server, with its sign-in and consent pages |
| `api.bank.localhost` | Alder Bank's payments API |

Sign in at the bank as **sam**, PIN **2468**.

## What to try

The console's **Start here** panel walks through all of this in order.

**1. Pay by bank.** Press **Pay by bank**. The shop pushes a signed
request object to the bank's PAR endpoint: the `payment_initiation`
details, a PKCE challenge, the redirect URI and the state, all under the
shop's signature, with a DPoP proof. Your browser only ever carries the
resulting `request_uri`. At the bank, sign in and approve. The consent
screen describes the payment from the request's authorization details,
with the payee's name from the bank's own records. The shop's own text
(the reference) is marked as unchecked. The bank answers with a signed
JARM response, and the shop redeems the code for a DPoP-bound token and
charges exactly the approved payment. The order page's **protocol trace**
shows each request and response, with the signed parts decoded.

**2. Misuse the approval.** On the paid order, each attack button is
refused:

| Attack | What stops it |
|---|---|
| Charge €1,290.00 | The payments API executes only a payment matching the approved `authorization_details` |
| Charge again | The approval is for one payment; the API won't execute it twice |
| Use the token from another device | The token is DPoP-bound to the shop's key; another device can't prove possession of it |
| Redeem the code again | The bank refuses a code redeemed twice, and revokes the token the first redemption issued — the API refuses that token from then on |
| Replay the response | The checkout session it answered is already used |
| Forge the response | It isn't signed by Alder Bank |

**3. Attack before paying.** From the shop's front page:

| Attack | What stops it |
|---|---|
| Change the amount in the signed request, on its way to the bank | The request object's signature no longer matches: PAR refuses it (`invalid_request_object`) |
| Send the result to another redirect URI | The redirect URI is inside the signed request, and the bank accepts only the one registered for the shop |
| Skip PAR | The authorization endpoint accepts only a `request_uri` the bank issued for a request it already verified |
| Inject an attacker's authorization response | An attacker (Alex, another customer) approves a payment of their own on their own device and stops before returning to the shop. Opened in your browser, which has its own checkout in progress, their valid response is refused: the shop accepts a response only alongside the session cookie of the checkout it answers |

## How it's built

Everything here uses FAPIgo's public API only.

| Piece | FAPIgo |
|---|---|
| Alder Bank | `server.Server` with `ProfileFAPISecurityWithMessageSigning`, `Config.RAR` and `Dependencies.AuthorizationCodeRARPolicy`; the consent page's state in a signed cookie with `InteractionRequest.MarshalText` / `server.ParseInteractionRequest` |
| The payments API | `serverresource.NewVerifier`, built from the bank's own server configuration; the granted details from the access token's `authorization_details` claim; `resource.ErrorInsufficientScope` for anything else |
| Northgate Outfitters | `client.Discover`, `client.NewFromDiscovery` with `ProfileFAPISecurityWithMessageSigning`; `BeginAuthorization` with `AuthorizationDetails`; `HandleAuthorizationResponse` and `ExchangeCode`; `ProtectedResource` for the DPoP-bound API call |

The code:

- [`payment/bank.go`](payment/bank.go) — Alder Bank's authorization server and consent page.
- [`payment/shop.go`](payment/shop.go) — the shop and the attack lab.
- [`payment/api.go`](payment/api.go) — the payments API.
- [`payment/trace.go`](payment/trace.go) — the protocol trace, and the in-flight tampering attack.
- [`payment/e2e_test.go`](payment/e2e_test.go) — the payment and every attack, driven end to end.

## What's simplified

- The customer signs in with a username and a PIN; a real bank would use
  its own strong authentication.
- One process plays every party, so the bank and its API share their
  stores directly. Separate services would share a database instead.
