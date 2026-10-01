# Payroll run demo

**Ledgerline**, a payroll provider, pays **Harbour Coffee**'s staff from
Harbour Coffee's account at **Alder Bank**. It's machine to machine: no
one signs in, and no browser is part of the flow.

- Ledgerline authenticates to the bank with a TLS client certificate
  the bank's client CA issued (mutual TLS, [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)
  §2, `tls_client_auth`). The bank checks that the certificate chains
  through that CA to its root CA, that neither the certificate nor the
  CA has been revoked, and that its subject is the one registered for
  Ledgerline.
- It gets an access token through the client credentials grant, bound
  to that certificate (RFC 8705 §3, `cnf.x5t#S256`).
- The token grants one payroll batch, as a [Rich Authorization Request
  (RFC 9396)](https://www.rfc-editor.org/rfc/rfc9396). With no end user
  to approve it, the bank checks it against Harbour Coffee's standing
  mandate.

An **attack lab** tries to get around each of those, and a **rotation
panel** replaces Ledgerline's certificate. Every run shows a protocol
trace: the certificate presented, and the access token decoded.

Everything runs in one process, on your machine, each party at its own
`*.localhost` host.

> This is a demo. Every store is in memory, every key and client
> certificate is generated at startup, and the bank, companies, people
> and account numbers are made up.

This is a separate Go module. It builds against this checkout of the
library (`replace` in `go.mod`), and release-please ignores it.

## Running it

```sh
cd examples/payroll-run
go run ./cmd/payroll-run -open
```

`-open` starts Chrome (or Chromium; `-chrome` gives its path) on
**https://console.localhost:8646/**, in a separate profile under
`.payroll-state/chrome-profile` that accepts the demo's certificate —
only that one, identified by its key — without a warning. Use that
window for the whole demo, and only for it: Chrome accepts that key for
*any* host in this profile, and the key sits in `.payroll-state/`.
Chrome shows a banner about an unsupported command-line flag; that's
expected. Ctrl-C stops the demo.

It uses port 8646, so it can run alongside the
[federated-union](../federated-union/README.md) (8643),
[decoupled-checkout](../decoupled-checkout/README.md) (8644) and
[payment-consent](../payment-consent/README.md) (8645) demos. `-port`
changes it.

### Other browsers

Every page is served over HTTPS with one certificate from the demo's own
CA. The CA can only vouch for `*.localhost` (an X.509 name constraint),
never a real site or an IP address, and it's kept in `.payroll-state/`,
so this is once, not every run. The startup banner prints the command for
your system:

| | Trust | Remove |
|---|---|---|
| macOS (Chrome, Safari) | `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db .payroll-state/ca.pem` | `security delete-certificate -c "Payroll run demo CA"` |
| Linux (Chrome) | `certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n "Payroll run demo CA" -i .payroll-state/ca.pem` | `certutil -d sql:$HOME/.pki/nssdb -D -n "Payroll run demo CA"` |
| Windows | `certutil -user -addstore Root .payroll-state\ca.pem` | `certutil -user -delstore Root "Payroll run demo CA"` |
| Firefox | Settings → Privacy & Security → View Certificates → Authorities → Import | Same list → Delete |

`-reset` deletes `.payroll-state/` and issues a new CA; remove the old
one from your trust store if you'd trusted it. `-state` moves the
directory.

The client certificates are a different matter: Alder Bank's own PKI
issues them, in memory, every run. Your browser never sees them — the
two hosts that ask for one are only ever called by Ledgerline.

## Who's who

| Host | Party |
|---|---|
| `console.localhost` | The console: a guided tour and the traffic between the parties |
| `ledgerline.localhost` | Ledgerline's dashboard, the attack lab and the rotation panel |
| `bank.localhost` | Alder Bank's authorization server: metadata, keys, and a token endpoint that never asks for a certificate |
| `mtls.bank.localhost` | The token endpoint's mTLS alias (`mtls_endpoint_aliases`): it asks for a client certificate |
| `api.bank.localhost` | Alder Bank's payroll API: it asks for a client certificate too |

Copperfield Payroll, a second payroll provider with a valid certificate
of its own, is registered at the bank but has no pages: the attack lab
borrows its certificate.

### Alder Bank's PKI

| CA | Signed by | Issues |
|---|---|---|
| Alder Bank root CA | itself | issuing CAs, and revokes them |
| Alder Bank client CA 2 | the root | client certificates today: Ledgerline's and Copperfield's |
| Alder Bank client CA 1 | the root | client certificates until its key leaked; the root has revoked it |

The bank trusts the root in `TrustedClientCAs.Roots` and lists both
issuing CAs in `Intermediates`. That split matters: a CA in `Roots` is a
trust anchor, and nothing checks a trust anchor for revocation, so an
issuing CA put there would stay trusted after the root revoked it.
`ClientCertificateCRLs` gets a CRL from every CA in the chain: the root's
revokes issuing CAs, and each issuing CA's revokes client certificates.

## What to try

The console's **Start here** panel walks through all of this in order.

**1. Run payroll.** Press **Run payroll**. Ledgerline asks the bank's mTLS
token endpoint for a token, presenting its certificate, with the batch
as `authorization_details`: €22,840.00 from Harbour Coffee's account to
12 staff. The token comes back bound to the certificate's thumbprint and
granting exactly that batch, and the API pays it. The run page's
**protocol trace** shows the certificate presented on each connection
and the access token decoded.

**2. Steal the token.** On the paid run, each attack is refused:

| Attack | What stops it |
|---|---|
| Use the token without Ledgerline's certificate | The token is bound to a certificate, and the connection presents none |
| Use the token with Copperfield's certificate | A valid certificate, but not the one the token's `cnf.x5t#S256` names |
| Add €5,000.00 to the batch | The API pays only within the granted `authorization_details` |
| Pay the batch again | The token was for one batch |

**3. Get a token without Ledgerline's key.** On Ledgerline's page, each
attack at the token endpoint is refused with `invalid_client`:

| Attack | What stops it |
|---|---|
| Ask for a token without a certificate | `tls_client_auth` needs one |
| Present a self-signed certificate naming Ledgerline | Anyone can make one: it doesn't chain to the bank's root CA |
| Present a certificate naming Ledgerline from another CA | That CA calls itself "Alder Bank client CA 2", but the bank trusts its own CAs' keys, not their names |
| Present Ledgerline's expired certificate | Validity is checked at the server's clock |
| Present Ledgerline's leaked, revoked certificate | A real certificate from the bank's client CA, but its key leaked and the CA revoked it: it's on the CA's revocation list (`server.ClientCertificateCRLs`) |
| Present a certificate from Alder Bank's retired, revoked client CA | The bank's previous issuing CA leaked its key, and the attacker mints a fresh certificate naming Ledgerline with it. The certificate itself was never revoked, and it chains to the root — but the root has revoked the CA that issued it, and that CA is checked too because it's in `Intermediates`, not `Roots` |
| Claim to be Ledgerline with Copperfield's certificate | A valid certificate from the bank's client CA, but its subject isn't the one registered for Ledgerline |

**4. Exceed the mandate.** Two more token requests, with Ledgerline's
real certificate, are refused with `invalid_authorization_details`:

| Attack | What stops it |
|---|---|
| Pay from Brightwater Bakery's account | Harbour Coffee's mandate covers only its own account |
| Pay a €40,000.00 batch | The mandate allows up to €25,000.00 per batch |

**5. Rotate the certificate.** The bank's CA issues Ledgerline a new
certificate with the same subject. Ledgerline's registration names the
subject, not a certificate, so it doesn't change: new tokens are issued
straight away. But a token issued before the rotation is bound to the old
certificate, so it's refused with the new one — tokens follow the
certificate, not the client. Rotate shortly before the old certificate
expires, and let old tokens run out.

## How it's built

Everything here uses FAPIgo's public API only.

| Piece | FAPIgo |
|---|---|
| Alder Bank | `server.Server` with `ClientCredentialsGrant`, `OAuthOnly`, `MTLSEndpoints`, `Config.RAR` and `Dependencies.ClientCredentialsRARPolicy`; clients registered with `ClientAuthMethodTLSClientAuth` and `SenderConstrainMTLS`; `Dependencies.ClientCertificateTrust` set to `TrustedClientCAs` — the root CA in `Roots`, the issuing CAs in `Intermediates` — with `ClientCertificateCRLs` |
| The payroll API | `serverresource.NewVerifier`, built from the bank's own server configuration, with `VerifyRequest.PeerCertificate`; the granted batch from the access token's `authorization_details` claim |
| Ledgerline | `client.Discover`, `MTLSEndpointAliases.ApplyForClientAuth`, `client.NewFromDiscovery` with `ClientAuthMethodTLSClientAuth`, `SenderConstrainMTLS` and `OAuthOnly`; `RequestClientCredentialsToken` with `AuthorizationDetails`; `ClientCredentialsResource` for the API call. The certificate lives in the HTTP client's TLS configuration: FAPIgo never sees its key, and with nothing else to sign, Ledgerline has no `Dependencies.Keys` at all |

The code:

- [`payroll/bank.go`](payroll/bank.go) — Alder Bank's authorization server.
- [`payroll/pki.go`](payroll/pki.go) — Alder Bank's root and issuing CAs and their revocation lists, and every certificate the demo uses.
- [`payroll/rar.go`](payroll/rar.go) — the `payroll_batch` detail type and the mandate policy.
- [`payroll/api.go`](payroll/api.go) — the payroll API.
- [`payroll/ledgerline.go`](payroll/ledgerline.go) — Ledgerline, the attack lab and the rotation panel.
- [`payroll/trace.go`](payroll/trace.go) — the protocol trace.
- [`payroll/e2e_test.go`](payroll/e2e_test.go) — the run, every attack and the rotation, driven end to end.

## What's simplified

- The bank's CAs run in the same process, so the authorization server
  reads their revocation lists directly. A real deployment fetches
  and caches the CA's published CRL, refreshing it before its
  `nextUpdate` — `ClientCertificateCRLs` refuses a certificate whose
  issuer has no current list.
- Revocation is checked when a client authenticates. A token already
  issued to a certificate that's revoked later keeps working at the API
  until it expires, so keep access tokens short-lived.
- One process plays every party, so the bank and its API share their
  stores directly. Separate services would share a database instead.
