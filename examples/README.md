# FAPIgo examples

Six runnable demos, each a small but complete deployment of FAPIgo:
banks, apps, identity providers and APIs, each at its own `*.localhost`
host in one process on your machine. Each one tells a story from open
banking or digital identity, and each has an attack lab that tries to
break what it shows.

| Demo | The story | Port |
|---|---|---|
| [federated-union](federated-union/README.md) | Three countries' identity federations joined into one OpenID Federation: a bank in one country signs in a citizen of another, with neither registered with the other beforehand | 8643 |
| [decoupled-checkout](decoupled-checkout/README.md) | A customer approves, on their phone, a payment or account access started on a shop's till or another app | 8644 |
| [payment-consent](payment-consent/README.md) | A web shop takes payment by bank through the FAPI 2.0 Message Signing redirect flow | 8645 |
| [payroll-run](payroll-run/README.md) | A payroll provider pays a company's staff through its bank's API, machine to machine, with mutual TLS | 8646 |
| [identity-check](identity-check/README.md) | A fintech verifies a new customer's identity by having them sign in at their bank, acting as an OpenID Provider | 8647 |
| [linked-accounts](linked-accounts/README.md) | A budgeting app links a customer's accounts for 90 days and syncs them on its own, until the customer revokes it | 8648 |

## What each demo shows

| Capability | Spec | federated-union | decoupled-checkout | payment-consent | payroll-run | identity-check | linked-accounts |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Pushed authorization requests and the authorization code flow | [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126) | ● | | ● | | ● | ● |
| Signed request objects and JARM (FAPI 2.0 Message Signing) | [FAPI 2.0 Message Signing](https://openid.net/specs/fapi-2_0-message-signing.html) | | | ● | | | |
| DPoP-bound access tokens | [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) | ● | ● | ● | | ● | ● |
| `private_key_jwt` client authentication | [OIDC Core §9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) | | ● | ● | | ● | ● |
| mTLS client authentication and certificate-bound tokens | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) | | | | ● | | |
| Client certificate revocation (CRLs, intermediate CAs) | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | | | | ● | | |
| Rich Authorization Requests | [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) | | ● | ● | ● | | ● |
| CIBA, poll and ping delivery | [FAPI-CIBA](https://openid.net/specs/openid-financial-api-ciba-ID1.html) | | ● | | | | |
| Client credentials grant | [RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4) | | | | ● | | |
| The OIDC `claims` parameter, with per-claim consent | [OIDC Core §5.5](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter) | ● | | | | ● | |
| `acr_values` and `max_age` (step-up authentication) | [OIDC Core §3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) | | | | | ● | |
| Signed and encrypted ID tokens and UserInfo | [OIDC Core §5.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) | | | | | ● | |
| Refresh tokens kept sealed between syncs, and DPoP key rotation | [RFC 6749 §6](https://www.rfc-editor.org/rfc/rfc6749#section-6) | | | | | | ● |
| Revoking a whole grant ("connected apps") | — | | | | | | ● |
| OpenID Federation: trust chains, metadata policy, automatic registration, Trust Marks | [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html) | ● | | | | | |
| A resource server verifying sender-constrained tokens | [RFC 9449 §7](https://www.rfc-editor.org/rfc/rfc9449#section-7), [RFC 8705 §3](https://www.rfc-editor.org/rfc/rfc8705#section-3) | | ● | ● | ● | ● | ● |

Each demo's README has a **What to try** walk-through, and a **How it's
built** table naming the FAPIgo API behind each piece.

## What every demo has

- **A console** at `https://console.localhost:<port>/`, with a guided
  tour ("Start here") and a log of the traffic between the parties.
- **An attack lab** (federated-union calls them attack scenes) that
  misuses what the demo shows — a stolen token, a swapped ID token, a
  tampered request, a revoked certificate — and shows each one refused,
  with the reason.
- **A protocol trace** of each request and response, with the JWTs
  decoded (payment-consent, payroll-run, identity-check, linked-accounts).
- **Errors shown at the right level.** What the bank, identity provider
  and APIs send back carries only a FAPIgo error's public description,
  or a fixed message, with the full error logged: `Error()` includes the
  internal cause, which is for logs. The attack lab, protocol trace,
  logs and the apps' own failure pages show full errors on purpose,
  since explaining a refusal is what they're for.
- **Only FAPIgo's public API.** CI checks that no demo imports
  `internal/`, so nothing a demo does is out of reach of your own code.
- **Tests** that drive the whole demo end to end, attacks included.

Every store is in memory and every key is generated at startup: these
are demos, never a template for production storage. The banks, apps,
countries and people are made up.

## Running one

Each demo is its own Go module that builds against this checkout of the
library:

```sh
cd examples/payment-consent
go run ./cmd/payment-consent -open
```

`-open` starts Chrome (or Chromium) in a separate profile that trusts
the demo's local certificate, without a warning, and opens the console.
Each demo's README covers other browsers.

## Ports

Every demo has its own port, so they can all run at once. None uses
8443, which a locally running OpenID Foundation conformance suite
uses. `-port` changes it.

| Port | Demo |
|---|---|
| 8643 | federated-union |
| 8644 | decoupled-checkout |
| 8645 | payment-consent |
| 8646 | payroll-run |
| 8647 | identity-check |
| 8648 | linked-accounts |

`internal/demokit` is the demos' shared scaffolding: the local
certificate authority, the `*.localhost` host routing, and the browser
launch. It's for the demos only, not part of FAPIgo's API.
