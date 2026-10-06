# Federated union demo

Three fictional countries — **Northland**, **Southport** and
**Eastmark** — each run their own identity federation, then join the
**Meridian Union**, an [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)
trust anchor above them. A service in one country can then accept a
citizen of another: neither registers with the other beforehand, and the
Union's rules apply on top of each country's own.

Everything runs in one process, on your machine, each entity at its own
`*.localhost` host.

> This is a demo. Every store is in memory, every key is generated at
> startup, and the countries, schemes and people are made up.

This is a separate Go module. It builds against this checkout of the
library (`replace` in `go.mod`), and release-please ignores it.

## Running it

```sh
cd examples/federated-union
go run ./cmd/federated-union -open
```

`-open` starts Chrome (or Chromium; `-chrome` gives its path) on
**https://console.localhost:8643/**, in a separate profile under
`.union-state/chrome-profile` that accepts the demo's certificate — only
that one, identified by its key — without a warning. Use that window for
the whole demo, and only for it: Chrome accepts that key for *any* host
in this profile, and the key sits in `.union-state/`. Chrome shows a
banner about an unsupported command-line flag; that's expected. Ctrl-C
stops the demo.

### Other browsers

Every page is served over HTTPS with one certificate from the demo's own
CA. The CA can only vouch for `*.localhost` (an X.509 name constraint),
never a real site or an IP address, and it's kept in `.union-state/`, so
this is once, not every run. The startup banner prints the command for
your system:

| | Trust | Remove |
|---|---|---|
| macOS (Chrome, Safari) | `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db .union-state/ca.pem` | `security delete-certificate -c "Meridian Union demo CA"` |
| Linux (Chrome) | `certutil -d sql:$HOME/.pki/nssdb -A -t C,, -n "Meridian Union demo CA" -i .union-state/ca.pem` | `certutil -d sql:$HOME/.pki/nssdb -D -n "Meridian Union demo CA"` |
| Windows | `certutil -user -addstore Root .union-state\ca.pem` | `certutil -user -delstore Root "Meridian Union demo CA"` |
| Firefox | Settings → Privacy & Security → View Certificates → Authorities → Import | Same list → Delete |

Or accept the warning on each host the first time you reach it. The
certificate is reused across runs, but a sign-in visits several hosts.
`*.localhost` names resolve to your own machine in Chrome and Firefox
with no setup.

`-reset` deletes `.union-state/` and issues a new CA; remove the old one
from your trust store if you'd trusted it. `-state` moves the directory,
and `-port` changes the port.

Everything else (keys, registrations, sign-ins) is in memory and starts
fresh each run.

## Who's who

```
                      Meridian Union (trust anchor)
          ┌─────────────────────┼─────────────────────┐
  Northland authority    Southport authority    Eastmark authority      national authorities
     │         │            │         │            │         │
  NorthID  Accreditation  SouthID  Accreditation  EastID  Accreditation    identity providers
           Office                  Office                 Office           + accreditation bodies
                         Southport              Eastmark
                         Savings Bank           Telecom                    services
```

| Host | Entity |
|---|---|
| `console.localhost` | The Union's console: members, scenes, Trust Chain inspector, federation traffic |
| `union.localhost` | Meridian Union — the trust anchor |
| `ta.<country>.localhost` | Each country's federation authority |
| `accreditation.<country>.localhost` | Each country's accreditation office, which issues level-of-assurance Trust Marks |
| `id.<country>.localhost` | Each country's identity provider: NorthID, SouthID, EastID |
| `bank.southport.localhost` | Southport Savings Bank |
| `telco.eastmark.localhost` | Eastmark Telecom |
| `bank.northland.localhost` | An impostor, used by one scene |

Services trust the Union and their own country's authority. Identity
providers do too, and register services they've never seen automatically
(OpenID Federation 1.0 §12.1).

## What to try

The console's **Start here** panel walks through all of this in order,
with a button for each scene. While any scene is on, every page says so
and offers to turn them all off.

**1. Cross-border sign-in with no onboarding.** Open Southport Savings
Bank and sign in with **EastID**. The bank finds EastID by resolving its
Trust Chain (EastID → Eastmark authority → Meridian Union); EastID
registers the bank the same way when its request arrives. Neither was
told about the other.

**2. Union rules on top of national rules.** In the console, open the
bank's **trust chain**. The bank declares three grant types; the Union's
metadata policy allows two, and Southport's adds that services must
publish a contact. Compare "as the entity declares it" with "after every
superior's policy".

**3. Recognised assurance.** Each identity provider carries a
level-of-assurance Trust Mark from its country's accreditation office.
The Union lists exactly those offices as accredited issuers, and
services only accept providers whose mark checks out.

**4. Data minimisation.** The bank asks for name, date of birth,
nationality and address. On EastID's consent page, untick the address:
only what's ticked leaves EastID, and the bank's page shows the address
as not shared.

Then the console's scenes:

| Scene | What happens | What stops it |
|---|---|---|
| **EastID forges its assurance mark** | EastID publishes a level-of-assurance mark it signed itself | The signature verifies — EastID is a federation member — but the Union doesn't accredit EastID to issue that mark, so services refuse EastID |
| **Suspend Eastmark** | The Union stops vouching for Eastmark's authority | Cross-border sign-ins with EastID fail; Eastmark Telecom, which also trusts Eastmark's authority directly, keeps working |
| **Eastmark's authority is compromised** | Eastmark's authority vouches for an impostor claiming a Northland host | The Union's naming constraints confine Eastmark to `*.eastmark.localhost`: the impostor resolves through Eastmark alone, but not through the Union. That protects only parties relying on the Union: EastID, which trusts Eastmark's authority directly, would still accept the impostor |

Identity providers cache a service's registration for 10 seconds, and
remember a registration that failed for 10 seconds too (FAPIgo's
default, so repeated requests can't each trigger a fresh resolution),
so a scene can take that long to affect a sign-in, or to stop
affecting one once it's turned off.
Everything else here resolves Trust Chains afresh, which is why
suspension is near-instant. In a real federation, a Subordinate
Statement stays valid until it expires (24 hours in this demo), so a
party that cached it keeps trusting a suspended authority until then.

The console's **Recent federation traffic** shows every request one
entity made to another: each Entity Configuration, Subordinate Statement
and key set fetched to build a Trust Chain.

## How it's built

Everything here uses FAPIgo's public API only.

| Piece | FAPIgo |
|---|---|
| Union and national authorities | `federation.SelfIssuer` (with `TrustMarkIssuers`), `federation.SubordinateIssuer` with `MetadataPolicy` and `Constraints` |
| Accreditation offices | `federation.TrustMarkIssuer` |
| Identity providers | `server.Server` with `Config.AutomaticRegistration` and `Config.Federation`; `Server.EntityConfiguration` publishing the Trust Mark; `GrantedAuthorization.ApprovedIdentityClaims` from the consent page; the pending sign-in kept in an encrypted cookie (`server/interactioncookie`) rather than in the process, as a provider running several instances would |
| Services | `client.DiscoverViaFederation`, `client.NewFromDiscovery`, `BeginAuthorizationRequest.Claims`, `Resolver.VerifyTrustMark` with `RequireFederationAccreditation` |
| Sign-in | PAR with a signed request object, PKCE, DPoP-bound tokens, and the session cookie binding (`client/sessioncookie`, carrying the identity provider too) |

The code:

- [`union/world.go`](union/world.go) — the countries, the Union and its policy, the scenes.
- [`union/idp.go`](union/idp.go) — the identity providers, whose pending sign-ins travel in an `interactioncookie.Cookie`.
- [`union/rp.go`](union/rp.go) — the services.
- [`union/console.go`](union/console.go) — the console.
- [`../internal/demokit`](../internal/demokit/net.go) — one listener serving every host, the certificate, and the Chrome window; shared with the other example demos.
- [`union/e2e_test.go`](union/e2e_test.go) — every scene, driven end to end.

## Not shown

- Explicit registration (§12.2) — FAPIgo implements automatic registration only.
- Key rollover through the Federation Historical Keys endpoint.
- Trust Mark status queries.
