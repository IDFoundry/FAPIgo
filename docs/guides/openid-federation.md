# OpenID Federation in Go

[OpenID Federation 1.0] lets parties that have never met trust each other
through a shared authority. Each entity publishes a signed Entity
Configuration about itself; superiors (Intermediates, and at the top a
Trust Anchor) publish signed Subordinate Statements about the entities
they vouch for, with metadata policy those entities must follow. To
trust a peer, you walk its Trust Chain up to a Trust Anchor you already
trust and apply every policy on the way.

The payoff for OAuth is that a client needs no registration step: with
automatic registration (§12.1), it presents its own Entity Identifier as
its `client_id`, and the authorization server resolves its chain and
takes its registration from the resolved metadata.

## Authorization server: publish, and accept federated clients

```go
cfg := server.Config{
	// Issuer, Endpoints, Profile, Algorithms, Limits ...
	Federation: server.FederationConfig{
		EntityID:       "https://id.example.com",
		AuthorityHints: []string{"https://federation.example.org"},
		Lifetime:       24 * time.Hour,
		Algorithm:      fapi.ES256, // a keys.FederationEntitySigning key in Dependencies.Keys
	},
	AutomaticRegistration: server.AutomaticRegistrationConfig{
		TrustAnchors:         []federation.TrustAnchor{anchor},
		AllowedScopes:        []string{"openid"},
		MaxPathLength:        4,
		MaxAuthorityHints:    5,
		MaxStatementLifetime: 48 * time.Hour,
		MaxClockSkew:         30 * time.Second,
		MaxCacheAge:          10 * time.Minute,
	},
}
```

Serve your Entity Configuration at `federation.WellKnownPath`. You build
the metadata, typically your server's own `Metadata` as
`openid_provider`, plus `federation_entity`, and the server signs it:

```go
token, err := srv.EntityConfiguration(ctx, map[string]json.RawMessage{
	"openid_provider":   providerMetadata,
	"federation_entity": entityMetadata,
})
// ...
federation.WriteEntityStatement(w, token)
```

With `AutomaticRegistration.TrustAnchors` set, an unknown `client_id`
that is an `https` Entity Identifier is resolved through its Trust Chain,
and its `openid_relying_party` metadata becomes its registration.
Outbound fetches go through `Dependencies.FederationHTTP`, which `New`
requires once trust anchors are set. Statically registered clients
always take priority. What a client may do
beyond the authorization code flow is your grant, never its own metadata's:
`AllowedScopes`, `AuthorizationDetailsTypes`, `AllowsClientCredentialsGrant`,
`AllowsCIBA` and `AllowedClientAuthMethods`. A resolved registration is cached for at most
`MaxCacheAge`, so a superior that stops vouching for a client takes
effect within that time. A failed one is remembered for `FailureCacheAge`
(10 seconds by default), so requests repeating a client_id that doesn't
resolve don't each repeat the outbound fetches. `OnResolutionFailure` tells
your operator why a client was refused, once per resolution attempted; the
client itself only sees `invalid_client`.

## Relying party: be resolvable, and find providers

A federated client's `client_id` is its Entity Identifier, and it pushes
a signed request object, which is how it proves control of the keys in
its resolved metadata (§12.1.1.1):

```go
c, err := client.NewFromDiscovery(discovered, client.Config{
	ClientID:              fapi.ClientID("https://bank.example.com"),
	PushedRequestEncoding: client.PushedRequestEncodingRequestObject,
	// RedirectURI, Profile, Algorithms, Limits ...
}, deps)
```

Publish your own Entity Configuration with `Client.EntityConfiguration`
(set `Config.Federation`), with an `openid_relying_party` object
describing your redirect URIs, keys and authentication method
(`federation.OpenIDRelyingPartyMetadata` is a typed form of it). To find
a provider through the federation rather than plain discovery,
`client.DiscoverViaFederation` resolves the provider's Trust Chain with a
`federation.Resolver` and returns the same `DiscoveredMetadata`.

## Trust Anchors and Intermediates

A superior signs its own Entity Configuration with `federation.SelfIssuer`
and a Subordinate Statement for each entity it vouches for with
`federation.SubordinateIssuer`, carrying that entity's keys, metadata
policy and constraints. Serve the statements from your
`federation_fetch_endpoint`:

```go
func fetch(w http.ResponseWriter, r *http.Request) {
	sub, err := issuer.SubjectFromFetchRequest(r)
	if err != nil {
		federation.WriteError(w, err)
		return
	}
	token, err := issuer.SubordinateStatement(federation.SubordinateStatementParams{
		Subject:        sub,
		JWKS:           jwksOf(sub),
		MetadataPolicy: policyFor(sub),
		SourceEndpoint: fetchEndpoint,
	})
	// ...
	federation.WriteEntityStatement(w, token)
}
```

You keep the list of subordinates: the package signs statements, but
doesn't store who your subordinates are.

A Trust Anchor can also serve a resolve endpoint (§8.3), answering with
the resolved metadata of an entity on its callers' behalf:
`federation.ResolveRequestFromHTTP` reads the request, a `Resolver`
resolves the subject, and `ResolveIssuer.Response` signs the answer. To
use someone's resolve endpoint, call `Resolver.ResolveViaEndpoint` with
`ExpectedIssuer` naming the resolver you trust, typically the Trust
Anchor (§17.3): a response issued by anyone else is refused before any
fetch.

## What's checked for you

`federation.Resolver` validates every statement's signature and expiry at
each hop, and applies:

- **Metadata policy** from every superior, merged top-down by entity
  type, parameter and operator (§6.1.4.1), refusing a combination that
  conflicts or uses an operator marked critical that it doesn't know.
- **Constraints**: each statement's `max_path_length`,
  `naming_constraints` and `allowed_entity_types`.
- **Bounded fetching**: `Limits.MaxPathLength` and
  `Limits.MaxAuthorityHints` cap one resolution at a fixed number of
  outbound fetches, since automatic registration resolves a `client_id`
  chosen by an unauthenticated caller.
- **Strict JSON**: entity metadata and keys are decoded case-sensitively,
  so a member that differs only in case (`REDIRECT_URIS`) can't slip past
  a policy written for the real one.
- **Trust Marks**, when you ask: `Resolver.VerifyTrustMark` takes the
  subject's own `ResolvedEntity`, resolves the mark's issuer through the
  same Trust Anchor the subject was trusted through, and checks the
  mark's signature against that chain. With
  `federation.RequireFederationAccreditation` it also requires that Trust
  Anchor to list the issuer in its `trust_mark_issuers`. A
  federation-member signature alone isn't accreditation, and neither is
  another federation's: with several Trust Anchors configured, an issuer
  trusted only through one of them can't vouch for a subject of another.

## See it running

- [federated-union](../../examples/federated-union/README.md): three
  countries under one Trust Anchor, identity providers registering
  services automatically, Union and national policy combined, and a
  suspended authority. The entities are in
  [`union/entity.go`](../../examples/federated-union/union/entity.go),
  the providers in [`union/idp.go`](../../examples/federated-union/union/idp.go),
  and the services in [`union/rp.go`](../../examples/federated-union/union/rp.go).

[OpenID Federation 1.0]: https://openid.net/specs/openid-federation-1_0.html
