# Rich Authorization Requests in Go

A scope says what kind of access a client wants ("payments"). Rich
Authorization Requests ([RFC 9396]) say exactly what: one payment of
EUR 129.00 to a named account, or read access to the accounts the
customer picks. The client sends an `authorization_details` array of
typed JSON objects, the user approves those details (or a narrower
version), and the access token carries what was granted.

FAPIgo validates the details at every step against types you define in
Go: when the client asks, when the user approves, and when a resource
server reads the token.

## Define a type

```go
type paymentInitiation struct {
	InstructedAmount struct {
		Currency string `json:"currency"`
		Amount   string `json:"amount"`
	} `json:"instructedAmount"`
	CreditorName string `json:"creditorName"`
}

var paymentType = extension.RARDefinition[paymentInitiation]{
	Type: "payment_initiation", MaxObjects: 1, MaxBytesPerObject: 1024,
	Validate: func(p paymentInitiation) error { /* your own checks */ return nil },
	// ValidateGrant nil: approved exactly as asked, or not at all.
}

registry, err := extension.NewRARRegistry(4096, 4, paymentType) // total bytes, nesting depth
```

`Validate` adds your own checks to the type's shape. `ValidateGrant`
decides what counts as an acceptable narrowing at approval (a lower
amount, fewer accounts); left nil, a granted object must match what was
requested exactly.

## Authorization server: register, gate, approve

Set `server.Config.RAR` to the registry; without it, an
`authorization_details` parameter is refused outright. Then:

- **List each client's types** in
  `storage.RegisteredClientConfig.AuthorizationDetailsTypes`. Any other
  type is refused with `invalid_authorization_details`, and an empty list
  allows none. `Server.CheckClientRegistration` finds a listed type the
  registry doesn't know, usually a typo.
- **Set a policy per grant**: `Dependencies.AuthorizationCodeRARPolicy`,
  `CIBARARPolicy` or `ClientCredentialsRARPolicy`. It sees each request
  as it arrives, before anyone is asked to approve it (for client
  credentials, there's no one to ask, so it decides alone).
  `server.AllowRequestedAuthorizationDetails{}`
  passes what a client's registered types allow; supply your own
  `RARPolicy` to check the details themselves, such as a payment limit.
  A grant with no policy refuses `authorization_details`.
- **Approve at consent.** `InteractionRequest.AuthorizationDetails` holds
  the validated request. Read it with `extension.RARGet`, show it to the
  user, and pass what they approved back, re-encoded with
  `extension.RARSet`:

```go
payments, err := extension.RARGet(interaction.AuthorizationDetails, paymentType)
// ... show payments[0].Fields to the user ...
approved, err := extension.RARSet(paymentType, payments[0].Fields)
// ...
result := server.Authorize(subject, authCtx, server.GrantedAuthorization{
	Scope:                interaction.Scope,
	AuthorizationDetails: []json.RawMessage{approved},
})
```

`CompleteAuthorization` refuses a granted object that isn't an
acceptable narrowing of one that was requested (per `ValidateGrant`),
just as it refuses a scope that wasn't requested.

## Client: ask with the same definition

```go
detail, err := extension.RARSet(paymentType, payment)
// ...
session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{
	Scope:                []string{"openid"},
	AuthorizationDetails: []json.RawMessage{detail},
})
```

`RARSet` stamps the definition's `type` into each object, so your Go
type needn't carry one. The token response's granted details come back
as `TokenSet.AuthorizationDetails`.

## Resource server: read what was granted

```go
authz, err := verifier.Verify(r.Context(), resource.VerifyRequestFromHTTP(r, paymentsEndpoint))
// ...
granted, err := extension.ParseGrantedRAR(authz.Claims[extension.AuthorizationDetailsClaim])
// ...
payments, err := extension.RARGet(granted, paymentType)
```

A token without the claim was granted none: the result is empty, never
an error read as "nothing to check". Refuse a request the granted
details don't cover with `resource.NewInsufficientScopeError(authz,
"...")`, sent with `resource.WriteError`: a 403 whose challenge uses
the scheme the token was presented with.

## Checked for you

- **Strict parsing:** a member the Go type doesn't declare is refused, and
  so is one spelled differently from its JSON tag (`ACTIONS` for
  `actions`), at any depth. Each object's `type` must be a registered
  one, and no member may appear twice.
- **Bounds:** the whole array's size and nesting depth, and each type's
  object count and object size.

## See it running

- [payment-consent](../../examples/payment-consent/README.md): a single
  `payment_initiation` approved exactly as asked. The type is in
  [`payment/rar.go`](../../examples/payment-consent/payment/rar.go), the
  consent step in [`payment/bank.go`](../../examples/payment-consent/payment/bank.go),
  and the resource server reads it in
  [`payment/api.go`](../../examples/payment-consent/payment/api.go).
- [linked-accounts](../../examples/linked-accounts/README.md): an
  `account_access` request naming no accounts, narrowed by the customer
  choosing which to share; its `ValidateGrant` is in
  [`linked/rar.go`](../../examples/linked-accounts/linked/rar.go).
- [decoupled-checkout](../../examples/decoupled-checkout/README.md): the
  same over CIBA, approved on the customer's phone.

[RFC 9396]: https://www.rfc-editor.org/rfc/rfc9396
