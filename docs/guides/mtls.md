# Mutual TLS in Go

OAuth 2.0 Mutual-TLS ([RFC 8705]) does two separate jobs with a TLS
client certificate:

- **Client authentication** (§2): the client proves who it is by the
  certificate it presents, instead of a signed client assertion. Either
  the certificate chains to a CA the authorization server trusts and
  names the registered subject (`tls_client_auth`), or it's a
  self-signed certificate the server has registered by thumbprint
  (`self_signed_tls_client_auth`).
- **Certificate-bound access tokens** (§3): the access token carries
  the certificate's thumbprint (`cnf.x5t#S256`), and a resource server
  accepts it only over a connection presenting that certificate.

FAPI 2.0 requires sender-constrained access tokens, by mTLS or by
[DPoP](dpop.md). FAPIgo supports both; the two jobs are independent, so
a client can, for example, authenticate with `private_key_jwt` and still
get certificate-bound tokens.

## Client: a certificate on the HTTP client

FAPIgo never holds the certificate's private key. It's configured on
the `*http.Client` you pass as `Dependencies.HTTP`:

```go
// RFC 8705 §5: requests that do mutual TLS go to the server's mTLS
// aliases. With Endpoints left zero, NewFromDiscovery applies them:
// at every request that authenticates the client (PAR, token, CIBA,
// revocation) for certificate client authentication, and at the
// token-using ones (not PAR) for certificate-bound tokens alone. Set
// Endpoints yourself only to adjust them first, with
// discovered.MTLSEndpointAliases.ApplyForClientAuth or
// ApplyForSenderConstrain.
c, err := client.NewFromDiscovery(discovered, client.Config{
	// ClientID, Profile, Limits ...
	ClientAuthMethod: storage.ClientAuthMethodTLSClientAuth,
	SenderConstrain:  storage.SenderConstrainMTLS,
}, client.Dependencies{
	HTTP: &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{clientCert}},
	}},
	// Clock, Random ...
})
```

With `SenderConstrainMTLS`, the client sends no DPoP proofs, and
`ProtectedResource(tokens).Do` (or `ClientCredentialsResource` for the
client credentials grant) sends `Authorization: Bearer <token>` over the
same certificate-presenting transport. A client that only authenticates
with mTLS, and signs nothing else, needs no `Dependencies.Keys`.

## Authorization server: trust, registration and the certificate

```go
srv, err := server.New(server.Config{
	// Issuer, Endpoints, Profile, Algorithms, Limits, Subjects ...
	MTLSEndpoints: server.MTLSEndpoints{Token: mtlsTokenURL},
}, server.Dependencies{
	// RFC 8705 §2.1.1: verify the chain yourself, and check revocation.
	ClientCertificateTrust: server.TrustedClientCAs{
		Roots:         rootCAs,
		Intermediates: issuingCAs, // revocation-checked, unlike Roots
		Revocation:    server.ClientCertificateCRLs{Lists: currentCRLs},
	},
	// ...
})
```

- **Registration.** `ClientAuthMethodTLSClientAuth` matches
  `ExpectedSubjectDN`; its siblings `ClientAuthMethodTLSClientAuthSANDNS`,
  `...SANURI`, `...SANIP` and `...SANEmail` match a subject alternative
  name instead. `ClientAuthMethodSelfSignedTLSClientAuth` matches
  `ExpectedCertificateThumbprint` and needs no chain trust. Set
  `SenderConstrain: storage.SenderConstrainMTLS` for bound tokens.
- **Chain trust is required.** `Dependencies.ClientCertificateTrust` has
  no default: `TrustedClientCAs` verifies the chain and asks its
  `Revocation` (CRLs, your own OCSP check, or an explicit
  `NoClientCertificateRevocationCheck{}`), and
  `NoClientCertificateChainTrust{}` declares that something before
  FAPIgo already verified the chain (your TLS listener's `ClientCAs` with
  `RequireAndVerifyClientCert`, or a gateway). A missing or stale CRL
  fails closed. A server whose clients use only
  `self_signed_tls_client_auth`, or no certificate at all, passes
  `NoPKIClientAuthentication{}`, which refuses `tls_client_auth`
  outright: with `NoClientCertificateChainTrust{}` and no real chain
  check, anyone could present a self-signed certificate naming a
  client's subject. Federation automatic registration registers
  `tls_client_auth` only under `TrustedClientCAs`, or under
  `NoClientCertificateChainTrust{}` when
  `AutomaticRegistration.AllowedClientAuthMethods` names it.
- **The certificate.** The `…FromHTTP` request constructors read it from
  the request's own TLS connection (`PeerCertificateFromHTTP`). Behind a
  proxy that terminates TLS, set it yourself, with
  `TokenEndpointRequest.SetPeerCertificate` or the `PeerCertificate`
  field of the other request types — but only from your own proxy, over
  a hop clients can't reach, with the proxy removing any copy of its
  forwarding header a client sent. A certificate is public (a self-signed
  one is in the client's registered JWKS); only the TLS handshake proves
  the client holds its key, so a header a client can set lets anyone
  authenticate as any mTLS client.
- **Metadata** advertises `mtls_endpoint_aliases` once
  `MTLSEndpoints` is set, and `tls_client_certificate_bound_access_tokens`
  and the mTLS authentication methods once a client can do mutual TLS
  anywhere: with `MTLSEndpoints`, or with `Config.MutualTLSAtEndpoints`
  when the listener serving the ordinary endpoints asks for a client
  certificate itself (RFC 8705 §5 makes aliases optional).
  `tls_client_auth` isn't advertised under
  `NoPKIClientAuthentication{}`, which refuses it.

## Resource server: the token follows the certificate

`resource.Verifier` checks that the certificate on the request matches
the token's `cnf.x5t#S256`. `resource.VerifyRequestFromHTTP` reads it
from the connection; behind a proxy, set `VerifyRequest.PeerCertificate`,
under the same rule: only from your own proxy's forwarding.
The resource server checks the binding, not revocation, so keep
`Limits.AccessTokenLifetime` short.

## See it running

- [payroll-run](../../examples/payroll-run/README.md): a payroll
  provider pays staff through its bank's API with `tls_client_auth` and
  certificate-bound tokens. Its attack lab gets a token without the
  provider's key (self-signed, wrong-CA, expired, revoked and
  wrong-subject certificates) and steals the token; a rotation panel
  shows tokens following the certificate. The bank's wiring is in
  [`payroll/bank.go`](../../examples/payroll-run/payroll/bank.go), the
  client's in
  [`payroll/ledgerline.go`](../../examples/payroll-run/payroll/ledgerline.go).
- [GETTING_STARTED](../../GETTING_STARTED.md): wiring all three roles.

[RFC 8705]: https://www.rfc-editor.org/rfc/rfc8705
