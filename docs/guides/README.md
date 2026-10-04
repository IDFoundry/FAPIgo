# Guides

Short guides to one mechanism or use case each: what it is, why FAPI 2.0
needs it, and the FAPIgo code for every role involved, with links to a
runnable demo. For wiring a whole deployment, start with
[GETTING_STARTED](../../GETTING_STARTED.md).

| Guide | Covers |
|---|---|
| [DPoP in Go](dpop.md) | Sender-constrained access tokens (RFC 9449): client, authorization server and resource server |
| [Pushed Authorization Requests in Go](par.md) | PAR (RFC 9126), and signed request objects under Message Signing |
| [A FAPI 2.0 wallet in Go](native-wallet.md) | Native app clients: redirects, client attestation, platform keys, relaunch, and token lifecycle |
| [Mutual TLS in Go](mtls.md) | Certificate client authentication and certificate-bound tokens (RFC 8705), the alternative to DPoP |
| [FAPI 2.0 Message Signing in Go](message-signing.md) | Signed request objects (JAR), signed authorization responses (JARM), and signed UserInfo |
| [CIBA in Go](ciba.md) | Decoupled authorization (FAPI-CIBA): poll and ping delivery, and the server's three steps |
| [Rich Authorization Requests in Go](rar.md) | Fine-grained `authorization_details` (RFC 9396): defining types, policies, consent and reading grants |
| [OpenID Federation in Go](openid-federation.md) | Trust chains, automatic client registration, and running a Trust Anchor or Intermediate |
