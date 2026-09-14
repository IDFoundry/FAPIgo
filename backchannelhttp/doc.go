// Package backchannelhttp provides a ready-to-use server.BackchannelNotifier
// backed by fapihttp's hardened HTTP transport, so a CIBA (OpenID Connect
// Client-Initiated Backchannel Authentication) §10.2 ping-delivery deployment
// doesn't have to hand-wire its own SSRF/DNS-rebinding-safe HTTP client just
// to dispatch a notification —
// server itself never terminates or originates a TLS connection (see
// ARCHITECTURE.md design rule 6 and server.BackchannelNotifier's own doc
// comment), the same reason fapihttp lives outside client/server/resource
// rather than inside any one of them.
//
// New wraps a caller-supplied fapihttp.HTTPClient — strongly prefer one
// built by fapihttp.NewClient, for the reasons its own doc comment
// describes. This package adds nothing beyond that transport and CIBA
// §10.2's own response handling: a 2xx status is success, anything else
// (including a transport error) is a plain error, which
// server.BackchannelNotifier.Notify's own doc comment already treats as
// best-effort informational only.
package backchannelhttp
