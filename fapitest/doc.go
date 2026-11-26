// Package fapitest is an in-process interoperability harness that wires a
// client.Client, server.Server and resource.Verifier together over real
// HTTP (via httptest.Server — real TLS with a real client certificate
// too, under Config.SenderConstrain storage.SenderConstrainMTLS or
// Config.ClientAuthMethod's two RFC 8705 §2 mTLS values) to run
// end-to-end flows in tests.
//
// It exists purely to catch cross-role bugs — parameter serialization,
// duplicate handling, header issues, URI canonicalization mismatches,
// content-type handling, redirect behaviour — that unit tests against a
// single role cannot see. It must never become a production shortcut that
// lets a client call a server directly, in-process, without going through
// wire encoding and HTTP semantics; doing so would defeat its own purpose.
// This package is test-only and must not be imported by client, server,
// resource or internal/.
//
// The harness's own authorization endpoint approves every interaction
// at once (AutoApprove). For a test of what an embedding application's
// login and consent UI does with the interaction, Harness.EmbedderUI
// serves a model one in front of the same server: a sign-in that sets
// the UI's own session cookie, an authorization endpoint keeping the
// interaction in a cookie server/interactioncookie seals, and a consent
// submission completing it for the signed-in subject. It uses only the
// server's and server/interactioncookie's public API, so an embedder's
// own UI can follow it; EmbedderUIOptions.UnsafeRawHandleCookie keeps
// the raw handle in a plain cookie instead, for negative tests only.
package fapitest
