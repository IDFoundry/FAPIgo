// Package fapitest is an in-process interoperability harness that wires a
// client.Client, server.Server and resource.Verifier together over real
// HTTP (via httptest.Server — real TLS with a real client certificate
// too, under Config.SenderConstrain storage.SenderConstrainMTLS) to run
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
package fapitest
