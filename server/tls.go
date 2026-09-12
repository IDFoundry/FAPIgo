package server

import "crypto/tls"

// FAPIRWTLSCipherSuites is the FAPI-RW §8.5 TLS 1.2 cipher suite
// allow-list: ECDHE key exchange (forward secrecy) with an AEAD cipher
// only — no CBC-mode suites, which Go's zero-value tls.Config still
// offers by default for broader interop. Set it as a Server's own
// http.Server.TLSConfig.CipherSuites alongside MinVersion:
// tls.VersionTLS12; TLS 1.3 needs no equivalent list — crypto/tls
// ignores CipherSuites for 1.3 and always offers only its three
// built-in AEAD suites.
//
// This is the narrower FAPI-RW §8.5 list (AES-GCM only, both ECDSA and
// RSA), not the broader BCP195/RFC 7525 set FAPI2-SP-FINAL-5.2.2 cites
// (which also permits ChaCha20-Poly1305) — the OIDF conformance
// suite's own FAPI-RW-8.5-1/8.5-2 check hardcodes a TLS 1.2 probe
// against exactly this narrower list and flags ChaCha20-Poly1305 as
// "not permitted" even though BCP195 itself endorses it. A deployment
// only targeting BCP195, not FAPI-RW §8.5 specifically, is free to use
// a wider list instead.
var FAPIRWTLSCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}
