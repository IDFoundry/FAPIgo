package server_test

import (
	"crypto/tls"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

// TestFAPIRWTLSCipherSuitesExcludesChaCha20Poly1305 covers the one
// property that distinguishes this list from the broader BCP195 set:
// no ChaCha20-Poly1305 suite, which the OIDF FAPI-RW-8.5-1/8.5-2 check
// flags as "not permitted" even though BCP195 itself endorses it.
func TestFAPIRWTLSCipherSuitesExcludesChaCha20Poly1305(t *testing.T) {
	disallowed := map[uint16]bool{
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:   true,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305: true,
	}
	for _, suite := range server.FAPIRWTLSCipherSuites {
		if disallowed[suite] {
			t.Fatalf("FAPIRWTLSCipherSuites contains a ChaCha20-Poly1305 suite (%d), want none", suite)
		}
	}
}

// TestFAPIRWTLSCipherSuitesAllAEADWithForwardSecrecy covers the other
// defining property: every suite is ECDHE (forward secrecy) with an
// AEAD (GCM) cipher — no static RSA key exchange, no CBC mode.
func TestFAPIRWTLSCipherSuitesAllAEADWithForwardSecrecy(t *testing.T) {
	allowed := map[uint16]bool{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
	}
	if len(server.FAPIRWTLSCipherSuites) == 0 {
		t.Fatal("FAPIRWTLSCipherSuites is empty")
	}
	for _, suite := range server.FAPIRWTLSCipherSuites {
		if !allowed[suite] {
			t.Fatalf("FAPIRWTLSCipherSuites contains unexpected suite %d", suite)
		}
	}
}
