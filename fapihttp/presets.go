package fapihttp

import "time"

// RecommendedTransportConfig returns a TransportConfig for NewClient with
// both of its required timeouts set and every host exception off — the
// production-ready starting point. Adjust the timeouts for your network;
// set a loopback exception only for local development, where it also
// stops NewClient's transport counting as hardened (see AllowsLoopback).
func RecommendedTransportConfig() TransportConfig {
	return TransportConfig{
		// Not spec-mandated — long enough for a TCP connection across
		// the public internet, short enough that an unreachable host
		// doesn't hold a request for long.
		DialTimeout: 5 * time.Second,

		// Not spec-mandated — the same budget for the TLS handshake.
		TLSHandshakeTimeout: 5 * time.Second,
	}
}

// RecommendedConfig returns a Config for New with all of its required
// limits set and every host exception off — sized for what this module
// fetches with it: discovery metadata, JWKS documents, OpenID Federation
// entity statements and trust-mark responses.
func RecommendedConfig() Config {
	return Config{
		// Not spec-mandated — 1 MiB comfortably holds a metadata
		// document, a JWKS or an entity statement, while bounding what a
		// hostile endpoint can make this process buffer.
		MaxResponseBytes: 1 << 20,

		// Not spec-mandated — the whole fetch, every redirect hop
		// included.
		RequestTimeout: 10 * time.Second,

		// Not spec-mandated — enough for a host moving its documents
		// behind one or two redirects; each hop is re-validated.
		MaxRedirects: 2,
	}
}
