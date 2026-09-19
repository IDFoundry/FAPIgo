package keys

// KeySourceCapabilities is what a ClientKeySource, IssuerKeySource, or
// ClientEncryptionKeySource implementation self-declares about its own
// safety properties — checked under server.AssuranceProduction/
// client.AssuranceProduction the same way storage.StoreAssurance is
// checked for a store, and for the same reason: each of these
// interfaces is a single method with no structural way to tell a
// hardened implementation from a naive one apart from what it declares
// here.
type KeySourceCapabilities struct {
	// LiveFetchHardened is true iff every live network fetch this key
	// source performs goes through fapihttp's own SSRF/size-limit/
	// redirect protections (ARCHITECTURE.md design rule 6), or the
	// implementation performs no live fetch at all (administratively
	// pre-resolved or cached keys only).
	LiveFetchHardened bool
}

// KeySourceAssurance is the optional interface a ClientKeySource,
// IssuerKeySource, or ClientEncryptionKeySource implementation can
// declare its own KeySourceCapabilities through. There is no default:
// an implementation that doesn't implement this interface at all is
// rejected under AssuranceProduction — the same "declaring capabilities
// is not optional" stance storage.StoreAssurance takes; see that type's
// own doc comment. JWKSIssuerKeySource (this package) and
// keys/ephemeral.ClientKeySource are this module's own two bundled
// live-fetch implementations; only JWKSIssuerKeySource declares
// LiveFetchHardened (true, since it's unconditionally built on
// fapihttp.Client) — keys/ephemeral is explicitly "local development
// and testing only, never production" (see that package's own doc
// comment), so it deliberately does not implement this interface,
// keeping it correctly rejected under AssuranceProduction rather than
// accidentally passing because its live fetch happens to also go
// through fapihttp.
type KeySourceAssurance interface {
	Capabilities() KeySourceCapabilities
}
