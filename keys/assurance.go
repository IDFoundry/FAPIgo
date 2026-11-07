package keys

// KeySourceCapabilities is what a ClientKeySource, IssuerKeySource,
// ClientEncryptionKeySource or AttesterKeySource implementation — or a
// server.AttesterTrustAnchors/AttesterAnchorSource, which supplies
// attester trust anchors rather than keys — self-declares about its own
// safety properties — checked under
// server.AssuranceProduction, client.AssuranceProduction and
// resource.AssuranceProduction the same way storage.StoreAssurance is
// checked for a store, and for the same reason: each of these
// interfaces is a single method with no structural way to tell a
// hardened implementation from a naive one apart from what it declares
// here.
type KeySourceCapabilities struct {
	// LiveFetchHardened is true iff every live network fetch this key
	// source performs goes through fapihttp's own SSRF/size-limit/
	// redirect protections (ARCHITECTURE.md design rule 6) over a
	// fetcher that is fapihttp.Client.HardenedForProduction (NewClient's
	// intact transport, which validates the address it dials, with no
	// loopback exception granted), or the implementation performs no
	// live fetch at all (administratively pre-resolved or cached keys
	// only).
	LiveFetchHardened bool
}

// KeySourceAssurance is the optional interface a ClientKeySource,
// IssuerKeySource, ClientEncryptionKeySource or AttesterKeySource
// implementation can declare its own KeySourceCapabilities through. There is no default:
// an implementation that doesn't implement this interface at all is
// rejected under AssuranceProduction — the same "declaring capabilities
// is not optional" stance storage.StoreAssurance takes; see that type's
// own doc comment. JWKSIssuerKeySource, ClientJWKSSource (this
// package) and keys/ephemeral.ClientKeySource are this module's own
// bundled live-fetch implementations; only JWKSIssuerKeySource and
// ClientJWKSSource declare LiveFetchHardened — true only when their
// fapihttp.Client is HardenedForProduction (or, for ClientJWKSSource,
// when it has none and so fetches nothing) — and LocalIssuerKeys,
// StaticClientKeys and StaticAttesterKeys, which fetch nothing,
// declare it too. keys/ephemeral is explicitly "local development
// and testing only, never production" (see that package's own doc
// comment), so it deliberately does not implement this interface,
// keeping it correctly rejected under AssuranceProduction rather than
// accidentally passing because its live fetch happens to also go
// through fapihttp.
//
// A declaration is the operator's promise about the implementation, not
// something this library verifies: production assurance trusts it, so
// declare only what the implementation actually provides.
//
// A declaration describes the declaring type's own behaviour. A type
// embedding a source that declares it inherits the declaration through
// Go's method promotion, and production assurance can't tell it from one
// the wrapper made itself. A wrapper that changes how keys are resolved
// must override Capabilities with what the wrapper does: one embedding
// StaticClientKeys, StaticAttesterKeys or LocalIssuerKeys (or
// server.StaticAttesterTrustAnchors or server.StaticAttesterAnchors),
// whose LiveFetchHardened holds because they fetch nothing, and adding a
// fetch of its own (a jwks_uri fallback, say) is hardened only if that
// fetch is; one embedding ClientJWKSSource or JWKSIssuerKeySource, whose
// declaration covers their own fetcher, likewise.
type KeySourceAssurance interface {
	Capabilities() KeySourceCapabilities
}
