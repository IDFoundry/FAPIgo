// Package keys defines operation-based signing, verification, and
// decryption contracts so that callers never need to hold or pass
// around a raw crypto.PrivateKey.
//
// signing.go defines the KeyManager a server or client uses to request
// a signature or public key for a specific purpose (JARM response
// signing, ID token and access token signing, client assertions,
// request objects, DPoP proofs); verification.go defines the
// corresponding public-key resolution used to check signatures against
// a known or discovered JWK. decryption.go defines Decrypter, the
// decryption-side counterpart: recovering the content-encryption key of
// an encrypted ID token or UserInfo response without ever exposing the
// recipient's private key to this module or its caller.
//
// Every one of these interfaces never returns a crypto.Signer or a
// private key — only an operation (Sign, UnwrapContentEncryptionKey)
// and a public JWK — so an HSM- or KMS-backed implementation never has
// to hand private key material into this process. Concrete
// implementations this package itself provides:
//
//   - capability_decrypter.go's NewDecrypter/NewSingleKeyDecrypter
//     assemble a Decrypter from a backend implementing ECDHAgreer,
//     KeyDecrypter, or both — each delegating exactly the one
//     private-key primitive a real HSM/KMS exposes (raw ECDH
//     agreement, or an RSA-OAEP-256 decrypt), never a raw key.
//   - inmemory_decrypter.go's NewInMemoryECDH/NewInMemoryRSA implement
//     those same capabilities over a static in-memory key — a
//     production key loaded from a secrets manager, or a fixed key a
//     test fixture was generated against.
//   - signer_keymanager.go's NewKeyManagerFromSigners adapts any
//     crypto.Signer — Go's own "delegate the primitive, not the key"
//     abstraction, and what most HSM/KMS Go client wrappers already
//     implement — into a KeyManager, covering both a static in-memory
//     key (*ecdsa.PrivateKey, *rsa.PrivateKey, and ed25519.PrivateKey
//     all satisfy crypto.Signer directly) and an arbitrary KMS/HSM
//     backend, with no FAPIgo-specific glue code in either case.
//
// The one exception to "production-suitable" above is keys/ephemeral,
// an in-tree, in-memory KeyManager/Decrypter/ClientKeySource set that
// always generates a fresh key rather than taking one — for local
// development and testing only, never production — so integrating
// server or client doesn't require writing key management from scratch
// just to get something running; see its own package doc comment.
//
// Key rotation: KeyManager/Decrypter say nothing about how an
// implementation manages its own key lifecycle — that's deliberately
// left to the embedder — but two places needed real support, not just
// permission, for a rotation to be safe. signing.go's
// RotatingKeyManager is KeyManager's optional extension for publishing
// more than one currently-valid key per purpose (the outgoing key
// alongside the incoming one) during a rotation's overlap window, so a
// signature made just before the cutover stays verifiable; server's
// PublicJWKS uses it automatically when a configured KeyManager
// implements it. decryption.go's UnwrapRequest carries the JWE's own
// "kid" through to Decrypter (and, in turn, to ECDHAgreer/KeyDecrypter)
// for exactly the matching reason: a backend holding more than one
// registered decryption key needs the kid to know which one a given
// ciphertext was actually wrapped to, rather than always guessing "the
// current one."
//
// Resolving a remote party's verification keys (e.g. a registered
// client's JWKS, for request-object and client-assertion verification)
// or encryption key (for issuing an encrypted ID token) is a distinct
// concern from KeyManager/Decrypter: prefer administratively
// pre-resolved or registered keys over a live fetch in the
// request-handling path, and where a live fetch is unavoidable it must
// go through the same SSRF, response-size, content-type,
// bounded-redirect and stale-key/duplicate-kid protections as any other
// outbound fetch (see fapihttp).
package keys
