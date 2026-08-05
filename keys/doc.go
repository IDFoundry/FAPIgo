// Package keys defines operation-based signing and verification contracts
// so that callers never need to hold or pass around a raw crypto.PrivateKey.
//
// signing.go defines the KeyManager a server uses to request a signature
// or public key for a specific purpose (today: JARM response signing;
// ID token and access token signing will register their own
// SigningPurpose values once those endpoints are implemented);
// verification.go
// defines the corresponding public-key resolution used to check
// signatures against a known or discovered JWK. Concrete implementations
// (in-process, HSM-backed, KMS-backed) live outside this module and only
// need to satisfy these interfaces.
//
// KeyManager never returns a crypto.Signer — only a Sign operation and a
// public JWK — so an HSM- or remote-signing-service-backed implementation
// never has to hand private key material into this process. Resolving a
// remote party's verification keys (e.g. a registered client's JWKS, for
// request-object and client-assertion verification) is a distinct
// concern from KeyManager: prefer administratively pre-resolved or
// registered keys over a live fetch in the request-handling path, and
// where a live fetch is unavoidable it must go through the same SSRF,
// response-size, content-type, bounded-redirect and stale-key/duplicate-kid
// protections as any other outbound fetch (see fapihttp).
package keys
