// Package jwe implements JWE (RFC 7516) compact-serialization
// encryption and decryption for exactly the two key-management
// algorithms fapi.KeyManagementAlgorithm supports (RSA-OAEP-256 and
// ECDH-ES+A256KW) paired with the one content-encryption algorithm
// fapi.ContentEncryptionAlgorithm supports (A256GCM).
//
// Like internal/jose, this package is intentionally low-level and
// generic: it knows nothing about ID tokens, nested JWTs, or any other
// FAPI-specific convention. A caller wanting a signed-then-encrypted
// nested JWT (OIDC Core §10.2) composes this package with
// internal/jose itself — sign first, then Encrypt the resulting compact
// JWS as this package's plaintext with ContentType "JWT" — rather than
// this package knowing about that convention on its own.
package jwe
