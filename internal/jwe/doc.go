// Package jwe implements JWE (RFC 7516) compact-serialization
// encryption and decryption for exactly the two key-management
// algorithms fapi.KeyManagementAlgorithm supports (RSA-OAEP-256 and
// ECDH-ES+A256KW), each of which may be paired with either
// content-encryption algorithm fapi.ContentEncryptionAlgorithm
// supports: A256GCM (a single AEAD primitive) or A256CBC-HS512
// (encrypt-then-MAC — AES-256-CBC plus a separate HMAC-SHA-512 tag,
// RFC 7518 §5.2.3).
//
// Like internal/jose, this package is intentionally low-level and
// generic: it knows nothing about ID tokens, nested JWTs, or any other
// FAPI-specific convention. A caller wanting a signed-then-encrypted
// nested JWT (OIDC Core §10.2) composes this package with
// internal/jose itself — sign first, then Encrypt the resulting compact
// JWS as this package's plaintext with ContentType "JWT" — rather than
// this package knowing about that convention on its own.
package jwe
