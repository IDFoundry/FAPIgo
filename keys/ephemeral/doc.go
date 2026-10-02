// Package ephemeral provides in-memory implementations of
// keys.KeyManager, keys.Decrypter and keys.ClientKeySource (which also
// resolves clients' encryption keys, keys.ClientEncryptionKeySource) —
// for local development and testing only. Never production — its KeyManager deliberately doesn't
// implement keys.KeyCustodyAssurance, so server.AssuranceProduction and
// client.AssuranceProduction reject it.
//
// KeyManager generates fresh keys once at process startup and never
// persists them. Restarting the process invalidates every previously
// issued token and everything a client cached from this server's own
// JWKS — there is no key rollover, no durability, nothing to recover
// after a crash. That's the right tradeoff for a short local
// development session; it is never the right tradeoff for anything
// that needs to survive a restart.
package ephemeral
