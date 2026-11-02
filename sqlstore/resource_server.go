package sqlstore

import "errors"

// ResourceServerStores are a resource server's stores, for a resource
// server that runs apart from the authorization server (one in the same
// process uses serverresource.NewVerifier, which takes the server's
// Dependencies): ResourceServer returns them.
type ResourceServerStores struct {
	// Revocation is resource.Dependencies.Revocation: the server's
	// revocations, which server.Server.RevokeGrant and a reused
	// authorization code record.
	Revocation *RevocationStore

	// Replay is resource.Dependencies.Replay: the server's replay
	// table, in which each role keeps its digests in a namespace of its
	// own.
	Replay *ReplayStore

	// AccessTokens is resource.OpaqueAccessTokens' Store: the server's
	// opaque access tokens. Unused with JWT access tokens.
	AccessTokens *AccessTokenStore

	// Nonces is resource.Dependencies.Nonces: the resource server's own
	// DPoP nonces, never the server's, whose nonces it would then accept
	// (RFC 9449 keeps the server's, §8, apart from a resource server's,
	// §9).
	Nonces *NonceStore
}

// ResourceServer returns a resource server's stores: Revocation,
// Replay and AccessTokens from server, a DB on the authorization
// server's tables (its TablePrefix and, for opaque access tokens, its
// Sealer), and Nonces from own, a DB with a TablePrefix of its own.
//
// Take them all from here rather than from either DB's methods: a
// resource server whose Revocation came from own, as its Nonces must,
// would read a table the server never writes, and keep accepting the
// tokens of a revoked grant until they expire, with nothing failing.
// It refuses a nil DB, and server and own on one TablePrefix (the same
// DB, or two over it), whose nonces would be the server's. Migrate
// (or CheckSchema) both, as for any DB; only the server runs Sweep on
// the tables they share, and the resource server on own.
func ResourceServer(server, own *DB) (ResourceServerStores, error) {
	switch {
	case server == nil || own == nil:
		return ResourceServerStores{}, errors.New("sqlstore: resource server: nil DB")
	case server == own || server.prefix == own.prefix:
		return ResourceServerStores{}, errors.New("sqlstore: resource server: own is on the server's TablePrefix, " + server.prefix + ", so its nonces would be the server's: give it a TablePrefix of its own")
	}
	return ResourceServerStores{
		Revocation:   server.Revocation(),
		Replay:       server.Replay(),
		AccessTokens: server.AccessTokens(),
		Nonces:       own.Nonces(),
	}, nil
}
