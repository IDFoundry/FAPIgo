// Package sqlstore holds durable implementations of the storage
// interfaces a FAPIgo Authorization Server (server.Dependencies) needs,
// in a PostgreSQL or SQLite database reached through database/sql. It
// is a Go module of its own, github.com/idfoundry/fapigo/sqlstore, so
// FAPIgo itself takes no database driver: bring the driver you use.
// Every store passes its storage.Test*Contract suite on both databases.
//
// # Setup
//
// Open the database with your driver, wrap it with New, and create its
// tables with Migrate:
//
//	sqlDB, err := sql.Open("pgx", dsn) // github.com/jackc/pgx/v5/stdlib
//	db, err := sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{})
//	err = db.Migrate(ctx) // or db.CheckSchema(ctx), where a deployment step migrates
//
// Then take each store from the DB, one method per server.Dependencies
// field:
//
//	deps := server.Dependencies{
//		Clients:      db.Clients(),
//		Transactions: db.Transactions(),
//		Grants:       db.Grants(),
//		Replay:       db.Replay(),
//		Nonces:       db.Nonces(),
//		Revocation:   db.Revocation(),
//		// ...
//	}
//
// Replay, Nonces and Revocation also serve a resource server
// (resource.Dependencies' Replay, Nonces and Revocation): give it the
// same tables, through a DB with the same TablePrefix, so a revocation
// the server records is seen there.
//
// For SQLite, with a driver such as modernc.org/sqlite (pure Go, no
// cgo), open the file in WAL mode with a busy timeout, so readers don't
// wait on writers and a connection waits its turn for the write lock
// instead of failing:
//
//	sql.Open("sqlite", "file:fapigo.db?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
//
// # Migrations
//
// The schema is versioned, its migrations embedded in the package.
// Nothing migrates implicitly — New doesn't touch the database: Migrate
// applies the migrations the database lacks, each in a transaction,
// once between any number of processes running it at once (a Postgres
// advisory lock; SQLite's write lock). Run it from a deployment step
// with a role that may create tables, or at startup; CheckSchema, at
// startup, fails fast where the schema is behind. Both refuse a schema
// a newer release of this package has migrated further, whose changes
// this one doesn't know. Options.TablePrefix ("fapigo_" by default)
// prefixes every table, schema_migrations included, so several DBs —
// OID4VCgo's sqlstore among them ("oid4vc_") — can share one database
// and one *sql.DB.
//
// # Atomicity
//
// Every consume-once operation is one statement or one transaction,
// atomic across every process sharing the database, not just within
// one:
//
//   - a replay digest is one INSERT … ON CONFLICT DO NOTHING;
//   - an authorization code's redemption is one UPDATE … RETURNING that
//     matches only an unredeemed code (and, given the redeeming
//     client's ID, only one issued to that client);
//   - BeginAuthorization's UPDATE … RETURNING finds the pushed request
//     unconsumed and unexpired at the server's time and locks its row,
//     in the transaction that inserts the new interaction;
//     CompleteAuthorization deletes the interaction (DELETE …
//     RETURNING) and marks its pushed request consumed only if it
//     wasn't already, in one transaction, so exactly one interaction
//     per pushed request ever completes.
//
// On SQLite every write runs in a transaction started with BEGIN
// IMMEDIATE. Expiry is compared against the time the server passes
// (storage.BeginAuthorizationTransaction.Now), never the database's
// clock; elsewhere the server compares the expiry a store returns
// itself. Times are kept as Unix nanoseconds, so they round-trip
// exactly.
//
// Keys are case- and byte-exact: digests are binary columns, and text
// keys compare with the "C" collation on Postgres and bytewise on
// SQLite. A text key PostgreSQL's text type can't hold (NUL or invalid
// UTF-8) is answered as unknown by a lookup, and refused by a write.
//
// The stores keep what the server hands them: the digests of codes,
// refresh tokens, request_uri references and interaction handles, never
// the values themselves, and the server's request and grant records as
// opaque blobs.
//
// # Errors
//
// A store that couldn't answer — the database unreachable, a timeout, a
// cancelled context — returns an error wrapping
// storage.ErrStoreUnavailable (and the database's own error, so
// errors.Is still finds context.Canceled), which the server and a
// resource server answer with 500 server_error. An unknown key is an
// error wrapping ErrNotFound instead, a replayed digest ErrReplayed, and
// a reused authorization code *storage.AuthorizationCodeAlreadyRedeemedError,
// as the interfaces require.
//
// # Capabilities
//
// Every store declares storage.StoreAssurance capabilities, which
// server.New checks under AssuranceProduction:
//
//   - Postgres: Durable, AtomicConsume and CrossInstanceConsistent. Rows
//     are committed to the database, the consumes above are atomic
//     statements or row-locked transactions, and every instance sharing
//     the database sees the same rows. Not SerializableRedemption: the
//     stores run at the database's default READ COMMITTED isolation,
//     relying on row locks for each key rather than on SERIALIZABLE
//     isolation between keys.
//   - SQLite: Durable, AtomicConsume and SerializableRedemption, since
//     SQLite's transactions are serializable. Not
//     CrossInstanceConsistent: a database file on one host can't back a
//     horizontally scaled deployment, so server.New refuses these stores
//     with server.DeploymentHorizontallyScaled; use them with
//     server.DeploymentSingleInstance.
//
// Neither declares EncryptedAtRest: the records are stored as the
// server hands them. Encrypt the database's storage, or wait for the
// record sealing a later release adds.
//
// # Clients
//
// ClientRepository reads the clients table, which the operator manages:
// a client_id column and a config column holding the client's
// storage.RegisteredClientConfig, less its ID, as a versioned JSON
// document (ClientConfigVersion), for example:
//
//	{"version":1,
//	 "redirect_uris":["https://rp.example/callback"],
//	 "client_assertion_algorithm":"ES256",
//	 "sender_constrain":"dpop",
//	 "allowed_scopes":["openid","accounts"]}
//
// Each member is a RegisteredClientConfig field in snake_case
// (client_auth_methods, expected_san_dns, backchannel_token_delivery_mode,
// display with name, logo_uri, policy_uri and tos_uri, and so on); each
// enumeration is its wire value (what its type's String returns and its
// Parse function reads: "private_key_jwt", "PS256", "pairwise"); each
// URL a string. An omitted member is the field's zero value. A member
// the version doesn't define is refused, so a misspelt one can't be
// silently dropped. MarshalClientConfig writes the document from a
// RegisteredClientConfig, ParseClientConfig reads it, and Put and
// Delete manage rows, Put refusing a configuration
// storage.NewRegisteredClient refuses. ResolveClient builds the client
// on every call, so a change takes effect on the next request; a row
// that doesn't make a valid client is answered as an outage
// (ErrClientConfig, wrapping storage.ErrStoreUnavailable), not as an
// unknown client.
//
// # Sweeping
//
// The stores never delete an expired row themselves: the server refuses
// an expired record it reads. Call Sweep periodically (every few
// minutes, say) with the server's time to delete them, so the tables
// don't grow without bound. A row is kept as long as something may
// still need it: a pushed request until the last interaction begun from
// it expires, a redeemed authorization code until the tokens its
// redemption issued expire (so reusing the code still revokes them),
// and a revocation until the latest expiry it was recorded with.
//
// # Not yet provided
//
// This release provides the stores above. Not yet: the
// AccessTokenStore (for server.OpaqueAccessTokens; JWT access tokens
// need none), the BackchannelAuthenticationStore (for CIBA), the
// PairwiseSubjectStore (for random, mapped pairwise subjects), the client's
// SessionStore, and sealing of the stored records. Until then, take
// those from an implementation of your own, run against its
// storage.Test*Contract suite.
package sqlstore
