// Package sqlstore holds durable implementations of the storage
// interfaces a FAPIgo Authorization Server (server.Dependencies) needs,
// and of a relying party's session store (client.Dependencies.Sessions),
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
// and, for the features that need one, its store:
//
//	deps.AccessTokens = server.OpaqueAccessTokens{Store: db.AccessTokens()} // opaque access tokens; JWTs need none
//	deps.Backchannel = db.Backchannel()                                    // CIBA
//	deps.PairwiseSubjects, err = pairwise.NewMapping(db.PairwiseSubjects()) // pairwise subs (Config.Subjects), random and mapped
//
// A relying party (package client) takes its session store from a DB
// the same way, for client.Dependencies.Sessions:
//
//	deps := client.Dependencies{
//		Sessions: db.Sessions(),
//		// ...
//	}
//
// Revocation and AccessTokens also serve a resource server
// (resource.Dependencies.Revocation and resource.OpaqueAccessTokens'
// store), as does Replay (resource.Dependencies.Replay, whose digests
// each role keeps in a namespace of its own): give it the same tables,
// through a DB with the same TablePrefix and Sealer, so a revocation or
// an access token the server records is seen there. Its DPoP nonce
// store (resource.Dependencies.Nonces, serverresource.Options.Nonces)
// is the exception: never the server's, whose nonces it would then
// accept (RFC 9449 §8, §9), but Nonces from a DB with a TablePrefix of
// its own:
//
//	rsDB, err := sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{TablePrefix: "fapigo_rs_"})
//	err = rsDB.Migrate(ctx)
//	verifier, err := serverresource.NewVerifier(cfg, deps, serverresource.Options{
//		ResourceURLs: resourceURLs,
//		Nonces:       rsDB.Nonces(),
//	})
//
// (serverresource.NewVerifier refuses the server's own db.Nonces(), but
// can't tell two DBs with one TablePrefix apart.)
//
// A resource server needs far less of the database than the server
// does, and is often run in more places, so give it a database role of
// its own with just that, rather than the server's: SELECT on the
// server's access_tokens, revocations and schema_migrations (for
// CheckSchema) tables, SELECT and INSERT on its replay table, and its
// own TablePrefix's tables (which its Migrate creates, so that once,
// with CREATE on the schema, or by a deployment step). With the
// server's role, a resource server that's compromised could delete a
// revocation or rewrite the server's codes and refresh tokens. Only the
// server sweeps the tables they share: a resource server runs Sweep on
// its own DB alone, since a Sweep with a clock ahead of the server's
// would drop replay digests and revocations the server still needs.
//
// For SQLite, with a driver such as modernc.org/sqlite (pure Go, no
// cgo), open the file in WAL mode with a busy timeout, so readers don't
// wait on writers and a connection waits its turn for the write lock
// instead of failing:
//
//	sql.Open("sqlite", "file:fapigo.db?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
//
// Migrate and CheckSchema refuse a database that isn't in WAL mode:
// without it, a read made while a write commits fails with SQLITE_BUSY
// unless its connection has a busy timeout, and under concurrent
// requests most of them would fail as outages. Options.SQLiteBusyTimeout
// covers this package's writes, which set it on their connection;
// reads get the DSN's busy_timeout, so give the DSN both.
// List busy_timeout first, so it applies to the pragmas after it. On a
// new file, the first connection switches the file to WAL mode (which
// lasts) as it opens, holding the write lock without waiting the busy
// timeout, so a connection another process opens at that moment fails
// with SQLITE_BUSY. Migrate retries that, so every process can run it at
// startup; but run Migrate before anything else uses a new file — or
// create and migrate the file once, from a deployment step, before
// starting the processes that share it.
//
// # Migrations
//
// The schema is versioned, its migrations embedded in the package.
// Nothing migrates implicitly — New doesn't touch the database: Migrate
// applies the migrations the database lacks, each in a transaction,
// once between any number of processes running it at once (a Postgres
// advisory lock; SQLite's write lock, waiting out a new file's switch
// to WAL mode — see Setup). Run it from a deployment step
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
//     per pushed request ever completes;
//   - a CIBA decision is an UPDATE … RETURNING that matches only a
//     pending request, so exactly one is recorded; a poll locks the
//     request's row (an UPDATE … RETURNING that changes nothing), then
//     checks it, records the poll and, for an approval, marks it
//     redeemed, in one transaction, so exactly one poll observes an
//     approval, and the poll interval (slow_down) is checked and
//     recorded atomically;
//   - a relying party's session is consumed by one DELETE … RETURNING,
//     in a transaction that also opens its record, so exactly one
//     Consume of a state returns it;
//   - a pairwise subject is one INSERT … ON CONFLICT DO NOTHING,
//     against the table's primary key (issuer, sector, subject) and its
//     unique (issuer, sector, body), then read back: of concurrent
//     calls for one user and sector exactly one stores its body, and a
//     body is never another user's in the same issuer and sector.
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
// refresh tokens, access tokens, auth_req_ids, request_uri references
// and interaction handles, never the values themselves, and the
// server's request and grant records as opaque blobs.
//
// # Sealing
//
// Options.Sealer seals every record blob the stores write with an AEAD
// — AESGCMSealer (AES-256-GCM), or a Sealer of your own calling a key
// management service; OID4VCgo's verifier.TransactionSealer is the same
// interface, so one sealer value serves both:
//
//	sealer, err := sqlstore.AESGCMSealer(key) // 32 bytes from crypto/rand, kept outside the database
//	db, err := sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{Sealer: sealer})
//
// AESGCMSealer refuses a key that's certainly not random, as FAPIgo's
// other sealers do: one byte repeated (an all-zero placeholder), or all
// printable text (a passphrase, or a hex or base64 key not yet decoded:
// decode it first).
//
// Sealed are the blobs that hold what a copy of the database mustn't
// reveal: pushed requests and interactions' copies of them (the
// authorization request, its claims and PKCE challenge), authorization
// codes' and refresh tokens' grants (the end user, scope, claims and
// consent), opaque access tokens' records (subject, scope, binding and
// claims), and CIBA requests and decisions (the request, a ping
// request's auth_req_id and client notification token — a bearer
// secret the server presents — and the approved grant), and a relying
// party's sessions (the PKCE verifier and nonce it later presents and
// checks). Each is bound, as AEAD additional data, to its table,
// column, row key, client_id (the empty string for a session, whose
// row has none) and the DB's TablePrefix, so a sealed blob copied to
// another row, client, table or prefix fails to open; and to the
// columns of its row that change what it means but never change once
// it's written: its expires_at, an interaction's reference (the pushed
// request completing it consumes), and a CIBA request's handle_hash,
// delivery_mode and poll_interval. So a database writer without the key
// can't make a token or code outlive its expiry, have a user's
// approval through one CIBA handle land on another request, or have an
// interaction consume another pushed request: the blob no longer
// opens. A sealed blob starts with a format byte (3) that no JSON
// record starts with.
//
// Not sealed, since the stores look rows up, consume and sweep them by
// them: keys and digests (which reveal nothing of the values they're
// digests of, though a session's state is the value itself, which the
// authorization request carried in the clear), client IDs, expiry and sweep times, CIBA status, delivery
// mode and poll bookkeeping, replay digests, DPoP nonces, revoked keys,
// pairwise subjects (the issuer, sector, internal subject and body are
// every lookup's keys), and the clients table (public client metadata,
// which the operator edits with SQL; it holds no secret). Sealing gives
// confidentiality, and integrity for each blob and the columns bound to
// it; it doesn't make the database tamper-proof: anyone who can write
// to it can still delete rows (a revocation, or a pending request),
// change the columns that do change — whether a code is redeemed, a
// pushed request consumed, a CIBA request's status — or put back a row
// it held before, such as a refresh token deleted when it was revoked.
// Keep write access to the database as tight as read access.
//
// sqlstore v0.2 and earlier sealed blobs with format byte 2 and
// additional data that bound neither the expiry nor those other
// columns. A store still opens them, without that binding, so a
// database upgraded from v0.2 keeps working. Run DB.SealRecords once
// after upgrading every instance: it re-seals them in the current
// format, binding them like the rest. (Until it has, or they've
// expired, a database writer can still change those columns of their
// rows.) A store of v0.2 can't open a blob sealed in the current format,
// so upgrade every instance sharing a database together: a record one
// upgraded instance seals is unreadable (an outage) to one that isn't
// yet, and rolling back to v0.2 makes the records sealed since
// unreadable.
//
// With a Sealer, a store refuses a blob that isn't sealed, and without
// one, a sealed blob: either is an error wrapping ErrRecordFormat and
// storage.ErrStoreUnavailable, as is a blob sealed under another key or
// altered. To start sealing a database already in use, deploy with
// Options.ReadUnsealed set too, which reads the blobs written before,
// run DB.SealRecords, which seals them in place, then deploy without
// ReadUnsealed: while it's set, anyone who can write to the database
// could plant a blob the Sealer never sealed, so it's for that
// migration only. SealRecords seals every unsealed blob it finds, one
// planted before it ran included, which from then on opens as if the
// server had written it: run it on a database whose contents you
// trust.
//
// Keep the key outside the database — in a secrets manager or a KMS —
// and away from its backups, which is what makes them unreadable
// without it. Losing it makes every sealed record unreadable: clients
// authorize again, as they would once the records expired.
// Changing it does the same for the records sealed under the old one;
// to rotate without that, use RotatingSealer, which seals with the new
// key and opens with either, until the longest-lived record (a refresh
// token) sealed under the old one expires. AESGCMSealer's random nonces
// allow 2^32 seals per key (NIST SP 800-38D), which a busy server can
// reach in weeks: rotate before then — see AESGCMSealer. A resource
// server reading opaque access tokens needs the same Sealer.
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
// server.New, and client.New for Sessions, check under
// AssuranceProduction:
//
//   - Postgres: Durable, AtomicConsume and CrossInstanceConsistent. Rows
//     are committed to the database, the consumes above are atomic
//     statements or row-locked transactions, and every instance sharing
//     the database sees the same rows. Not SerializableRedemption: the
//     stores write at READ COMMITTED isolation, relying on row locks for
//     each key rather than on SERIALIZABLE isolation between keys. Each
//     write is a transaction that asks for READ COMMITTED explicitly, so
//     a database, role or DSN whose default_transaction_isolation is
//     REPEATABLE READ or SERIALIZABLE doesn't turn a lost race (a reused
//     code, a consumed session) into a serialization failure, answered
//     as an outage.
//   - SQLite: Durable, AtomicConsume and SerializableRedemption, since
//     SQLite's transactions are serializable. Not
//     CrossInstanceConsistent: a database file on one host can't back a
//     horizontally scaled deployment, so server.New refuses these stores
//     with server.DeploymentHorizontallyScaled; use them with
//     server.DeploymentSingleInstance.
//
// client.New requires only Durable and AtomicConsume of a session
// store, so it accepts Sessions on either database — except that a
// native app's CallbackBindingDeviceLocalStore refuses a store that
// declares CrossInstanceConsistent, which PostgreSQL's does: use
// SQLite, a file on the device, there.
//
// With Options.Sealer set, the stores whose records it seals —
// Transactions, Grants, AccessTokens, Backchannel and Sessions — also
// declare EncryptedAtRest (but not while ReadUnsealed lets unsealed
// records be read); Clients, Replay, Nonces, Revocation and PairwiseSubjects,
// whose rows are their lookup keys, never do. Nothing in FAPIgo
// requires EncryptedAtRest; encrypting the database's storage as well
// is still worth it.
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
// URL a string. An omitted member is the field's zero value. Nothing in
// the document is silently dropped or altered: a member the version
// doesn't define is refused, as are a member given twice in one object
// (encoding/json would keep the last; a reviewer, or another JSON
// parser, may read the first), a member spelt in another case
// ("ALLOWED_SCOPES", which encoding/json would read as allowed_scopes),
// and text that isn't valid UTF-8 or escapes an unpaired surrogate
// (which would read back as U+FFFD). MarshalClientConfig writes the document from a
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
// and at least RedeemedCodeRetention (an hour) past its own expiry, so
// that a Sweep running while the server issues those tokens can't
// remove it before the server records them, and a revocation until the latest expiry it was recorded with. An
// opaque access token is kept until it expires, and a CIBA request
// until BackchannelExpiredRetention (an hour) after it does, so a
// client that polls it late gets expired_token rather than an unknown
// auth_req_id's invalid_grant. A relying party's session is kept until
// it's consumed or expires. Pairwise subjects are never swept: a user's
// identifier for a sector must stay the same for as long as relying
// parties may hold it.
package sqlstore
