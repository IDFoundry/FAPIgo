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
// A resource server in a process of its own, which builds
// resource.Dependencies itself, needs both DBs, and the shortest path
// is the wrong one: the same rsDB for everything, whose Revocation reads
// a table the server never writes, so a grant the server revokes is
// never revoked there, with nothing failing. Take its stores from
// ResourceServer instead, which takes each from the right DB and
// refuses two on one TablePrefix:
//
//	serverDB, err := sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{Sealer: sealer}) // the server's tables
//	rsDB, err := sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{TablePrefix: "fapigo_rs_"})
//	err = rsDB.Migrate(ctx)
//	stores, err := sqlstore.ResourceServer(serverDB, rsDB)
//	deps := resource.Dependencies{
//		AccessTokens: resource.OpaqueAccessTokens{Store: stores.AccessTokens, Issuer: issuer, Audience: audience}, // or JWTAccessTokens
//		Replay:       stores.Replay,
//		Revocation:   stores.Revocation,
//		Nonces:       stores.Nonces,
//		// ...
//	}
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
//     request's row (SELECT … FOR UPDATE on PostgreSQL), then checks
//     it, records the poll and, for an approval, marks it redeemed, in
//     one transaction, so exactly one poll observes an approval, and
//     the poll interval (slow_down) is checked and recorded atomically;
//   - a relying party's session is consumed by one DELETE … RETURNING,
//     in a transaction that also opens its record, so exactly one
//     Consume of a state returns it;
//   - a pairwise subject is one INSERT … ON CONFLICT DO NOTHING,
//     against the table's primary key (issuer, sector, subject) and its
//     unique (issuer, sector, body), then read back: of concurrent
//     calls for one user and sector exactly one stores its body, and a
//     body is never another user's in the same issuer and sector (a
//     returning user's body, which never changes, is read without the
//     INSERT).
//
// On PostgreSQL a write that is one statement runs on its own, in the
// implicit transaction PostgreSQL commits it in (autocommit): if its
// context is cancelled while the reply is in flight, the change may be
// committed though the caller sees an error. That fails closed: the
// request fails with server_error, and a code the statement spent, or
// a replay digest it recorded, refuses a retry (a revocation it
// recorded stays recorded); nothing is ever applied twice.
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
// — AESGCMSealer (AES-256-GCM), or a Sealer of your own, local and fast
// (see Performance and scaling); OID4VCgo's verifier.TransactionSealer
// is the same interface, so one sealer value serves both:
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
// ReadUnsealed. SealRecords reads each table in key order, so a row an
// instance still without the Sealer writes during a pass (in a rolling
// deploy, say) can land behind its cursor and stay unsealed, and once
// ReadUnsealed is cleared it is refused (failing closed): run a final
// SealRecords after every instance seals, before clearing ReadUnsealed.
// While ReadUnsealed is set, anyone who can write to the database
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
// reach in weeks, or days: rotate before then — see AESGCMSealer, and
// Performance and scaling for the cadence. The budget is the key's,
// not an instance's: every instance sealing with the key, and every
// other store or service sealing with it too (a relying party's
// sessions, a co-hosted service given the same key), draws on the one
// 2^32, so count their seals together. A resource server reading
// opaque access tokens needs the same Sealer.
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
//     write of several statements is a transaction that asks for READ
//     COMMITTED explicitly, so a database, role or DSN whose
//     default_transaction_isolation is REPEATABLE READ or SERIALIZABLE
//     doesn't turn a lost race (a reused code, a consumed session) into
//     a serialization failure, answered as an outage. A write of one
//     statement runs on its own, without BEGIN and COMMIT; one that
//     fails with a serialization failure has changed nothing, and is run
//     again in such a transaction. Where Migrate or CheckSchema finds a
//     default other than READ COMMITTED, every write runs in one from
//     the start.
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
// storage.NewRegisteredClient refuses. ResolveClient reads the row on
// every call, so a change takes effect on the next request (unless
// Options.ClientCacheTTL is set: see there), and builds the client
// again only when the row has changed; a row
// that doesn't make a valid client is answered as an outage
// (ErrClientConfig, wrapping storage.ErrStoreUnavailable), not as an
// unknown client.
//
// The document holds the client's keys too, so the clients table is the
// one registry of clients and their keys: a jwks_uri member (an https
// URL) or an inline jwks member (a JWK Set), never both (RFC 7591 §2),
// which PutWithKeys and MarshalClientConfigWithKeys write
// (ClientKeyRegistration) and DB.ClientKeys serves as
// server.Dependencies.ClientKeys:
//
//	clientKeys, err := db.ClientKeys(fetcher) // fapihttp.Client, hardened for production; nil if no client has a jwks_uri
//	deps.ClientKeys = clientKeys
//	err = db.Clients().PutWithKeys(ctx, cfg, sqlstore.ClientKeyRegistration{JWKS: jwks})
//
// A client added or rekeyed at runtime authenticates with its new keys
// on its next request, with no restart (with Options.ClientCacheTTL
// set, a rekey through another DB takes up to the TTL). Put registers a client with no
// keys, replacing any (for a client that signs nothing, such as one
// authenticating with a TLS client certificate). These members are
// new in sqlstore v0.4: an earlier release refuses a row that has them.
//
// Put checks a client only as storage.NewRegisteredClient does. What
// only the server can check — Rich Authorization Request types its
// Config.RAR doesn't register, AllowedResources while it accepts no
// resource indicators, CIBA ping delivery without a notifier — is
// server.Server.CheckClientRegistration's: run it on each client after
// Put, and on every client at startup, since the operator's tooling
// writing the table may hold no *server.Server. All lists them:
//
//	for client, err := range db.Clients().All(ctx) {
//		if err == nil {
//			err = srv.CheckClientRegistration(client)
//		}
//		if err != nil {
//			return err
//		}
//	}
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
//
// Sweep deletes in batches, each a short transaction of its own, so a
// large backlog doesn't hold up the stores' writes; on PostgreSQL,
// instances sweeping the same tables at once leave each other's batches
// alone (an advisory lock, keyed by the TablePrefix and the schema the
// tables are in, so tenants with a schema each in one database don't
// share it), and on SQLite a Sweep that deleted rows
// then truncates the write-ahead log, when nothing is using it: best
// effort, never waiting on a reader or writer, so a backup or a
// long-running read doesn't hold up writes behind it.
//
// # Performance and scaling
//
// The figures here are indicative, not a benchmark: measured on
// sqlstore v0.4, and for v0.5's changes on a prototype of them with the
// same harness, on one 8-core Xeon host shared with other load (so ±30%), with PostgreSQL 17
// limited to 4 vCPUs and 2 GB in a Docker VM, SQLite through
// modernc.org/sqlite, Go 1.26 and pgx through database/sql, and a
// FAPI 2.0 login with private_key_jwt, DPoP with
// server nonces, opaque access tokens and a refresh token. Measure your
// own deployment; pg_stat_statements counts what each request runs.
//
// On PostgreSQL the database is the limit, not the server instances,
// which keep nothing between requests: under load the database's CPU
// saturated first in every scenario, and adding instances added nothing
// (244, 246 and 224 logins a second with 1, 2 and 4 of them). Its cost
// is statements and commits, not query plans: every hot statement is
// an index lookup by key, touching a few pages. A write that is one
// statement runs on its own, without BEGIN and COMMIT, on a database
// whose default isolation is READ COMMITTED (see Capabilities), which v0.4
// didn't. What a request costs:
//
//   - a pushed authorization request: 6 statements (12 on v0.4), 3 of
//     them writes;
//   - a whole login (pushed request, authorization and code exchange):
//     31 statements (55 on v0.4) and 14 write transactions, 7 of the
//     statements reads of the client's row and 5 writes of replay
//     digests;
//   - a refresh: 9 statements (15 on v0.4), 3 of them writes (refresh
//     tokens aren't rotated, as FAPI 2.0 requires);
//   - a resource server's check of an opaque access token: about 4
//     reads (the token and its grant's revocations), and one write for a
//     DPoP proof's replay digest;
//   - a CIBA poll of a pending request: 4 statements, 1 write
//     transaction.
//
// Two methods beyond the storage interfaces take a little more off,
// with a fapigo that looks for them (storage.RevocationBatchChecker and
// storage.IssuedTokensRecorder) and makes the separate calls otherwise:
// RevocationStore.IsAnyRevoked checks all of a token's or grant's
// revocation keys, current and legacy forms, in one statement rather
// than one each, on every token request and resource-server check; and
// GrantStore.RecordIssuedTokens records a code exchange's access and
// refresh tokens in one UPDATE of the code's row rather than two.
//
// Options.ClientCacheTTL takes the client's row out of most of those:
// with 5 seconds, a login was 24 statements, a pushed request 4 and a
// refresh 7, at the cost of a client's change made through another
// instance (or outside this package) taking up to that long to reach
// this one. Without it, the row is still read on every lookup, but
// parsed again only when it changed.
//
// On v0.4 the 4-vCPU database saturated at about 380 logins, 1,600
// pushed requests, 1,300 refreshes or 9,000 opaque access-token lookups
// (with their revocation checks) a second, at about 19 ms of its CPU
// per login and 5 per refresh, inflated by the VM's costly system
// calls: dedicated hardware should need less per statement. v0.5's
// changes, on the same setup, took about a quarter off the database's
// CPU per login, and raised logins a second by about a third and
// pushed requests and refreshes by about half. Size the database's CPU
// from your request rates and those costs; it scales with cores, not
// with server instances.
//
// Size the connection pool explicitly, on every instance: database/sql's
// defaults are wrong for this load. Its MaxIdleConns of 2 keeps at most
// two connections idle, closing any other a request gives back, so most
// requests open a new one (a new backend process, and pgx preparing its
// statements again): at 32 concurrent logins that cut throughput from 214 to 47 a
// second and raised the database's CPU per login from 19 to 85 ms. Its
// unlimited MaxOpenConns let 128 concurrent callers exceed
// max_connections (100), and about one call in ten failed as an outage.
// So:
//
//	sqlDB.SetMaxOpenConns(n)
//	sqlDB.SetMaxIdleConns(n)                   // the same n: never fewer idle than open
//	sqlDB.SetConnMaxLifetime(30 * time.Minute) // so connections move after a failover
//	sqlDB.SetConnMaxIdleTime(5 * time.Minute)  // so a quiet instance gives them back
//
// with n times the instances, plus every other client of the database
// and headroom for maintenance, below max_connections. n needn't be
// large: the connections busy at once are about the requests a second
// times the round trips each makes times the round-trip time (plus the
// database's own time), so 2,000 code exchanges a second at about a
// dozen round trips of 0.4 ms keep about 10 busy. Once the database's CPU
// saturates, a larger pool only moves the queue into the database: 50
// and 200 connections per instance did the same, while 10 capped logins
// at about 110 a second. (A pool of one never deadlocks; it serializes.)
//
// Many instances, or many processes with a pool each (resource servers
// too), can exceed max_connections however each is sized: put PgBouncer
// in front in transaction mode. Every operation here that runs more
// than one statement is one transaction (Migrate's advisory lock is a
// transaction's too), so transaction pooling keeps their guarantees.
// pgx's default prepares and caches named statements per connection,
// which transaction pooling breaks; set default_query_exec_mode in the
// DSN to exec, or cache_describe, neither of which names statements:
//
//	postgres://fapigo@pgbouncer:6432/fapigo?default_query_exec_mode=exec
//
// The package's tests pass that way through PgBouncer 1.26 in
// transaction mode, but not with pgx's default and PgBouncer's own
// prepared-statement support (max_prepared_statements), where a
// statement that once failed to prepare (CheckSchema before Migrate)
// kept its name taken. (statement_cache_capacity sizes only the default
// mode's cache.) PgBouncer refuses startup parameters it doesn't track,
// so set default_transaction_isolation and the like on the role or
// database, not in the DSN, and add search_path, if the DSN sets it, to
// track_extra_parameters.
//
// A login writes roughly 70 KB of WAL (45 KB for its pushed request and
// authorization, 27 KB for the code exchange, measured with the stores'
// SQL replayed by pgbench), mostly full-page images: digests as primary
// keys scatter writes across each index. wal_compression (lz4 or zstd)
// shrinks those images, and a longer checkpoint_timeout writes fewer of
// them. Keep the hot tables (replay, access_tokens, refresh_tokens and
// their indexes) in memory if you can: with 5 GB of rows against 512 MB
// of shared_buffers, throughput fell by 6–25%, with no change of plan.
// The tables are delete-heavy, so a lower autovacuum_vacuum_scale_factor
// on replay, access_tokens and interactions keeps them vacuumed.
//
// Sweep's cost grows with the rows it deletes, so run it often enough
// that each run deletes a modest number, thousands or tens of thousands
// per table rather than millions: a login leaves four or five replay
// digests, so at 300 logins a second a five-minute interval leaves
// about 400,000 replay rows for each run. The costly case is a backlog,
// the first Sweep after sweeping was off or failing. v0.4 deleted each
// table in one statement: on PostgreSQL, 6.9 million expired rows took
// 135 s, stalling every other writer on the WAL for 2 to 4 s at a time;
// on SQLite, 500,000 rows in one table held the write lock for 9 s.
// Sweep now deletes in batches, which takes longer in all but leaves
// the other writes running: with 2 million expired rows on PostgreSQL,
// the slowest 1% of concurrent writes took 23 to 99 ms rather than
// about 300, and with 400,000 on SQLite 64 ms rather than 3.5 s. One
// instance, or one scheduled job, is enough to sweep: a run deletes
// what every instance wrote, and on PostgreSQL a run that finds another
// instance's batch on the same tables in progress stops, leaving the
// rest to that one (see DB.Sweep for what that leaves).
//
// SQLite has one writer, and with the DSN in Setup each write
// transaction waits for an fsync: synchronous is FULL, SQLite's default
// (and modernc.org/sqlite's), and SQLite has no group commit. A login
// is 13 write transactions, a refresh 3, a resource server's check of a
// DPoP-bound token 1, so the ceiling is roughly one write transaction
// per fsync latency (plus about 0.1 ms), from every process and DB on
// the file together: on a Linux VM's disk, about 760 a second, which
// made 13 logins a second one at a time and 17 at 32 concurrent (p99
// 2.2 s). Faster
// storage raises that in proportion; a larger pool doesn't (DB
// serializes its writes; reads scale with cores, so keep MaxOpenConns
// at GOMAXPROCS or more). Don't size it on macOS: fsync there doesn't
// flush the drive's cache, so the same test ran thousands of writes a
// second, and 33 a second with fullfsync, which does.
//
// synchronous(NORMAL) in the DSN takes the fsync off each commit (in
// WAL mode, SQLite syncs at checkpoints instead): measured, 286 logins
// a second where FULL made 17. A process crash then loses nothing and
// the database is never corrupted, but an operating-system crash or a
// power loss loses the last commits before it, and here a lost commit
// can be a security event, not just lost data: a replay digest (a DPoP
// proof or client assertion accepted again while it's fresh), a code's
// redemption (the code redeemed again), a consumed pushed request or
// session, or a revocation the server reported done (a revoked grant's
// tokens accepted again). Whether that window is acceptable is the
// operator's call; the stores declare Durable whatever the DSN says.
//
// Keep to one writing process per file. Writes from another — a
// resource server in a process of its own, say, recording DPoP proofs'
// replay digests in the server's file — wait on SQLite's busy handler,
// which polls rather than queues: two and four processes added no
// throughput (3,235, 3,188 and 2,851 writes a second in all), took p99
// latency from 22 ms to as much as 1.2 s and starved one process to
// half its share, and a long Sweep can outlast another process's busy
// timeout, failing its requests with server_error. Several DBs writing
// to one file in one process behave the same way, since each queues
// only its own writes (one that writes rarely, such as a resource
// server's DB for its DPoP nonces, costs little). Run a resource server
// in the server's process (serverresource.NewVerifier), or use
// PostgreSQL.
//
// Under continuous reads the WAL file grows past the database (58 MB
// for a 15.5 MB database in 20 s), and a large Sweep left one of
// 157 MB; SQLite reuses the file but never shrinks it, unless the DSN
// sets journal_size_limit, to which it truncates the file after a
// checkpoint:
//
//	sql.Open("sqlite", "file:fapigo.db?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=journal_size_limit(67108864)")
//
// Move to PostgreSQL for more than one server instance (server.New
// refuses SQLite with server.DeploymentHorizontallyScaled), for a
// writer in another process, or for more write transactions than the
// disk's fsync allows.
//
// The Sealer runs on the request path for every sealed record: Seal for
// each one written, Open for each one read, some of them inside a write
// transaction (the Open in a consume, while it holds the row's lock,
// and on SQLite the one write lock). It must be local and fast:
// AESGCMSealer seals and opens a 600-byte record in about 1.2 µs, and
// turning sealing on made no measurable difference. Don't call a key
// management service per record, which would hold a pooled connection
// and its locks for the call, and on SQLite every other write too (2 ms
// a call inside the write lock is at most 500 writes a second): take
// the key from the KMS, or unwrap it with one, once at startup, and
// pass it to AESGCMSealer.
//
// AESGCMSealer's random nonces allow 2^32 seals per key (about 4.3
// billion; see AESGCMSealer), so rotate with RotatingSealer at a
// cadence set by your seal rate. A login seals five records (its pushed
// request, the interaction's copy, the code's grant, an opaque access
// token and a refresh token; fewer with JWT access tokens or no refresh
// token), a refresh one (its opaque access token), a CIBA request two
// and its decision one, and a relying party's session one, if it shares
// the key. Count every instance's seals, and any other service's that
// uses the key, against the one budget. So 2,000 logins a second are 10,000 seals a second, which
// reach 2^32 in five days, and 1,000 seals a second in seven weeks;
// rotating at a quarter of the budget, as AESGCMSealer suggests, is
// every 30 hours or so at 10,000 seals a second, and every 12 days at
// 1,000. Each previous key stays in the RotatingSealer until the
// refresh tokens it sealed expire, and an old record's Open tries the
// current key and then each previous one in turn: cheap with AES-GCM,
// but daily rotation under a 90-day refresh token lifetime keeps 90
// keys.
package sqlstore
