# sqlstore

Durable stores for a FAPIgo Authorization Server's `server.Dependencies`,
and for a relying party's `client.Dependencies.Sessions`, in PostgreSQL
or SQLite through `database/sql`. It's a Go module of its
own, `github.com/idfoundry/fapigo/sqlstore`, so FAPIgo itself takes no
database driver: bring the one you use.

The package documentation ([doc.go](doc.go)) is the reference: setup,
migrations, atomicity, sealing, capabilities, the clients table,
sweeping, and performance and scaling. This page is the short version. For a running deployment,
[examples/linked-accounts](../examples/linked-accounts) keeps an
Authorization Server's, a resource server's and two relying parties'
stores in one SQLite file, each under its own table prefix.

## Setup

```go
import (
	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib" // or _ "modernc.org/sqlite"

	"github.com/idfoundry/fapigo/pairwise"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/sqlstore"
)

sqlDB, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
db, err := sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{})
if err := db.Migrate(ctx); err != nil { … } // or CheckSchema, if a deployment step migrates

deps := server.Dependencies{
	Clients:      db.Clients(),
	Transactions: db.Transactions(),
	Grants:       db.Grants(),
	Replay:       db.Replay(),
	Nonces:       db.Nonces(),
	Revocation:   db.Revocation(),
	// …
}

// For the features that need one:
deps.AccessTokens = server.OpaqueAccessTokens{Store: db.AccessTokens()} // opaque access tokens (JWTs need none)
deps.Backchannel = db.Backchannel()                                    // CIBA
deps.PairwiseSubjects, err = pairwise.NewMapping(db.PairwiseSubjects()) // random, mapped pairwise subs

// A relying party (package client):
clientDeps := client.Dependencies{
	Sessions: db.Sessions(),
	// …
}
```

SQLite (for example [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite),
pure Go, no cgo) needs WAL mode and a busy timeout:

```go
sql.Open("sqlite", "file:fapigo.db?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
```

`Migrate` and `CheckSchema` refuse a SQLite database that isn't in WAL
mode: without it, a read made while a write commits fails with
`SQLITE_BUSY`, and under concurrent requests most fail as outages.
`Options.SQLiteBusyTimeout` covers sqlstore's writes; reads get the
DSN's `busy_timeout`, so give the DSN both.

On a new file, the first connection switches it to WAL mode as it
opens, and a connection another process opens at that moment fails with
`SQLITE_BUSY`. `Migrate` waits that out, so run it first in each
process (or once, from a deployment step, before starting them) before
anything else uses the file.

## Sealing records

Set `Options.Sealer` to encrypt every record blob the stores write —
pushed requests, grants behind codes and refresh tokens, opaque access
tokens, CIBA requests and decisions, a relying party's sessions — with
an AEAD bound to its row:

```go
sealer, err := sqlstore.AESGCMSealer(key) // 32 random bytes, from a secrets manager or KMS, never the database
db, err := sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{Sealer: sealer})
```

`AESGCMSealer` refuses a key that's certainly not random: one byte
repeated (an all-zero placeholder), or all printable text (a
passphrase, or a hex or base64 key not yet decoded: decode it first).

A sealed blob moved to another row, client, table or table prefix,
altered, or opened under another key is refused (`ErrRecordFormat`, as
an outage), as is one whose row's expiry (or an interaction's pushed
request, or a CIBA request's handle, delivery mode or interval) was
changed. Lookup keys and digests, client IDs, times, CIBA status,
replay digests, nonces, revocations, pairwise subjects and the clients
table stay readable: the stores look rows up by them. The `Sealer`
interface is OID4VCgo's `verifier.TransactionSealer`, so one sealer
serves both.

To start sealing a database in use: deploy with `Sealer` and
`ReadUnsealed: true`, run `db.SealRecords(ctx)`, then deploy without
`ReadUnsealed`. `SealRecords` trusts what it finds, so run it on a
database whose contents you trust. Losing the key makes sealed records
unreadable. `AESGCMSealer` allows 2^32 seals per key (random nonces,
NIST SP 800-38D), which a busy server reaches in weeks, or days (see
[Performance and scaling](#performance-and-scaling)): rotate before then
with `sqlstore.RotatingSealer(newSealer, oldSealer)`, which seals
with the new key and opens with either until the old one's records
expire. See the package documentation's Sealing section.

### Upgrading from v0.2

Blobs sealed by v0.2 and earlier (format byte 2) didn't bind their
row's expiry and the other columns above. They still open, so an
upgraded database keeps working; run `db.SealRecords(ctx)` once after
upgrading every instance to re-seal them in the current format (byte 3)
and bind them too. Upgrade every instance sharing a database at once: a
v0.2 instance can't open what an upgraded one seals, and rolling back
to v0.2 leaves the records sealed since unreadable.

## Upgrading from v0.3

v0.4 refuses configurations v0.3 accepted:

- **A sealing key that isn't random.** `AESGCMSealer` returns an error
  for a key that's one byte repeated (all zeros, say) or all printable
  text: a passphrase, or a hex or base64 key passed without decoding
  it. Such a key gave no confidentiality, and let anyone who could
  guess it and write to the database forge sealed records. Generate 32
  bytes with `crypto/rand`, and decode an encoded key before passing
  it:

  ```go
  key, err := hex.DecodeString(os.Getenv("FAPIGO_SEAL_KEY")) // `openssl rand -hex 32`
  sealer, err := sqlstore.AESGCMSealer(key)
  ```

  The records sealed under the old key open only under it, and
  `AESGCMSealer` no longer takes it. Either let them go (as with a lost
  key, clients authorize again), or open them with a `Sealer` of your
  own over the old key, in `RotatingSealer(newSealer, oldKeySealer)`,
  until the longest-lived of them (a refresh token) expires. It reads
  `AESGCMSealer`'s format, a 12-byte nonce then the ciphertext:

  ```go
  type oldKeySealer struct{ aead cipher.AEAD } // cipher.NewGCM(aes.NewCipher(oldKey))

  func (s oldKeySealer) Seal(plaintext, additionalData []byte) ([]byte, error) {
  	return nil, errors.New("the old key only opens")
  }

  func (s oldKeySealer) Open(sealed, additionalData []byte) ([]byte, error) {
  	if len(sealed) < s.aead.NonceSize() {
  		return nil, errors.New("sealed data is too short")
  	}
  	n := s.aead.NonceSize()
  	return s.aead.Open(nil, sealed[:n], sealed[n:], additionalData)
  }
  ```

  `RotatingSealer` also refuses two `AESGCMSealer`s over the same key.
- **A SQLite database not in WAL mode.** `Migrate` and `CheckSchema`
  return an error unless `PRAGMA journal_mode` is `wal`. Without it, a
  read made while a write commits failed with `SQLITE_BUSY`, answered
  as an outage: under concurrent requests, most of them. Open the file
  with both pragmas, `busy_timeout` first:

  ```go
  sql.Open("sqlite", "file:fapigo.db?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
  ```

  The first connection opened that way switches the file to WAL mode,
  which lasts.

## What each database declares

| | Durable | AtomicConsume | CrossInstanceConsistent | SerializableRedemption | EncryptedAtRest |
|---|---|---|---|---|---|
| PostgreSQL | yes | yes | yes | no (READ COMMITTED, row locks per key) | with a `Sealer`* |
| SQLite | yes | yes | no: one host's file | yes | with a `Sealer`* |

\* Transactions, Grants, AccessTokens, Backchannel and Sessions only,
and not while `ReadUnsealed` is set; Clients, Replay, Nonces,
Revocation and PairwiseSubjects never declare it.

So `server.New` accepts the PostgreSQL stores under
`AssuranceProduction` with either `Deployment`, and the SQLite stores
with `DeploymentSingleInstance` only. `client.New` accepts `Sessions` on
either under `AssuranceProduction`, except that a native app's
`CallbackBindingDeviceLocalStore` refuses PostgreSQL's, a store shared
between instances: use SQLite there.

## Running it

- **Migrations** are embedded and versioned. `Migrate` applies the
  missing ones and is safe to run from several processes at once; nothing
  migrates implicitly. `Options.TablePrefix` (default `fapigo_`)
  prefixes every table, so these tables can share a database, and a
  `*sql.DB`, with OID4VCgo's sqlstore (`oid4vc_`).
- **Sweeping**: stores never delete expired rows. Call
  `db.Sweep(ctx, time.Now())` every few minutes. CIBA requests are kept
  an hour past their expiry, so a late poll gets `expired_token`;
  sessions until they're consumed or expire; pairwise subjects are
  never swept.
- **Resource servers** reading opaque access tokens or revocations use
  the server's tables (`AccessTokens()`, `Revocation()`, and `Replay()`,
  whose digests each role namespaces), through a DB with the same
  `TablePrefix` and `Sealer`. Their DPoP nonce store is the exception:
  `Nonces()` from a DB with a `TablePrefix` of its own, never the
  server's, whose nonces it would then accept. A resource server in a
  process of its own takes all four from
  `sqlstore.ResourceServer(serverDB, rsDB)`, which reads each from the
  right DB: one whose `Revocation()` came from its own prefix, as its
  `Nonces()` must, never sees the server's revocations, and nothing
  fails.

  ```go
  stores, err := sqlstore.ResourceServer(serverDB, rsDB) // rsDB: TablePrefix "fapigo_rs_", say
  deps := resource.Dependencies{
  	AccessTokens: resource.OpaqueAccessTokens{Store: stores.AccessTokens, Issuer: issuer, Audience: audience}, // or JWTs
  	Replay:       stores.Replay,
  	Revocation:   stores.Revocation,
  	Nonces:       stores.Nonces,
  	// …
  }
  ```

  Give a resource server a database role of its own: `SELECT` on the
  server's `access_tokens`, `revocations` and `schema_migrations`,
  `SELECT`/`INSERT` on `replay`, and its own prefix's tables; and let
  only the server `Sweep` the tables they share.
- **Clients** are rows the operator manages: a `client_id` and a
  versioned JSON configuration, written with `Clients().Put` or
  `MarshalClientConfig`. See the package documentation's Clients
  section for the document's members.
- **Client keys** live in the same document, as a `jwks_uri` or an
  inline `jwks`, so the clients table is the one registry: write them
  with `Clients().PutWithKeys` (or `MarshalClientConfigWithKeys`) and
  serve them with `db.ClientKeys(fetcher)` as
  `server.Dependencies.ClientKeys`. A client added or rekeyed at
  runtime authenticates on its next request, without a restart.

  ```go
  deps.ClientKeys, err = db.ClientKeys(fetcher) // a hardened fapihttp.Client; nil if no client has a jwks_uri
  err = db.Clients().PutWithKeys(ctx, cfg, sqlstore.ClientKeyRegistration{JWKS: jwks})
  ```
- **Check each client against the server**: `Put` checks only what
  `storage.NewRegisteredClient` does. Run
  `srv.CheckClientRegistration` on every client at startup and after
  each `Put`, for what only the server knows (RAR types it doesn't
  register, `AllowedResources` without resource indicators, CIBA ping
  without a notifier); `Clients().All(ctx)` lists them.

## Performance and scaling

The package documentation's "Performance and scaling" section has the
detail and the measurements behind this summary. They were taken on
sqlstore v0.4 on one shared host (PostgreSQL 17 on 4 vCPUs in a Docker
VM), so read them as indicative and measure your own deployment.

- **PostgreSQL is the limit, not the server instances.** A whole login
  (PAR, authorization, code exchange) was 55 statements and 14 write
  transactions; a refresh 15 and 3. The 4-vCPU database saturated at
  about 380 logins, 1,300 refreshes or 9,000 opaque-token lookups a
  second, and 1, 2 or 4 server instances made no difference. Size the
  database's CPU for your request rates.
- **Size the pool on every instance.** `database/sql`'s default
  `MaxIdleConns` of 2 churns connections: in testing it cut logins from
  214 to 47 a second. Set `SetMaxIdleConns` equal to `SetMaxOpenConns`,
  plus `SetConnMaxLifetime` and `SetConnMaxIdleTime`, and keep
  `MaxOpenConns` × instances (plus headroom) below `max_connections`. A
  modest pool is enough: busy connections ≈ requests/s × round trips ×
  round-trip time.
- **PgBouncer** in transaction mode works: every multi-statement
  operation is one transaction. Set `default_query_exec_mode=exec` (or
  `cache_describe`) in the pgx DSN, since pgx's default named prepared
  statements don't survive transaction pooling, and set
  `default_transaction_isolation` and similar on the role, not the DSN.
- **WAL**: digests as primary keys make most WAL full-page images
  (roughly 70 KB per login): turn on `wal_compression`.
- **Sweep** often enough that each run deletes a modest number of rows
  (thousands to tens of thousands per table, not millions), from one
  instance or a scheduled job. A large backlog is the expensive case: on
  v0.4, millions of rows stalled other writers for seconds.
- **SQLite** has one writer, and with the documented DSN
  (`synchronous=FULL`) every write transaction waits for an fsync. A
  login is 13 of them, so on a Linux VM disk it managed 13–17 logins a
  second. Don't size it on macOS, whose `fsync` doesn't flush the drive.
  `_pragma=synchronous(NORMAL)` reached 286 a second, but an OS crash or
  power loss then drops the last commits, which here can mean a replay
  digest, a code's redemption or a revocation forgotten: your call. Keep
  one writing process per file (a resource server in its own process
  recording DPoP replay digests counts), add
  `_pragma=journal_size_limit(67108864)` to cap the WAL file, and move to
  PostgreSQL for more instances or more writes than the disk allows.
- **The `Sealer` must be local and fast**: it runs on every sealed write
  and read, sometimes inside a transaction. Don't call a KMS per record;
  unwrap the key once at startup and use `AESGCMSealer`.
- **Rotate the key by seal volume.** `AESGCMSealer` allows 2^32 seals
  per key. A login seals five records and a refresh one, so 2,000
  logins a second (10,000 seals) reach the limit in five days; rotating
  with `RotatingSealer` at a quarter of it is every 30 hours or so.

## Tests

The tests run each store's `storage` contract suite against SQLite, and
against PostgreSQL too when `FAPIGO_SQLSTORE_POSTGRES_DSN` is set (in
CI, where the `CI` environment variable is set, it must be):

```sh
docker run --rm -d --name sqlstore-pg -p 127.0.0.1:55432:5432 -e POSTGRES_PASSWORD=x postgres:17-alpine
FAPIGO_SQLSTORE_POSTGRES_DSN='postgres://postgres:x@127.0.0.1:55432/postgres?sslmode=disable' go test -race ./...
docker stop sqlstore-pg
```

Each run works in a schema of its own, dropped when it ends, and each
test in tables of its own.

## Versioning

This module is released and tagged on its own (`sqlstore/vX.Y.Z`). Its
`go.mod` requires the FAPIgo release it's built against; the `replace`
there serves development in this repository only, and CI also tests the
module against the required release with it dropped.
