# sqlstore

Durable stores for a FAPIgo Authorization Server's `server.Dependencies`,
in PostgreSQL or SQLite through `database/sql`. It's a Go module of its
own, `github.com/idfoundry/fapigo/sqlstore`, so FAPIgo itself takes no
database driver: bring the one you use.

The package documentation ([doc.go](doc.go)) is the reference: setup,
migrations, atomicity, capabilities, the clients table and sweeping.
This page is the short version.

## Setup

```go
import (
	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib" // or _ "modernc.org/sqlite"

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
```

SQLite (for example [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite),
pure Go, no cgo) needs WAL mode and a busy timeout:

```go
sql.Open("sqlite", "file:fapigo.db?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
```

## What each database declares

| | Durable | AtomicConsume | CrossInstanceConsistent | SerializableRedemption | EncryptedAtRest |
|---|---|---|---|---|---|
| PostgreSQL | yes | yes | yes | no (READ COMMITTED, row locks per key) | no |
| SQLite | yes | yes | no: one host's file | yes | no |

So `server.New` accepts the PostgreSQL stores under
`AssuranceProduction` with either `Deployment`, and the SQLite stores
with `DeploymentSingleInstance` only.

## Running it

- **Migrations** are embedded and versioned. `Migrate` applies the
  missing ones and is safe to run from several processes at once; nothing
  migrates implicitly. `Options.TablePrefix` (default `fapigo_`)
  prefixes every table, so these tables can share a database, and a
  `*sql.DB`, with OID4VCgo's sqlstore (`oid4vc_`).
- **Sweeping**: stores never delete expired rows. Call
  `db.Sweep(ctx, time.Now())` every few minutes.
- **Clients** are rows the operator manages: a `client_id` and a
  versioned JSON configuration, written with `Clients().Put` or
  `MarshalClientConfig`. See the package documentation's Clients
  section for the document's members.
- **Not yet provided**: the access token store (opaque access tokens),
  the CIBA store, the pairwise subject store, the client's session
  store and record sealing.

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
