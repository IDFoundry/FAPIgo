package sqlstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// migrationFiles are the schema's migrations, each NNNN_name.sql, in
// order. Each is written once its version has shipped and never edited:
// a change is a new migration.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

// migration is one schema version.
type migration struct {
	version int
	name    string
	sql     string
}

// migrations are migrationFiles, parsed, in version order.
var migrations = mustParseMigrations(migrationFiles)

func mustParseMigrations(files fs.FS) []migration {
	out, err := parseMigrations(files)
	if err != nil {
		panic(err)
	}
	return out
}

// parseMigrations reads files' migrations directory: versions 1, 2, …
// with no gaps.
func parseMigrations(files fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(files, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		version, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil {
			return nil, fmt.Errorf("sqlstore: migration %s: %w", e.Name(), err)
		}
		data, err := fs.ReadFile(files, path.Join("migrations", e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: version, name: e.Name(), sql: string(data)})
	}
	slices.SortFunc(out, func(a, b migration) int { return a.version - b.version })
	for i, m := range out {
		if m.version != i+1 {
			return nil, fmt.Errorf("sqlstore: migration %s: want version %d", m.name, i+1)
		}
	}
	return out, nil
}

// SchemaVersion is the schema version this package's stores need: the
// latest migration.
func SchemaVersion() int { return len(migrations) }

// statements are m's statements for d's dialect and table prefix:
// {{key}} is a case-sensitive text column type, {{blob}} a binary one,
// {{text}} free text, and {name} the table or index name with the
// prefix.
func (d *DB) statements(m migration) []string {
	key, blob := "TEXT", "BLOB" // SQLite compares TEXT bytewise (BINARY)
	if d.dialect == Postgres {
		key, blob = `TEXT COLLATE "C"`, "BYTEA"
	}
	// Comments are whole lines starting with --; statements end with ;.
	var lines []string
	for _, line := range strings.Split(m.sql, "\n") {
		if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "--") {
			lines = append(lines, line)
		}
	}
	text := strings.NewReplacer("{{key}}", key, "{{blob}}", blob, "{{text}}", "TEXT").Replace(strings.Join(lines, "\n"))
	var out []string
	for _, stmt := range strings.Split(text, ";") {
		if stmt = strings.TrimSpace(stmt); stmt != "" {
			out = append(out, d.q(stmt))
		}
	}
	return out
}

// Migrate brings the database's tables up to SchemaVersion, applying
// each migration it hasn't yet in a transaction of its own. It's safe
// to run from several processes at once: they apply each migration
// once between them (a Postgres advisory lock; SQLite's write lock).
// It refuses a database a newer release of this package has migrated
// further, as CheckSchema does.
//
// Nothing migrates implicitly — New doesn't: run it from a deployment
// step, or at startup before serving, as a role that may create tables.
func (d *DB) Migrate(ctx context.Context) error {
	for _, m := range migrations {
		if err := d.write(ctx, func(q querier) error { return d.apply(ctx, q, m) }); err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
	}
	if err := d.refuseNewer(ctx, d.db); err != nil {
		return fmt.Errorf("sqlstore: migrate: %w", err)
	}
	return nil
}

// apply applies m on q, a transaction, unless it has been already.
func (d *DB) apply(ctx context.Context, q querier, m migration) error {
	if d.dialect == Postgres {
		// Serializes concurrent Migrates of this prefix, before either
		// creates a table.
		if _, err := q.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", d.migrationLockKey()); err != nil {
			return err
		}
	}
	if _, err := q.ExecContext(ctx, d.q("CREATE TABLE IF NOT EXISTS {schema_migrations} (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)")); err != nil {
		return err
	}
	var one int
	switch err := q.QueryRowContext(ctx, d.q("SELECT 1 FROM {schema_migrations} WHERE version = ?"), m.version).Scan(&one); {
	case err == nil:
		return nil // already applied
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	for _, stmt := range d.statements(m) {
		if _, err := q.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", m.name, err)
		}
	}
	_, err := q.ExecContext(ctx, d.q("INSERT INTO {schema_migrations} (version, name, applied_at) VALUES (?, ?, ?)"), m.version, m.name, time.Now().Unix())
	return err
}

// migrationLockKey is the Postgres advisory lock Migrate takes for d's
// table prefix.
func (d *DB) migrationLockKey() int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("fapigo sqlstore migrate " + d.prefix))
	return int64(h.Sum64()) //nolint:gosec // a lock key: wrapping around is fine
}

// appliedVersions returns the versions the database's
// schema_migrations table lists.
func (d *DB) appliedVersions(ctx context.Context, q querier) (map[int]bool, error) {
	rows, err := q.QueryContext(ctx, d.q("SELECT version FROM {schema_migrations}"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	applied := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

// refuseNewer returns an error if the database lists a migration newer
// than SchemaVersion: a newer release migrated it, and this one doesn't
// know what that changed.
func (d *DB) refuseNewer(ctx context.Context, q querier) error {
	applied, err := d.appliedVersions(ctx, q)
	if err != nil {
		return err
	}
	return checkApplied(applied, false)
}

// checkApplied refuses applied when it lists a version newer than
// SchemaVersion, and, with requireAll, when it lacks one of this
// package's migrations.
func checkApplied(applied map[int]bool, requireAll bool) error {
	for v := range applied {
		if v > SchemaVersion() {
			return fmt.Errorf("the database's schema is at version %d, newer than this release of sqlstore knows (%d): upgrade it", v, SchemaVersion())
		}
	}
	if !requireAll {
		return nil
	}
	for _, m := range migrations {
		if !applied[m.version] {
			return fmt.Errorf("migration %s hasn't been applied: run Migrate", m.name)
		}
	}
	return nil
}

// CheckSchema returns an error unless the database's schema is exactly
// the one this package's stores need: every migration applied, and
// none newer than SchemaVersion (a newer release's, whose changes this
// one doesn't know). Call it at startup, where Migrate is run
// separately, to fail fast rather than on the first request.
func (d *DB) CheckSchema(ctx context.Context) error {
	applied, err := d.appliedVersions(ctx, d.db)
	if err != nil {
		return fmt.Errorf("sqlstore: check schema (has Migrate run?): %w", err)
	}
	if err := checkApplied(applied, true); err != nil {
		return fmt.Errorf("sqlstore: check schema: %w", err)
	}
	return nil
}
