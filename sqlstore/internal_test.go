package sqlstore

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// Times round-trip through their BIGINT column exactly, the zero time
// included; times beyond its range are clamped.
func TestNanos(t *testing.T) {
	now := time.Now()
	for _, tm := range []time.Time{{}, now, now.Add(time.Nanosecond), time.Unix(0, 0), time.Unix(-1, 0)} {
		if got := timeOf(nanos(tm)); !got.Equal(tm) {
			t.Errorf("timeOf(nanos(%v)) = %v", tm, got)
		}
	}
	far := time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := timeOf(nanos(far)); !got.Equal(maxNanos) {
		t.Errorf("timeOf(nanos(year 3000)) = %v, want %v", got, maxNanos)
	}
	early := time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := timeOf(nanos(early)); !got.IsZero() {
		t.Errorf("timeOf(nanos(year 1600)) = %v, want the zero time", got)
	}
}

func TestParseMigrationsRefusesGapsAndBadNames(t *testing.T) {
	for name, files := range map[string]fstest.MapFS{
		"gap":      {"migrations/0001_a.sql": {}, "migrations/0003_c.sql": {}},
		"no 1":     {"migrations/0002_b.sql": {}},
		"bad name": {"migrations/first.sql": {}},
		"no dir":   {},
	} {
		if _, err := parseMigrations(files); err == nil {
			t.Errorf("%s: parseMigrations = nil error, want an error", name)
		}
	}
	got, err := parseMigrations(fstest.MapFS{"migrations/0002_b.sql": {Data: []byte("B")}, "migrations/0001_a.sql": {Data: []byte("A")}})
	if err != nil || len(got) != 2 || got[0].sql != "A" || got[1].version != 2 {
		t.Fatalf("parseMigrations = %+v, %v", got, err)
	}
}

// The embedded migrations parse, and each statement is templated for
// both dialects: no placeholder or table name left unexpanded.
func TestStatementsAreTemplated(t *testing.T) {
	for _, dialect := range []Dialect{Postgres, SQLite} {
		d := &DB{dialect: dialect, prefix: "p_"}
		for _, m := range migrations {
			for _, stmt := range d.statements(m) {
				if strings.ContainsAny(stmt, "{}") {
					t.Errorf("%v %s: statement not templated: %s", dialect, m.name, stmt)
				}
			}
		}
	}
	if d := (&DB{dialect: Postgres, prefix: "p_"}); d.q("SELECT ? FROM {t} WHERE a = ?") != "SELECT $1 FROM p_t WHERE a = $2" {
		t.Errorf("q = %q", d.q("SELECT ? FROM {t} WHERE a = ?"))
	}
}
