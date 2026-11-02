package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// ResourceServer gives a standalone resource server the server's
// revocations, replay table and opaque access tokens, and nonces of its
// own: a grant the server revokes is revoked there, which it isn't
// through the resource server's own DB.
func TestResourceServerStores(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		serverDB := p.migratedWith(sqlstore.Options{Sealer: testSealer(t)})
		ownPlace := newPlace(t, dialect)
		ownPlace.path = p.path
		ownDB := ownPlace.migrated()

		rs, err := sqlstore.ResourceServer(serverDB, ownDB)
		must(t, err)
		expires := time.Now().Add(time.Hour)
		must(t, serverDB.Revocation().Revoke(ctx, "grant:g1", expires))
		wantRevoked(t, "the resource server's Revocation", rs.Revocation, true)
		wantRevoked(t, "the resource server's own DB's Revocation", ownDB.Revocation(), false)

		hash := sha256.Sum256([]byte("opaque access token"))
		must(t, serverDB.AccessTokens().CreateAccessToken(ctx, storage.NewAccessToken{TokenHash: hash, ClientID: "c", ExpiresAt: expires}))
		if _, err := rs.AccessTokens.LookupAccessToken(ctx, storage.AccessTokenLookup{TokenHash: hash}); err != nil {
			t.Errorf("the resource server's AccessTokens can't read the server's token: %v", err)
		}

		must(t, rs.Nonces.Issue(ctx, storage.NonceIssuance{Nonce: "rs-nonce", ExpiresAt: expires}))
		if _, err := serverDB.Nonces().Lookup(ctx, storage.NonceLookup{Nonce: "rs-nonce"}); err == nil {
			t.Error("the server's Nonces finds the resource server's nonce")
		}
		if _, err := ownDB.Nonces().Lookup(ctx, storage.NonceLookup{Nonce: "rs-nonce"}); err != nil {
			t.Errorf("the resource server's own DB doesn't hold its nonce: %v", err)
		}

		used := storage.ReplayUse{Namespace: "resource:dpop", Digest: sha256.Sum256([]byte("jti-1")), ExpiresAt: expires}
		must(t, rs.Replay.UseOnce(ctx, used))
		if err := serverDB.Replay().UseOnce(ctx, used); err == nil {
			t.Error("the resource server's replay digest isn't in the server's replay table")
		}
	})
}

// wantRevoked fails t unless checker reports grant g1 revoked as want.
func wantRevoked(t *testing.T, what string, checker interface {
	IsRevoked(context.Context, string) (bool, error)
}, want bool) {
	t.Helper()
	got, err := checker.IsRevoked(context.Background(), "grant:g1")
	if err != nil || got != want {
		t.Errorf("%s: IsRevoked(a grant the server revoked) = %v, %v, want %v", what, got, err, want)
	}
}

// ResourceServer refuses a nil DB, and nonces on the server's
// TablePrefix: the same DB, or another over the same prefix.
func TestResourceServerRefusals(t *testing.T) {
	p := newPlace(t, sqlstore.SQLite)
	serverDB, sqlDB := p.open()
	samePrefix, err := sqlstore.New(sqlDB, sqlstore.SQLite, sqlstore.Options{TablePrefix: p.prefix})
	must(t, err)
	defaultPrefix, err := sqlstore.New(sqlDB, sqlstore.SQLite, sqlstore.Options{})
	must(t, err)
	defaultPrefix2, err := sqlstore.New(sqlDB, sqlstore.SQLite, sqlstore.Options{TablePrefix: "fapigo_"})
	must(t, err)
	for name, c := range map[string]struct {
		server, own *sqlstore.DB
		want        string
	}{
		"nil server":     {nil, serverDB, "nil DB"},
		"nil own":        {serverDB, nil, "nil DB"},
		"one DB":         {serverDB, serverDB, "TablePrefix of its own"},
		"same prefix":    {serverDB, samePrefix, "TablePrefix of its own"},
		"default prefix": {defaultPrefix, defaultPrefix2, "TablePrefix of its own"},
	} {
		if _, err := sqlstore.ResourceServer(c.server, c.own); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("ResourceServer(%s) = %v, want an error saying %q", name, err, c.want)
		}
	}
}
