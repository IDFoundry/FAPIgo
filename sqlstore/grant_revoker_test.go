package sqlstore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// grantKey is a refresh token's grant key shaped like the server's
// (storage.NewRefreshToken.GrantKeys): a base64url SHA-256 digest.
func grantKey(name string) string {
	sum := sha256.Sum256([]byte("sqlstore test grant key\x00" + name))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newIndexedToken stores a refresh token named name through g, expiring
// at expires and indexed by keys, returning its digest.
func newIndexedToken(t *testing.T, g storage.GrantStore, name string, expires time.Time, keys ...string) [32]byte {
	t.Helper()
	hash := sha256.Sum256([]byte("refresh token " + name))
	must(t, g.CreateRefreshToken(context.Background(), storage.NewRefreshToken{
		TokenHash: hash, ClientID: "c", Grant: secretGrant, ExpiresAt: expires, GrantKeys: keys,
	}))
	return hash
}

// productionIssuer is the issuer productionServer and productionClient
// configure.
const productionIssuer = "https://as.example"

// serverRefreshTokenHash is the digest a server of issuer stores
// refreshToken under: the SHA-256 of a fixed prefix, the length-prefixed
// issuer and the token. It follows the server package's own
// (unexported) derivation; a test checking a token is gone from the
// store under it first checks the token is there under it.
func serverRefreshTokenHash(issuer, refreshToken string) [32]byte {
	return sha256.Sum256([]byte("fapigo refresh token\x00" + strconv.Itoa(len(issuer)) + ":" + issuer + refreshToken))
}

// redeemable reports whether g redeems the refresh token stored under
// hash, failing the test on an error other than an unknown token.
func redeemable(t *testing.T, g storage.GrantStore, hash [32]byte) bool {
	t.Helper()
	_, err := g.RedeemRefreshToken(context.Background(), storage.RefreshTokenRedemption{TokenHash: hash})
	if err != nil && !errors.Is(err, sqlstore.ErrNotFound) {
		t.Fatalf("RedeemRefreshToken = %v, want nil or ErrNotFound", err)
	}
	return err == nil
}

// revokeGrantTokens is g's RevokeGrantRefreshTokens(key), which must
// succeed, its hashes sorted.
func revokeGrantTokens(t *testing.T, g storage.GrantStore, key string) [][32]byte {
	t.Helper()
	revoked, err := g.(storage.GrantRefreshTokenRevoker).RevokeGrantRefreshTokens(context.Background(), key)
	must(t, err)
	slices.SortFunc(revoked, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	return revoked
}

// sortedHashes is hashes, sorted as revokeGrantTokens sorts its.
func sortedHashes(hashes ...[32]byte) [][32]byte {
	slices.SortFunc(hashes, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	return hashes
}

// Every store a DB hands out for server.Dependencies.Grants, sealed or
// not, is a storage.GrantRefreshTokenRevoker, so the server revokes a
// grant's refresh tokens through it, and TestGrantStoreContract checks
// the method on each.
func TestEveryGrantStoreRevokesGrantRefreshTokens(t *testing.T) {
	p := newPlace(t, sqlstore.SQLite)
	for name, d := range map[string]*sqlstore.DB{"plain": p.migrated(), "sealed": p.migratedWith(sqlstore.Options{Sealer: testSealer(t)})} {
		for store, g := range map[string]storage.GrantStore{"Grants": d.Grants(), "BatchingGrants": d.BatchingGrants()} {
			if _, ok := g.(storage.GrantRefreshTokenRevoker); !ok {
				t.Errorf("%s %s() isn't a storage.GrantRefreshTokenRevoker", name, store)
			}
		}
	}
}

// A refresh token and its grant keys are written in one transaction: an
// index row that can't be written leaves no token, nor the index rows
// written before it, and a token that can't be written leaves no index
// row.
func TestRefreshTokenAndItsGrantKeysAreOneWrite(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		g := p.migrated().Grants()
		_, db := p.open()
		hash := sha256.Sum256([]byte("one write"))
		keys := []string{grantKey("a"), grantKey("b")}
		slices.Sort(keys) // the order the index rows are written in
		rawExec(t, p, db, "INSERT INTO "+p.prefix+"refresh_token_grants (grant_key, token_hash, sweep_after) VALUES (?, ?, 0)", keys[1], hash[:])
		err := g.CreateRefreshToken(ctx, storage.NewRefreshToken{TokenHash: hash, ClientID: "c", Grant: secretGrant, ExpiresAt: time.Now().Add(time.Hour), GrantKeys: keys})
		if !errors.Is(err, storage.ErrStoreUnavailable) {
			t.Fatalf("CreateRefreshToken with an index row already there = %v, want an outage", err)
		}
		if redeemable(t, g, hash) || countRows(t, p, db, "refresh_token_grants") != 1 {
			t.Fatal("a CreateRefreshToken whose last index row failed left its token, or its first index row, stored")
		}
		rawExec(t, p, db, "DELETE FROM "+p.prefix+"refresh_token_grants")
		stored := newIndexedToken(t, g, "stored", time.Now().Add(time.Hour))
		err = g.CreateRefreshToken(ctx, storage.NewRefreshToken{TokenHash: stored, ClientID: "c", Grant: secretGrant, ExpiresAt: time.Now().Add(time.Hour), GrantKeys: keys})
		if err == nil {
			t.Fatal("CreateRefreshToken of a token already stored = nil error, want an error")
		}
		if n := countRows(t, p, db, "refresh_token_grants"); n != 0 {
			t.Fatalf("a CreateRefreshToken that failed on its token left %d index rows, want none", n)
		}
	})
}

// Revoking a grant's refresh tokens revokes, and reports, those indexed
// by its key and only those, whichever of a token's keys it is: another
// grant's stay redeemable, and a token already revoked isn't reported
// again.
func TestRevokeGrantRefreshTokensByEitherKey(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		g := freshDB(t, dialect).Grants()
		later := time.Now().Add(time.Hour)
		grant1, code1, grant2, code2 := grantKey("grant 1"), grantKey("code 1"), grantKey("grant 2"), grantKey("code 2")
		both1 := newIndexedToken(t, g, "both keys 1", later, grant1, code1)
		both2 := newIndexedToken(t, g, "both keys 2", later, grant2, code2)
		grantOnly := newIndexedToken(t, g, "grant key only", later, grant1)
		other := newIndexedToken(t, g, "another grant's", later, grantKey("other"))
		none := newIndexedToken(t, g, "no keys", later)
		for _, step := range []struct {
			key     string
			revoked [][32]byte // gone from then on, and reported
			stayed  [][32]byte
		}{
			{code1, [][32]byte{both1}, [][32]byte{both2, grantOnly, other, none}},
			{grant2, [][32]byte{both2}, [][32]byte{grantOnly, other, none}},
			{grant1, [][32]byte{grantOnly}, [][32]byte{other, none}},
			{code2, nil, [][32]byte{other, none}},
		} {
			if got := revokeGrantTokens(t, g, step.key); !slices.Equal(got, sortedHashes(step.revoked...)) {
				t.Fatalf("RevokeGrantRefreshTokens = %d tokens, want %d", len(got), len(step.revoked))
			}
			checkRedeemable(t, g, false, step.revoked...)
			checkRedeemable(t, g, true, step.stayed...)
		}
	})
}

// checkRedeemable fails the test unless g redeems each of hashes
// exactly when want.
func checkRedeemable(t *testing.T, g storage.GrantStore, want bool, hashes ...[32]byte) {
	t.Helper()
	for _, hash := range hashes {
		if got := redeemable(t, g, hash); got != want {
			t.Errorf("refresh token %x redeemable = %v, want %v", hash[:4], got, want)
		}
	}
}

// Sweep removes a refresh token's index rows once the token expires —
// those of a token revoked before then too — and not before.
func TestSweepRemovesGrantIndexRowsWithTheirToken(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		d := p.migrated()
		_, db := p.open()
		g := d.Grants()
		t0 := time.Now()
		newIndexedToken(t, g, "expiring", t0.Add(time.Minute), grantKey("a"), grantKey("b"))
		revoked := newIndexedToken(t, g, "revoked", t0.Add(time.Minute), grantKey("c"))
		newIndexedToken(t, g, "live", t0.Add(time.Hour), grantKey("d"))
		must(t, g.RevokeRefreshToken(ctx, revoked))
		if n, err := d.Sweep(ctx, t0); err != nil || n != 0 {
			t.Fatalf("Sweep before anything expired = %d, %v, want 0, nil", n, err)
		}
		if n := countRows(t, p, db, "refresh_token_grants"); n != 4 {
			t.Fatalf("index rows before their tokens expire = %d, want 4", n)
		}
		// The expiring token and its two index rows, and the revoked
		// token's index row.
		if n, err := d.Sweep(ctx, t0.Add(2*time.Minute)); err != nil || n != 4 {
			t.Fatalf("Sweep after a minute = %d, %v, want 4, nil", n, err)
		}
		if n := countRows(t, p, db, "refresh_token_grants"); n != 1 {
			t.Fatalf("index rows after a minute's Sweep = %d, want the live token's 1", n)
		}
	})
}

// A grant key the server can't have derived — empty, over 64 bytes, or
// outside the base64url alphabet — is refused by CreateRefreshToken as
// the caller's fault, not an outage, with nothing stored, and has no
// tokens to revoke, without asking the database; a key given twice is
// stored once.
func TestGrantKeysOutsideTheirBound(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		p := newPlace(t, dialect)
		g := p.migrated().Grants()
		_, db := p.open()
		for _, key := range []string{"", strings.Repeat("a", 65), "a=", "a+b", "a/b", "a.b", "a\x00b", "\xff", "é"} {
			checkGrantKeyRefused(t, g, key)
		}
		if n := countRows(t, p, db, "refresh_token_grants"); n != 0 {
			t.Fatalf("refused grant keys left %d index rows, want none", n)
		}
		longest := strings.Repeat("Az09-_", 10) + "Az09"
		twice := newIndexedToken(t, g, "twice", time.Now().Add(time.Hour), longest, longest)
		if n := countRows(t, p, db, "refresh_token_grants"); n != 1 {
			t.Fatalf("a grant key given twice = %d index rows, want 1", n)
		}
		if got := revokeGrantTokens(t, g, longest); !slices.Equal(got, [][32]byte{twice}) {
			t.Fatalf("RevokeGrantRefreshTokens(a 64-byte key) = %d tokens, want the 1 stored", len(got))
		}
	})
}

// checkGrantKeyRefused checks that g refuses a refresh token with key
// among its grant keys, as the caller's fault and storing nothing, and
// revokes no token for it.
func checkGrantKeyRefused(t *testing.T, g *sqlstore.GrantStore, key string) {
	t.Helper()
	ctx := context.Background()
	hash := sha256.Sum256([]byte("refused " + key))
	err := g.CreateRefreshToken(ctx, storage.NewRefreshToken{TokenHash: hash, ClientID: "c", ExpiresAt: time.Now().Add(time.Hour), GrantKeys: []string{grantKey("fine"), key}})
	if err == nil || errors.Is(err, storage.ErrStoreUnavailable) {
		t.Errorf("CreateRefreshToken(grant key %q) = %v, want a refusal", key, err)
	}
	if redeemable(t, g, hash) {
		t.Errorf("CreateRefreshToken(grant key %q) stored the token", key)
	}
	if revoked, err := g.RevokeGrantRefreshTokens(ctx, key); err != nil || len(revoked) != 0 {
		t.Errorf("RevokeGrantRefreshTokens(%q) = %d tokens, %v, want none, nil", key, len(revoked), err)
	}
}

// A refresh token stored before migration 0005, which sqlstore v0.9
// stored with no grant keys, stays redeemable after it, and revocable as
// before. Revoking its grant finds it in no index and leaves it: the
// server's revocation record of the grant is what refuses it.
func TestRefreshTokensStoredBeforeTheGrantIndex(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		p := newPlace(t, dialect)
		d, db := p.open()
		must(t, sqlstore.MigrateThrough(ctx, d, 4))
		kept, revoked := sha256.Sum256([]byte("v0.9 token")), sha256.Sum256([]byte("v0.9 token, revoked"))
		expires := time.Now().Add(time.Hour).UnixNano()
		for _, hash := range [][32]byte{kept, revoked} {
			// sqlstore v0.9's CreateRefreshToken statement.
			rawExec(t, p, db, "INSERT INTO "+p.prefix+"refresh_tokens (token_hash, client_id, record, expires_at, sweep_after) VALUES (?, ?, ?, ?, ?)",
				hash[:], "c", []byte(secretGrant), expires, expires)
		}
		must(t, d.Migrate(ctx))
		must(t, d.CheckSchema(ctx))
		g := d.Grants()
		if got := revokeGrantTokens(t, g, grantKey("their grant")); len(got) != 0 {
			t.Fatalf("RevokeGrantRefreshTokens after the migration = %d tokens, want none: nothing indexed them", len(got))
		}
		if !redeemable(t, g, kept) || !redeemable(t, g, revoked) {
			t.Fatal("a refresh token stored before migration 0005 isn't redeemable after it")
		}
		must(t, g.RevokeRefreshToken(ctx, revoked))
		if !redeemable(t, g, kept) || redeemable(t, g, revoked) {
			t.Fatal("RevokeRefreshToken of a token stored before migration 0005 didn't revoke it alone")
		}
	})
}

// A refresh token row a database writer planted under a key that isn't
// a digest's 32 bytes, and indexed by a grant key, is deleted when the
// grant's tokens are revoked, but not reported as one of them.
func TestRevokeGrantRefreshTokensSkipsAKeyThatIsNoDigest(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		p := newPlace(t, dialect)
		g := p.migrated().Grants()
		_, db := p.open()
		short, key := []byte("not a digest"), grantKey("planted")
		rawExec(t, p, db, "INSERT INTO "+p.prefix+"refresh_tokens (token_hash, client_id, record, expires_at, sweep_after) VALUES (?, 'c', ?, 0, 0)", short, []byte(secretGrant))
		rawExec(t, p, db, "INSERT INTO "+p.prefix+"refresh_token_grants (grant_key, token_hash, sweep_after) VALUES (?, ?, 0)", key, short)
		genuine := newIndexedToken(t, g, "genuine", time.Now().Add(time.Hour), key)
		if got := revokeGrantTokens(t, g, key); !slices.Equal(got, [][32]byte{genuine}) {
			t.Fatalf("RevokeGrantRefreshTokens = %d tokens, want the genuine one alone", len(got))
		}
		if n := countRows(t, p, db, "refresh_tokens"); n != 0 {
			t.Fatalf("%d refresh token rows left, want none", n)
		}
	})
}
