package sqlstore_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
)

// sweepFixture is one of each kind of row, all expiring a minute after
// t0, except what something still live needs: the pushed request an
// interaction (expiring at five minutes) was begun from, the redeemed
// code whose access token expires at ten, and a key revoked until
// twenty.
type sweepFixture struct {
	d         *sqlstore.DB
	t0        time.Time
	usedCode  [32]byte
	replayUse storage.ReplayUse
}

func newSweepFixture(t *testing.T, dialect sqlstore.Dialect) sweepFixture {
	t.Helper()
	ctx := context.Background()
	f := sweepFixture{d: freshDB(t, dialect), t0: time.Now(), usedCode: sha256.Sum256([]byte("used"))}
	minute := f.t0.Add(time.Minute)
	f.replayUse = storage.ReplayUse{Namespace: "n", Digest: sha256.Sum256([]byte("jti")), ExpiresAt: minute}
	tx, g := f.d.Transactions(), f.d.Grants()
	must(t, tx.CreatePAR(ctx, storage.NewPARRecord{Reference: "begun", ClientID: "c", ExpiresAt: minute}))
	must(t, tx.CreatePAR(ctx, storage.NewPARRecord{Reference: "unbegun", ClientID: "c", ExpiresAt: minute}))
	_, err := tx.BeginAuthorization(ctx, storage.BeginAuthorizationTransaction{Reference: "begun", Handle: "h", HandleExpiresAt: f.t0.Add(5 * time.Minute), Now: f.t0})
	must(t, err)
	must(t, g.CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: f.usedCode, ClientID: "c", ExpiresAt: minute}))
	_, err = g.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: f.usedCode})
	must(t, err)
	must(t, g.RecordIssuedAccessToken(ctx, f.usedCode, "at-1", f.t0.Add(10*time.Minute)))
	must(t, g.CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{CodeHash: sha256.Sum256([]byte("unused")), ClientID: "c", ExpiresAt: minute}))
	must(t, g.CreateRefreshToken(ctx, storage.NewRefreshToken{TokenHash: sha256.Sum256([]byte("rt")), ClientID: "c", ExpiresAt: minute}))
	must(t, f.d.Replay().UseOnce(ctx, f.replayUse))
	must(t, f.d.Nonces().Issue(ctx, storage.NonceIssuance{Nonce: "nonce", ExpiresAt: minute}))
	must(t, f.d.Revocation().Revoke(ctx, "short", minute))
	must(t, f.d.Revocation().Revoke(ctx, "long", minute))
	must(t, f.d.Revocation().Revoke(ctx, "long", f.t0.Add(20*time.Minute)))
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSweep(t *testing.T) {
	forEachDialect(t, func(t *testing.T, dialect sqlstore.Dialect) {
		ctx := context.Background()
		f := newSweepFixture(t, dialect)
		if n, err := f.d.Sweep(ctx, f.t0); err != nil || n != 0 {
			t.Fatalf("Sweep before anything expired = %d, %v, want 0, nil", n, err)
		}
		// The unbegun request, the unused code, the refresh token, the
		// replay digest, the nonce and the short revocation.
		if n, err := f.d.Sweep(ctx, f.t0.Add(2*time.Minute)); err != nil || n != 6 {
			t.Fatalf("Sweep after a minute = %d, %v, want 6, nil", n, err)
		}
		checkSweptAfterAMinute(t, f)
		// The begun request, the used code, the long revocation and the
		// digest recorded again (the completed interaction is gone
		// already).
		if n, err := f.d.Sweep(ctx, f.t0.Add(30*time.Minute)); err != nil || n != 4 {
			t.Fatalf("Sweep after everything expired = %d, %v, want 4, nil", n, err)
		}
		if revoked, err := f.d.Revocation().IsRevoked(ctx, "long"); err != nil || revoked {
			t.Fatalf("IsRevoked(long) after its expiry's sweep = %v, %v, want false, nil", revoked, err)
		}
	})
}

// checkSweptAfterAMinute checks f once rows expiring at a minute are
// swept: what's still needed stays.
func checkSweptAfterAMinute(t *testing.T, f sweepFixture) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.d.Transactions().CompleteAuthorization(ctx, storage.CompleteAuthorizationTransaction{Handle: "h"}); err != nil {
		t.Fatalf("CompleteAuthorization of a live interaction whose request expired = %v, want nil: its request must outlive the sweep", err)
	}
	var reused *storage.AuthorizationCodeAlreadyRedeemedError
	if _, err := f.d.Grants().RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: f.usedCode}); !errors.As(err, &reused) || reused.IssuedAccessTokenKey != "at-1" {
		t.Fatalf("RedeemAuthorizationCode of a reused code whose access token is live = %v, want reuse reporting at-1", err)
	}
	if _, err := f.d.Nonces().Lookup(ctx, storage.NonceLookup{Nonce: "nonce"}); !errors.Is(err, sqlstore.ErrNotFound) {
		t.Fatalf("Lookup of a swept nonce = %v, want ErrNotFound", err)
	}
	if err := f.d.Replay().UseOnce(ctx, f.replayUse); err != nil {
		t.Fatalf("UseOnce of a swept digest = %v, want nil", err)
	}
	for key, want := range map[string]bool{"short": false, "long": true} {
		if revoked, err := f.d.Revocation().IsRevoked(ctx, key); err != nil || revoked != want {
			t.Fatalf("IsRevoked(%s) = %v, %v, want %v, nil", key, revoked, err, want)
		}
	}
}
