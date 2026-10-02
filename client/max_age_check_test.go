package client_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/storage"
)

// TestCompleteAuthorizationChecksAuthTimeAgainstMaxAge covers OIDC Core
// §3.1.3.7 rule 13 on the client: with max_age requested, the ID token
// must carry auth_time, no older than max_age allows.
func TestCompleteAuthorizationChecksAuthTimeAgainstMaxAge(t *testing.T) {
	for _, tc := range []struct {
		name      string
		hasMaxAge bool
		maxAge    time.Duration
		authAgo   time.Duration // zero: no auth_time claim
		wantErr   bool
	}{
		{name: "within max_age", hasMaxAge: true, maxAge: 5 * time.Minute, authAgo: time.Minute},
		{name: "older than max_age", hasMaxAge: true, maxAge: 5 * time.Minute, authAgo: 10 * time.Minute, wantErr: true},
		{name: "no auth_time with max_age", hasMaxAge: true, maxAge: 5 * time.Minute, wantErr: true},
		{name: "max_age=0, just authenticated", hasMaxAge: true, authAgo: time.Second},
		{name: "no max_age, no auth_time", hasMaxAge: false},
		{name: "no max_age, long ago", hasMaxAge: false, authAgo: 48 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, as, _ := newTestClient(t, false)
			if tc.authAgo != 0 {
				as.idTokenAuthTime = time.Now().Add(-tc.authAgo)
			}
			ctx := context.Background()
			session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{
				Scope: []string{"openid", "accounts"}, MaxAge: tc.maxAge, HasMaxAge: tc.hasMaxAge,
			})
			if err != nil {
				t.Fatalf("BeginAuthorization: %v", err)
			}
			_, err = c.CompleteAuthorization(ctx, client.AuthorizationCallback{
				RawQuery: as.callbackFor(t, session.Handle().String(), "auth-code-123", ""), Session: session.Handle(),
			})
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("CompleteAuthorization: %v", err)
				}
				return
			}
			var cerr *client.Error
			if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInvalidResponse {
				t.Fatalf("CompleteAuthorization = %v, want invalid_response", err)
			}
		})
	}
}

// recordDroppingSessionStore is a SessionStore that doesn't persist
// NewSession.Record, as a store written before it existed wouldn't.
type recordDroppingSessionStore struct{ inner *fakeSessionStore }

func (s recordDroppingSessionStore) Create(ctx context.Context, session storage.NewSession) error {
	session.Record = nil
	return s.inner.Create(ctx, session)
}

func (s recordDroppingSessionStore) Consume(ctx context.Context, c storage.SessionConsumption) (storage.ConsumedSession, error) {
	return s.inner.Consume(ctx, c)
}

// TestHandleAuthorizationResponseRefusesSessionWithoutRecord covers a
// session store that drops NewSession.Record: the callback is refused,
// rather than processed without the checks the record carries.
func TestHandleAuthorizationResponseRefusesSessionWithoutRecord(t *testing.T) {
	c, as, _ := newTestClientWith(t, false, func(_ *client.Config, d *client.Dependencies) {
		d.Sessions = recordDroppingSessionStore{inner: newFakeSessionStore()}
	})
	ctx := context.Background()
	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{"openid", "accounts"}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	_, err = c.HandleAuthorizationResponse(ctx, client.AuthorizationCallback{
		RawQuery: as.callbackFor(t, session.Handle().String(), "auth-code-123", ""), Session: session.Handle(),
	})
	var cerr *client.Error
	if !errors.As(err, &cerr) || cerr.Code() != client.ErrorInternal {
		t.Fatalf("HandleAuthorizationResponse(session without record) = %v, want internal", err)
	}
	// The cause tells a store implementer what to fix.
	if !strings.Contains(err.Error(), "must persist NewSession.Record") {
		t.Errorf("error = %q, want it to say the store must persist NewSession.Record", err)
	}
}
