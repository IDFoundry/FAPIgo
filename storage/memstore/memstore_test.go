package memstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

func TestTransactionStoreContract(t *testing.T) {
	storage.TestTransactionStoreContract(t, func() storage.TransactionStore {
		return NewTransactionStore()
	})
}

func TestGrantStoreContract(t *testing.T) {
	storage.TestGrantStoreContract(t, func() storage.GrantStore {
		return NewGrantStore()
	})
}

func TestReplayStoreContract(t *testing.T) {
	storage.TestReplayStoreContract(t, func() storage.ReplayStore {
		return NewReplayStore()
	})
}

func TestAccessTokenStoreContract(t *testing.T) {
	storage.TestAccessTokenStoreContract(t, func() storage.AccessTokenStore {
		return NewAccessTokenStore()
	})
}

func TestNonceStoreContract(t *testing.T) {
	storage.TestNonceStoreContract(t, func() storage.NonceStore {
		return NewNonceStore()
	})
}

func TestBackchannelAuthenticationStoreContract(t *testing.T) {
	storage.TestBackchannelAuthenticationStoreContract(t, func() storage.BackchannelAuthenticationStore {
		return NewBackchannelAuthenticationStore()
	})
}

func TestSessionStoreContract(t *testing.T) {
	storage.TestSessionStoreContract(t, func() storage.SessionStore {
		return NewSessionStore()
	})
}

func TestRevocationStoreNotRevokedByDefault(t *testing.T) {
	s := NewRevocationStore()

	revoked, err := s.IsRevoked(context.Background(), "jti-1")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Fatalf("IsRevoked(never-revoked jti) = true, want false")
	}
}

func TestRevocationStoreRevokeThenIsRevoked(t *testing.T) {
	s := NewRevocationStore()

	if err := s.Revoke(context.Background(), "jti-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	revoked, err := s.IsRevoked(context.Background(), "jti-1")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatalf("IsRevoked(revoked jti) = false, want true")
	}

	revoked, err = s.IsRevoked(context.Background(), "jti-2")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Fatalf("IsRevoked(different jti) = true, want false")
	}
}

func newTestClient(t *testing.T, id fapi.ClientID) storage.RegisteredClient {
	t.Helper()
	c, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       id,
		RedirectURIs:             []fapi.RegisteredRedirectURI{"https://rp.example/callback"},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"openid"},
	})
	if err != nil {
		t.Fatalf("storage.NewRegisteredClient: %v", err)
	}
	return c
}

func TestClientRepositoryResolvesRegisteredClient(t *testing.T) {
	client := newTestClient(t, "client-1")
	repo := NewClientRepository([]storage.RegisteredClient{client})

	got, err := repo.ResolveClient(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("ResolveClient: %v", err)
	}
	if got.ID() != "client-1" {
		t.Fatalf("ID() = %q, want %q", got.ID(), "client-1")
	}
}

func TestClientRepositoryRejectsUnknownClient(t *testing.T) {
	repo := NewClientRepository([]storage.RegisteredClient{newTestClient(t, "client-1")})

	if _, err := repo.ResolveClient(context.Background(), "client-2"); err == nil {
		t.Fatal("ResolveClient(unknown) = nil error, want error")
	}
}

func TestClientRepositoryEmpty(t *testing.T) {
	repo := NewClientRepository(nil)

	if _, err := repo.ResolveClient(context.Background(), "client-1"); err == nil {
		t.Fatal("ResolveClient on empty repository = nil error, want error")
	}
}

// TestGrantStoreReportsTheReusedCodesClient covers ClientID on
// AuthorizationCodeAlreadyRedeemedError, which the server uses to revoke
// only when the code's own client reuses it.
func TestGrantStoreReportsTheReusedCodesClient(t *testing.T) {
	store := NewGrantStore()
	ctx := context.Background()
	hash := sha256.Sum256([]byte("code"))
	if err := store.CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{
		CodeHash: hash, ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: hash}); err != nil {
		t.Fatal(err)
	}
	_, err := store.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: hash})
	var reused *storage.AuthorizationCodeAlreadyRedeemedError
	if !errors.As(err, &reused) || reused.ClientID != "client-1" {
		t.Fatalf("reuse error = %v, want ClientID client-1", err)
	}
}

// TestBackchannelAuthenticationStoreRefusesAnotherClientsPoll pins that
// memstore checks PollBackchannelAuthentication.ClientID, so the
// contract's subtest for it runs rather than skips here.
func TestBackchannelAuthenticationStoreRefusesAnotherClientsPoll(t *testing.T) {
	store := NewBackchannelAuthenticationStore()
	ctx := context.Background()
	authReqIDHash := sha256.Sum256([]byte("auth-req"))
	if err := store.CreateBackchannelAuthentication(ctx, storage.NewBackchannelAuthentication{
		AuthReqIDHash: authReqIDHash, HandleHash: sha256.Sum256([]byte("handle")), ClientID: "client-1",
		DeliveryMode: "poll", PollInterval: time.Second, ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("CreateBackchannelAuthentication: %v", err)
	}
	if _, err := store.PollBackchannelAuthentication(ctx, storage.PollBackchannelAuthentication{
		AuthReqIDHash: authReqIDHash, Now: time.Now(), ClientID: "client-2",
	}); err == nil {
		t.Fatal("poll by another client = nil error, want refused")
	}
}

// TestGrantStoreRefusesAnotherClientsCode pins that memstore checks
// AuthorizationCodeRedemption.ClientID, so the contract's subtest for it
// runs rather than skips here.
func TestGrantStoreRefusesAnotherClientsCode(t *testing.T) {
	store := NewGrantStore()
	ctx := context.Background()
	hash := sha256.Sum256([]byte("code"))
	if err := store.CreateAuthorizationCode(ctx, storage.NewAuthorizationCode{
		CodeHash: hash, ClientID: "client-1", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	if _, err := store.RedeemAuthorizationCode(ctx, storage.AuthorizationCodeRedemption{CodeHash: hash, ClientID: "client-2"}); err == nil {
		t.Fatal("redemption by another client = nil error, want refused")
	}
}
