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

func TestInteractionLookupContract(t *testing.T) {
	storage.TestInteractionLookupContract(t, func() (storage.TransactionStore, storage.InteractionLookup) {
		store := NewTransactionStore()
		return store, NewInteractionLookup(store)
	})
}

func TestPushedRequestLookupContract(t *testing.T) {
	storage.TestPushedRequestLookupContract(t, func() (storage.TransactionStore, storage.PushedRequestLookup) {
		store := NewTransactionStore()
		return store, NewPushedRequestLookup(store)
	})
}

func TestGrantRegistryContract(t *testing.T) {
	storage.TestGrantRegistryContract(t, func() storage.GrantRegistry { return NewGrantRegistry() })
}

// GrantRegistry honours GrantListing.Key: only that entry is listed,
// not the subject's others.
func TestGrantRegistryListsByKeyAlone(t *testing.T) {
	r := NewGrantRegistry()
	ctx := context.Background()
	expires := time.Now().Add(time.Hour)
	for _, key := range []string{"g1", "g2"} {
		if err := r.RecordGrant(ctx, storage.NewGrantEntry{Key: key, SubjectKey: "s1", ClientID: "c", ExpiresAt: expires}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := r.ListGrants(ctx, storage.GrantListing{SubjectKey: "s1", Now: time.Now(), Key: "g1"})
	if err != nil || len(entries) != 1 || entries[0].Key != "g1" {
		t.Fatalf("ListGrants(s1, key g1) = %+v, %v, want g1 alone", entries, err)
	}
}

func TestBackchannelInboxContract(t *testing.T) {
	storage.TestBackchannelInboxContract(t, func() storage.BackchannelInbox { return NewBackchannelInbox() })
}

func TestPairwiseSubjectEraserContract(t *testing.T) {
	storage.TestPairwiseSubjectEraserContract(t, func() storage.PairwiseSubjectEraser { return NewPairwiseSubjectStore() })
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

// TestBackchannelAuthenticationStoreReportsAnAlreadyDecidedRequest pins
// that memstore wraps storage.ErrBackchannelAuthenticationAlreadyDecided
// for a second decision, so the contract's subtest for it runs rather
// than skips here.
func TestBackchannelAuthenticationStoreReportsAnAlreadyDecidedRequest(t *testing.T) {
	store := NewBackchannelAuthenticationStore()
	ctx := context.Background()
	handleHash := sha256.Sum256([]byte("handle"))
	if err := store.CreateBackchannelAuthentication(ctx, storage.NewBackchannelAuthentication{
		AuthReqIDHash: sha256.Sum256([]byte("auth-req")), HandleHash: handleHash, ClientID: "client-1",
		DeliveryMode: "poll", PollInterval: time.Second, ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("CreateBackchannelAuthentication: %v", err)
	}
	decision := storage.DecideBackchannelAuthentication{HandleHash: handleHash, Status: storage.BackchannelAuthenticationDenied}
	if _, err := store.DecideBackchannelAuthentication(ctx, decision); err != nil {
		t.Fatalf("first DecideBackchannelAuthentication: %v", err)
	}
	if _, err := store.DecideBackchannelAuthentication(ctx, decision); !errors.Is(err, storage.ErrBackchannelAuthenticationAlreadyDecided) {
		t.Fatalf("second DecideBackchannelAuthentication = %v, want it to wrap ErrBackchannelAuthenticationAlreadyDecided", err)
	}
}

// TestBackchannelAuthenticationStoreRefusesDecisionOnUnknownHandle: a
// decision for a handle no request was created with is refused.
func TestBackchannelAuthenticationStoreRefusesDecisionOnUnknownHandle(t *testing.T) {
	store := NewBackchannelAuthenticationStore()
	if _, err := store.DecideBackchannelAuthentication(context.Background(), storage.DecideBackchannelAuthentication{
		HandleHash: sha256.Sum256([]byte("no such handle")), Status: storage.BackchannelAuthenticationApproved,
	}); err == nil {
		t.Fatal("decision on an unknown handle = nil error, want refused")
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

func TestRevocationStoreContract(t *testing.T) {
	storage.TestRevocationStoreContract(t, func() storage.RevocationStore { return NewRevocationStore() })
}

func TestClientRepositoryContract(t *testing.T) {
	storage.TestClientRepositoryContract(t, func(clients []storage.RegisteredClient) storage.ClientRepository {
		return NewClientRepository(clients)
	})
}

func TestPairwiseSubjectStoreContract(t *testing.T) {
	storage.TestPairwiseSubjectStoreContract(t, func() storage.PairwiseSubjectStore { return NewPairwiseSubjectStore() })
}

// TestStoresHaveNoBatchMethods: GrantStore and RevocationStore don't
// implement storage.IssuedTokensRecorder or
// storage.RevocationBatchChecker. The server and resource.Verifier find
// those by type assertion, so a method on the store type would be
// promoted to every wrapper embedding it, and the server would call it
// in place of the wrapper's own RecordIssued* or IsRevoked.
func TestStoresHaveNoBatchMethods(t *testing.T) {
	var grants any = NewGrantStore()
	if _, ok := grants.(storage.IssuedTokensRecorder); ok {
		t.Error("*GrantStore implements storage.IssuedTokensRecorder")
	}
	var revocation any = NewRevocationStore()
	if _, ok := revocation.(storage.RevocationBatchChecker); ok {
		t.Error("*RevocationStore implements storage.RevocationBatchChecker")
	}
}

// GrantStore revokes a revoked grant's refresh tokens itself, so
// TestGrantStoreContract checks it as a storage.GrantRefreshTokenRevoker
// rather than skipping that subtest. A wrapper inheriting the method
// can't accept a token it revoked (see RevokeGrantRefreshTokens), unlike
// the batch methods above.
var _ storage.GrantRefreshTokenRevoker = (*GrantStore)(nil)
