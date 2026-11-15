package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"
)

// lookupHarness is beginPaymentInteraction's harness rebuilt over a
// memstore TransactionStore, with Dependencies.InteractionLookup reading
// it, and the interaction begun on it.
func lookupHarness(t *testing.T) (harness, server.InteractionRequired) {
	t.Helper()
	base, _ := beginPaymentInteraction(t)
	deps := base.deps
	transactions := memstore.NewTransactionStore()
	deps.Transactions = transactions
	deps.InteractionLookup = memstore.NewInteractionLookup(transactions)
	srv, err := server.New(base.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	h := base
	h.server, h.deps = srv, deps
	pushResult, err := srv.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: plainFormParameters(t, h.clientAssertion(t), map[string]string{
			"authorization_details": `[{"type":"payment","actions":["approve"],"amount":"SGD 500.00"}]`,
			"login_hint":            "alice@example.com",
		})},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := srv.BeginAuthorization(context.Background(), server.BeginAuthorizationRequest{RequestURI: pushResult.RequestURI.String(), ClientID: testClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	required, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("action = %T, want InteractionRequired", action)
	}
	return h, required
}

func wantLookupError(t *testing.T, err error, code server.ErrorCode) {
	t.Helper()
	var serverErr *server.Error
	if !errors.As(err, &serverErr) || serverErr.Code() != code {
		t.Fatalf("LookupInteraction error = %v, want a %s *Error", err, code)
	}
}

// TestLookupInteractionReturnsBegunInteraction: the lookup gives back
// exactly what BeginAuthorization returned, as often as asked, and
// leaves the interaction to complete once; after that, it's gone.
func TestLookupInteractionReturnsBegunInteraction(t *testing.T) {
	h, required := lookupHarness(t)
	ctx := context.Background()
	for i := range 2 {
		got, err := h.server.LookupInteraction(ctx, required.Handle)
		if err != nil {
			t.Fatalf("LookupInteraction #%d: %v", i+1, err)
		}
		if !reflect.DeepEqual(got, required.Interaction) {
			t.Fatalf("LookupInteraction #%d = %+v, want %+v", i+1, got, required.Interaction)
		}
	}
	details, err := extension.RARGet(required.Interaction.AuthorizationDetails, paymentRARDef)
	if err != nil || len(details) != 1 {
		t.Fatalf("RARGet = %d details, %v", len(details), err)
	}
	subject, authCtx := rarSubjectAndAuthCtx(t, h.now)
	result, err := h.server.CompleteAuthorization(ctx, server.CompleteAuthorizationRequest{
		Handle: required.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: required.Interaction.Scope, AuthorizationDetails: []json.RawMessage{mustMarshal(t, details[0].Fields)},
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	if _, ok := result.(server.AuthorizationRedirect); !ok {
		t.Fatalf("CompleteAuthorization after lookups = %T, want AuthorizationRedirect", result)
	}
	_, err = h.server.LookupInteraction(ctx, required.Handle)
	wantLookupError(t, err, server.ErrorInvalidRequest)
}

func TestLookupInteractionNeedsTheDependency(t *testing.T) {
	h, required := beginPaymentInteraction(t)
	_, err := h.server.LookupInteraction(context.Background(), required.Handle)
	wantLookupError(t, err, server.ErrorServerError)
	if !strings.Contains(err.Error(), "Dependencies.InteractionLookup") {
		t.Errorf("LookupInteraction error = %v, want it to name the dependency", err)
	}
}

func TestLookupInteractionUnknownHandle(t *testing.T) {
	h, _ := lookupHarness(t)
	// Begun on another server's store: unknown to this one.
	_, other := beginPaymentInteraction(t)
	_, err := h.server.LookupInteraction(context.Background(), other.Handle)
	wantLookupError(t, err, server.ErrorInvalidRequest)
}

func TestLookupInteractionExpired(t *testing.T) {
	h, required := lookupHarness(t)
	deps := h.deps
	deps.Clock = fixedClock{now: h.now.Add(h.cfg.Limits.InteractionLifetime)}
	later, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	_, err = later.LookupInteraction(context.Background(), required.Handle)
	wantLookupError(t, err, server.ErrorInvalidRequest)
}

// expiryIgnoringLookup returns its interaction whatever txn.Now is,
// breaking InteractionLookup's contract: the server's own expiry check
// still refuses it.
type expiryIgnoringLookup struct{ pending storage.PendingInteraction }

func (l expiryIgnoringLookup) LookupAuthorization(context.Context, storage.LookupAuthorizationTransaction) (storage.PendingInteraction, error) {
	return l.pending, nil
}

func TestLookupInteractionBackstopsExpiry(t *testing.T) {
	h, required := lookupHarness(t)
	deps := h.deps
	deps.InteractionLookup = expiryIgnoringLookup{storage.PendingInteraction{ClientID: testClientID, ExpiresAt: h.now}}
	srv, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	_, err = srv.LookupInteraction(context.Background(), required.Handle)
	wantLookupError(t, err, server.ErrorInvalidRequest)
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("LookupInteraction error = %v, want it to say the handle expired", err)
	}
}

// failingLookup fails every lookup with err.
type failingLookup struct{ err error }

func (l failingLookup) LookupAuthorization(context.Context, storage.LookupAuthorizationTransaction) (storage.PendingInteraction, error) {
	return storage.PendingInteraction{}, l.err
}

// TestLookupInteractionStoreOutage: a store that couldn't answer is a
// server error, not an unknown handle the login UI would show as an
// expired session.
func TestLookupInteractionStoreOutage(t *testing.T) {
	h, required := lookupHarness(t)
	deps := h.deps
	deps.InteractionLookup = failingLookup{fmt.Errorf("backend down: %w", storage.ErrStoreUnavailable)}
	srv, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	_, err = srv.LookupInteraction(context.Background(), required.Handle)
	wantLookupError(t, err, server.ErrorServerError)
}

func TestLookupInteractionClientNoLongerRegistered(t *testing.T) {
	h, required := lookupHarness(t)
	delete(h.clients.clients, testClientID)
	_, err := h.server.LookupInteraction(context.Background(), required.Handle)
	wantLookupError(t, err, server.ErrorUnauthorizedClient)
}

// declaredLookup is an InteractionLookup declaring caps.
type declaredLookup struct {
	failingLookup
	caps storage.Capabilities
}

func (l declaredLookup) Capabilities() storage.Capabilities { return l.caps }

func TestProductionChecksInteractionLookup(t *testing.T) {
	for name, tc := range map[string]struct {
		lookup storage.InteractionLookup
		want   string
	}{
		"memstore":    {memstore.NewInteractionLookup(memstore.NewTransactionStore()), "interaction_lookup must implement storage.StoreAssurance"},
		"not durable": {declaredLookup{caps: storage.Capabilities{}}, "interaction_lookup must declare Durable"},
		"durable":     {declaredLookup{caps: storage.Capabilities{Durable: true}}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			err := productionNew(t, func(deps *server.Dependencies) { deps.InteractionLookup = tc.lookup })
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("New(production, %s lookup) = %v, want nil", name, err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("New(production, %s lookup) = %v, want %q", name, err, tc.want)
			}
		})
	}
}

// TestLookupInteractionClientStoreOutage: a client repository that
// couldn't answer is a server error, as at BeginAuthorization, not a
// client no longer registered.
func TestLookupInteractionClientStoreOutage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		storeErr error
		cancel   bool
	}{
		{"store unavailable", fmt.Errorf("db: %w", storage.ErrStoreUnavailable), false},
		{"request cancelled", errors.New("lookup interrupted"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, required := lookupHarness(t)
			h.clients.err = tc.storeErr
			_, err := h.server.LookupInteraction(lookupContext(t, tc.cancel), required.Handle)
			checkServerError(t, err, server.ErrorServerError, 500)
		})
	}
}

// TestLookupInteractionRefusesAnUnreadableRecord: a stored request the
// server can't decode, as from a store that altered it, isn't shown.
func TestLookupInteractionRefusesAnUnreadableRecord(t *testing.T) {
	h, required := lookupHarness(t)
	deps := h.deps
	deps.InteractionLookup = expiryIgnoringLookup{storage.PendingInteraction{
		ClientID: testClientID, Request: json.RawMessage(`{"not":"a request record"}`), ExpiresAt: h.now.Add(time.Minute),
	}}
	srv, err := server.New(h.cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if _, err := srv.LookupInteraction(context.Background(), required.Handle); err == nil {
		t.Fatal("LookupInteraction(unreadable record) = nil error, want error")
	}
}
