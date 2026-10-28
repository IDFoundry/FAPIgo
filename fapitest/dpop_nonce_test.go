package fapitest_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapitest"
	"github.com/idfoundry/fapigo/server"
)

// concurrentNonceFlows is how many authorization code flows
// TestConcurrentFlowsWithDPoPNonces runs at once through one client.
const concurrentNonceFlows = 24

// TestConcurrentFlowsWithDPoPNonces runs concurrent authorization code
// flows, each followed by a refresh, through one client against a
// server that requires DPoP nonces. Every one must succeed: a nonce is
// valid for its lifetime, not for one use (RFC 9449 §8), so requests in
// flight together can all present the nonce the client holds. Were it
// single-use, all but one of them would be challenged, and those that
// were challenged again on their one retry would fail.
func TestConcurrentFlowsWithDPoPNonces(t *testing.T) {
	h := fapitest.New(t, fapitest.Config{Profile: server.ProfileFAPISecurity, DPoPNonces: true})
	ctx := context.Background()

	// Prime the client's nonce cache, as a running client's would be.
	if _, err := h.RunAuthorizationCodeFlow(ctx, offlineScope); err != nil {
		t.Fatalf("RunAuthorizationCodeFlow: %v", err)
	}

	tokens := make([]client.TokenSet, concurrentNonceFlows)
	errs := make([]error, concurrentNonceFlows)
	var wg sync.WaitGroup
	for i := range concurrentNonceFlows {
		wg.Go(func() { tokens[i], errs[i] = flowAndRefresh(ctx, h) })
	}
	wg.Wait()

	if err := errors.Join(errs...); err != nil {
		t.Fatalf("concurrent flows with DPoP nonces failed:\n%v", err)
	}
	for _, ts := range tokens {
		verifyBoundAccessToken(t, h, ts)
	}
}

// flowAndRefresh runs one authorization code flow and refreshes its
// tokens, returning the refreshed set.
func flowAndRefresh(ctx context.Context, h *fapitest.Harness) (client.TokenSet, error) {
	ts, err := h.RunAuthorizationCodeFlow(ctx, offlineScope)
	if err != nil {
		return client.TokenSet{}, fmt.Errorf("flow: %w", err)
	}
	refreshed, err := h.Client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: ts})
	if err != nil {
		return client.TokenSet{}, fmt.Errorf("refresh: %w", err)
	}
	return refreshed, nil
}
