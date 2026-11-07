package resource_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/internal/mtls"
	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage"
)

// batchRevocationChecker is a storage.RevocationBatchChecker counting
// its calls. batchErr, if set, is what IsAnyRevoked returns;
// batchRevoked makes it answer true whatever keys it gets; keyErr, if
// set, is what IsRevoked returns.
type batchRevocationChecker struct {
	revoked      map[string]bool
	batchErr     error
	batchRevoked bool
	keyErr       error

	mu         sync.Mutex
	batchKeys  [][]string
	singleKeys []string
}

var _ storage.RevocationBatchChecker = (*batchRevocationChecker)(nil)

func (b *batchRevocationChecker) IsRevoked(_ context.Context, key string) (bool, error) {
	b.mu.Lock()
	b.singleKeys = append(b.singleKeys, key)
	b.mu.Unlock()
	if b.keyErr != nil {
		return false, b.keyErr
	}
	return b.revoked[key], nil
}

func (b *batchRevocationChecker) IsAnyRevoked(_ context.Context, keys []string) (bool, error) {
	b.mu.Lock()
	b.batchKeys = append(b.batchKeys, slices.Clone(keys))
	b.mu.Unlock()
	if b.batchErr != nil {
		return false, b.batchErr
	}
	if b.batchRevoked {
		return true, nil
	}
	for _, key := range keys {
		if b.revoked[key] {
			return true, nil
		}
	}
	return false, nil
}

// batchRevocationCase is one TestVerifyChecksRevocationInOneBatch case.
type batchRevocationCase struct {
	checker     *batchRevocationChecker
	claims      map[string]json.RawMessage
	noIssuer    bool
	wantCode    resource.ErrorCode
	wantDesc    string
	wantBatches int
	wantSingles bool
}

// batchRevocationKeys are every revocation key of the token
// batchRevocationClaims names, in the order Verify asks about them.
var (
	batchRevocationClaims = map[string]json.RawMessage{"grant_id": json.RawMessage(`"g-1"`), "code_grant_id": json.RawMessage(`"cg-1"`)}
	batchRevocationKeys   = []string{"token-1", "grant:g-1@" + testIssuer, "grant:g-1", "code-grant:cg-1@" + testIssuer, "code-grant:cg-1"}
)

// TestVerifyChecksRevocationInOneBatch: with a
// storage.RevocationBatchChecker, a token carrying grant_id and
// code_grant_id is checked in one IsAnyRevoked call covering its own key
// and every grant key, current and pre-v0.61.0; anything but "none
// revoked" falls back to the IsRevoked calls, so each outcome keeps the
// response it has without a batch checker, and a batch answer of
// revoked is never overturned.
func TestVerifyChecksRevocationInOneBatch(t *testing.T) {
	down := errors.New("down")
	for name, tc := range map[string]batchRevocationCase{
		"none revoked":            {checker: &batchRevocationChecker{}, wantBatches: 1},
		"token revoked":           {checker: &batchRevocationChecker{revoked: map[string]bool{"token-1": true}}, wantCode: resource.ErrorInvalidToken, wantDesc: "access token has been revoked", wantBatches: 1, wantSingles: true},
		"grant revoked":           {checker: &batchRevocationChecker{revoked: map[string]bool{"grant:g-1@" + testIssuer: true}}, wantCode: resource.ErrorInvalidToken, wantDesc: "access token's grant has been revoked", wantBatches: 1, wantSingles: true},
		"legacy code grant":       {checker: &batchRevocationChecker{revoked: map[string]bool{"code-grant:cg-1": true}}, wantCode: resource.ErrorInvalidToken, wantDesc: "access token's grant has been revoked", wantBatches: 1, wantSingles: true},
		"batch fails, keys don't": {checker: &batchRevocationChecker{batchErr: down}, wantBatches: 1, wantSingles: true},
		"batch and keys fail":     {checker: &batchRevocationChecker{batchErr: down, keyErr: down}, wantCode: resource.ErrorServerError, wantDesc: "failed to check token revocation", wantBatches: 1, wantSingles: true},
		"batch revoked, no key":   {checker: &batchRevocationChecker{batchRevoked: true}, wantCode: resource.ErrorInvalidToken, wantDesc: "access token has been revoked", wantBatches: 1, wantSingles: true},
		"malformed claim":         {checker: &batchRevocationChecker{}, claims: map[string]json.RawMessage{"grant_id": json.RawMessage(`42`)}, wantCode: resource.ErrorInvalidToken, wantDesc: "access token's grant_id is malformed", wantSingles: true},
		"no issuer":               {checker: &batchRevocationChecker{}, noIssuer: true, wantCode: resource.ErrorServerError, wantDesc: "failed to check grant revocation", wantSingles: true},
	} {
		t.Run(name, func(t *testing.T) {
			err := verifyWithBatchChecker(t, tc)
			requireVerifyOutcome(t, err, tc.wantCode, tc.wantDesc)
			requireBatchCalls(t, tc)
		})
	}
}

// verifyWithBatchChecker verifies an mTLS-bound token carrying tc's
// claims (batchRevocationClaims by default) against tc.checker.
func verifyWithBatchChecker(t *testing.T, tc batchRevocationCase) error {
	t.Helper()
	now := time.Now()
	cert := selfSignedTestClientCert(t, "client-1")
	target, err := url.Parse("https://rs.example.com/accounts")
	if err != nil {
		t.Fatal(err)
	}
	claims := batchRevocationClaims
	if tc.claims != nil {
		claims = tc.claims
	}
	v, err := resource.NewVerifier(validConfig(t), resource.Dependencies{
		AccessTokens: grantClaimResolver{thumbprint: mtls.Thumbprint(cert), claims: claims, now: now, noIssuer: tc.noIssuer},
		Replay:       &fakeReplayStore{},
		Revocation:   tc.checker,
		Clock:        fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	_, err = v.Verify(context.Background(), resource.VerifyRequest{Method: "GET", URL: target, Authorization: "Bearer token", PeerCertificate: cert})
	return err
}

// requireVerifyOutcome fails unless err is nil when wantCode is empty,
// or a *resource.Error with wantCode and wantDesc otherwise.
func requireVerifyOutcome(t *testing.T, err error, wantCode resource.ErrorCode, wantDesc string) {
	t.Helper()
	if wantCode == "" {
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		return
	}
	var rerr *resource.Error
	if !errors.As(err, &rerr) || rerr.Code() != wantCode || rerr.PublicDescription() != wantDesc {
		t.Fatalf("Verify = %v, want %s %q", err, wantCode, wantDesc)
	}
}

// requireBatchCalls fails unless tc.checker saw the IsAnyRevoked and
// IsRevoked calls tc wants.
func requireBatchCalls(t *testing.T, tc batchRevocationCase) {
	t.Helper()
	if len(tc.checker.batchKeys) != tc.wantBatches {
		t.Fatalf("IsAnyRevoked calls = %v, want %d", tc.checker.batchKeys, tc.wantBatches)
	}
	if tc.wantBatches > 0 && !slices.Equal(tc.checker.batchKeys[0], batchRevocationKeys) {
		t.Fatalf("IsAnyRevoked keys = %v, want %v", tc.checker.batchKeys[0], batchRevocationKeys)
	}
	if (len(tc.checker.singleKeys) > 0) != tc.wantSingles {
		t.Fatalf("IsRevoked calls = %v, want some: %v", tc.checker.singleKeys, tc.wantSingles)
	}
}
