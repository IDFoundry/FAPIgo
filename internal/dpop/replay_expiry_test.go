package dpop

import (
	"context"
	"math"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
)

// recordingReplay records the ExpiresAt Verify asks the replay store
// for.
type recordingReplay struct{ expiresAt time.Time }

func (r *recordingReplay) UseOnce(_ context.Context, _ jose.Thumbprint, _ string, expiresAt time.Time) error {
	r.expiresAt = expiresAt
	return nil
}

// TestVerifyReplayRecordOutlastsHugeSkew: MaxProofAge plus twice an
// absurdly large MaxClockSkew saturates rather than wrapping, so the
// replay record outlasts the proof instead of having already expired
// while the proof is still accepted.
func TestVerifyReplayRecordOutlastsHugeSkew(t *testing.T) {
	key := generateKey(t)
	now := time.Now()
	target := mustURL(t, "https://as.example/token")
	proof, err := CreateProof(ProofRequest{Signer: key, Algorithm: fapi.ES256, Method: "POST", URL: target, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	replay := &recordingReplay{}
	if _, err := Verify(context.Background(), VerifyRequest{Proof: proof, Method: "POST", URL: target, Now: now,
		MaxProofAge: time.Minute, MaxClockSkew: math.MaxInt64 / 2, Replay: replay}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !replay.expiresAt.After(now.Add(100 * 365 * 24 * time.Hour)) {
		t.Fatalf("replay record ExpiresAt = %v, want far in the future (now %v)", replay.expiresAt, now)
	}
}
