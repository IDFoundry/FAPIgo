package resource

import (
	"context"
	"time"

	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/replaykey"
	"github.com/idfoundry/fapigo/storage"
)

// dpopReplayNamespace keeps this verifier's replayed DPoP proof jtis
// from ever colliding with another role's or subsystem's use-once
// tokens in a shared storage.ReplayStore — see storage.ReplayNamespace.
const dpopReplayNamespace storage.ReplayNamespace = "resource:dpop"

// replayChecker records a DPoP proof's jti in storage.ReplayStore,
// scoped to the key that signed the proof (replaykey.Digest), so a proof
// signed with one key can't use up a jti another key will send.
type replayChecker struct {
	store     storage.ReplayStore
	namespace storage.ReplayNamespace
}

func (r replayChecker) UseOnce(ctx context.Context, key jose.Thumbprint, jti string, expiresAt time.Time) error {
	return r.store.UseOnce(ctx, storage.ReplayUse{
		Namespace: r.namespace,
		Digest:    replaykey.Digest(key.String(), jti),
		ExpiresAt: expiresAt,
	})
}

func (v *Verifier) dpopReplayChecker() replayChecker {
	return replayChecker{store: v.deps.Replay, namespace: dpopReplayNamespace}
}
