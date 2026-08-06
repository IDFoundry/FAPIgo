package resource

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/osanderson/go-fapi/storage"
)

// dpopReplayNamespace keeps this verifier's replayed DPoP proof jtis
// from ever colliding with another role's or subsystem's use-once
// tokens in a shared storage.ReplayStore — see storage.ReplayNamespace.
const dpopReplayNamespace storage.ReplayNamespace = "resource:dpop"

// replayChecker adapts storage.ReplayStore — which is keyed by a
// namespaced digest — to the narrow, jti-string-keyed ReplayChecker
// interface internal/dpop defines. It hashes jti itself so internal/dpop
// never sees storage.ReplayStore's shape.
type replayChecker struct {
	store     storage.ReplayStore
	namespace storage.ReplayNamespace
}

func (r replayChecker) UseOnce(ctx context.Context, jti string, expiresAt time.Time) error {
	return r.store.UseOnce(ctx, storage.ReplayUse{
		Namespace: r.namespace,
		Digest:    sha256.Sum256([]byte(jti)),
		ExpiresAt: expiresAt,
	})
}

func (v *Verifier) dpopReplayChecker() replayChecker {
	return replayChecker{store: v.deps.Replay, namespace: dpopReplayNamespace}
}
