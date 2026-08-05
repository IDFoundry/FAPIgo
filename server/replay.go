package server

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/osanderson/go-fapi/storage"
)

// clientAssertionReplayNamespace, requestObjectReplayNamespace and
// dpopReplayNamespace keep replayed jtis from different subsystems from
// ever colliding on the same digest.
const (
	clientAssertionReplayNamespace storage.ReplayNamespace = "server:client-assertion"
	requestObjectReplayNamespace   storage.ReplayNamespace = "server:request-object"
	dpopReplayNamespace            storage.ReplayNamespace = "server:dpop"
)

// replayChecker adapts storage.ReplayStore — which is keyed by a
// namespaced digest — to the narrow, jti-string-keyed ReplayChecker
// interface internal/clientassertion and internal/requestobject each
// define. It hashes jti itself so neither internal package, nor
// storage.ReplayStore, ever sees the other's shape.
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

func (s *Server) clientAssertionReplayChecker() replayChecker {
	return replayChecker{store: s.deps.Replay, namespace: clientAssertionReplayNamespace}
}

func (s *Server) requestObjectReplayChecker() replayChecker {
	return replayChecker{store: s.deps.Replay, namespace: requestObjectReplayNamespace}
}

func (s *Server) dpopReplayChecker() replayChecker {
	return replayChecker{store: s.deps.Replay, namespace: dpopReplayNamespace}
}
