package server

import (
	"context"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/replaykey"
	"github.com/idfoundry/fapigo/storage"
)

// clientAssertionReplayNamespace, requestObjectReplayNamespace and
// dpopReplayNamespace keep replayed jtis from different subsystems from
// ever colliding on the same digest.
const (
	clientAssertionReplayNamespace                  storage.ReplayNamespace = "server:client-assertion"
	requestObjectReplayNamespace                    storage.ReplayNamespace = "server:request-object"
	dpopReplayNamespace                             storage.ReplayNamespace = "server:dpop"
	backchannelAuthenticationRequestReplayNamespace storage.ReplayNamespace = "server:backchannel-authentication-request"
	clientAttestationPoPReplayNamespace             storage.ReplayNamespace = "server:client-attestation-pop"
)

// replayChecker adapts storage.ReplayStore — which is keyed by a
// namespaced digest — to the narrow, jti-string-keyed ReplayChecker
// interface internal/clientassertion, internal/requestobject and
// internal/clientattestation each define. It records jti scoped to the
// authenticated client (replaykey.Digest), so one client can't use up a
// jti another will send; each of those packages has already checked
// that the token was issued by, or for, that client.
type replayChecker struct {
	store     storage.ReplayStore
	namespace storage.ReplayNamespace
	client    fapi.ClientID
}

func (r replayChecker) UseOnce(ctx context.Context, jti string, expiresAt time.Time) error {
	return r.store.UseOnce(ctx, storage.ReplayUse{
		Namespace: r.namespace,
		Digest:    replaykey.Digest(string(r.client), jti),
		ExpiresAt: expiresAt,
	})
}

// dpopReplayChecker adapts storage.ReplayStore to internal/dpop's
// ReplayChecker, recording a proof's jti scoped to the key that signed
// it, so a proof signed with one key can't use up a jti another key will
// send.
type dpopReplayChecker struct {
	store storage.ReplayStore
}

func (r dpopReplayChecker) UseOnce(ctx context.Context, key jose.Thumbprint, jti string, expiresAt time.Time) error {
	return r.store.UseOnce(ctx, storage.ReplayUse{
		Namespace: dpopReplayNamespace,
		Digest:    replaykey.Digest(key.String(), jti),
		ExpiresAt: expiresAt,
	})
}

func (s *Server) clientAssertionReplayChecker(client fapi.ClientID) replayChecker {
	return replayChecker{store: s.deps.Replay, namespace: clientAssertionReplayNamespace, client: client}
}

func (s *Server) requestObjectReplayChecker(client fapi.ClientID) replayChecker {
	return replayChecker{store: s.deps.Replay, namespace: requestObjectReplayNamespace, client: client}
}

func (s *Server) dpopReplayChecker() dpopReplayChecker {
	return dpopReplayChecker{store: s.deps.Replay}
}

func (s *Server) backchannelAuthenticationRequestReplayChecker(client fapi.ClientID) replayChecker {
	return replayChecker{store: s.deps.Replay, namespace: backchannelAuthenticationRequestReplayNamespace, client: client}
}

func (s *Server) clientAttestationPoPReplayChecker(client fapi.ClientID) replayChecker {
	return replayChecker{store: s.deps.Replay, namespace: clientAttestationPoPReplayNamespace, client: client}
}
