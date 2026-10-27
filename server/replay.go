package server

import (
	"context"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/jose"
	"github.com/idfoundry/fapigo/internal/replaykey"
	"github.com/idfoundry/fapigo/storage"
)

// The replay namespaces keep replayed jtis from different subsystems
// from ever colliding on the same digest.
//
// clientSignedJWTReplayNamespace is shared by every JWT the AS verifies
// against a client's own keys — client assertions, request objects at
// PAR and CIBA signed authentication requests. A client signs all three
// with one key set, so a JWT of one kind could otherwise be presented,
// once, as another kind under a jti its namespace hadn't seen (RFC 8725
// §3.11-3.12): sharing the namespace spends a jti however the JWT
// carrying it is first used. Each record lasts until the JWT's own exp
// plus twice Limits.MaxClockSkew, the same for every kind, so it lasts
// as long as the JWT could be accepted as any of them. A Client
// Attestation PoP keeps its own namespace: it is signed with the Client
// Instance's key, not the client's.
const (
	clientSignedJWTReplayNamespace      storage.ReplayNamespace = "server:client-signed-jwt"
	dpopReplayNamespace                 storage.ReplayNamespace = "server:dpop"
	clientAttestationPoPReplayNamespace storage.ReplayNamespace = "server:client-attestation-pop"
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

// clientSignedJWTReplayChecker is the replay checker for a client
// assertion, request object or CIBA request from client — see
// clientSignedJWTReplayNamespace.
func (s *Server) clientSignedJWTReplayChecker(client fapi.ClientID) replayChecker {
	return replayChecker{store: s.deps.Replay, namespace: clientSignedJWTReplayNamespace, client: client}
}

func (s *Server) dpopReplayChecker() dpopReplayChecker {
	return dpopReplayChecker{store: s.deps.Replay}
}

// clientAttestationPoPReplayChecker adapts storage.ReplayStore to
// internal/clientattestation's ReplayChecker, recording a Client
// Attestation PoP's jti scoped to the client and to the Client Instance
// whose key signed it: every installation of a client shares one
// client_id, so a record scoped to the client alone would let one
// installation use up a jti another will send. A replayed PoP carries
// the same instance key, so it is still refused. The thumbprint's
// encoding has a fixed length, so prefixing it to the jti can't make two
// different (key, jti) pairs collide.
type clientAttestationPoPReplayChecker struct {
	store  storage.ReplayStore
	client fapi.ClientID
}

func (r clientAttestationPoPReplayChecker) UseOnce(ctx context.Context, instanceKey jose.Thumbprint, jti string, expiresAt time.Time) error {
	return r.store.UseOnce(ctx, storage.ReplayUse{
		Namespace: clientAttestationPoPReplayNamespace,
		Digest:    replaykey.Digest(string(r.client), instanceKey.String()+jti),
		ExpiresAt: expiresAt,
	})
}

func (s *Server) clientAttestationPoPReplayChecker(client fapi.ClientID) clientAttestationPoPReplayChecker {
	return clientAttestationPoPReplayChecker{store: s.deps.Replay, client: client}
}
