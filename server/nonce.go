package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/idfoundry/fapigo/internal/dpopnonce"
	"github.com/idfoundry/fapigo/storage"
)

// NoDPoPNonces explicitly declines DPoP server nonces (RFC 9449 §8) as
// Dependencies.Nonces: the PAR, token and backchannel authentication
// endpoints then accept a DPoP proof without a "nonce" claim, as they
// do with Nonces left nil. AssuranceProduction refuses a nil Nonces, so
// declining there is a conscious, visible line of code
// (Nonces: server.NoDPoPNonces{}), the same reason NoRevocation exists.
//
// Without server nonces, a DPoP proof's freshness rests on its "iat"
// alone (Limits.MaxDPoPProofAge): an attacker who can make a client
// generate proofs ahead of time, or capture them, can use one at this
// server until it ages out (RFC 9449 §11.1, the FAPI 2.0 attacker
// model's A5). Right when every client is sender-constrained by mTLS
// rather than DPoP, or when that window is acceptable.
//
// New treats it as if Nonces were nil; it never stores or looks up a
// nonce. Passed anywhere else as a storage.NonceStore, Issue and Lookup
// fail.
type NoDPoPNonces struct{}

// errNoDPoPNonces is what NoDPoPNonces' own methods return.
var errNoDPoPNonces = errors.New("server: NoDPoPNonces stores no DPoP nonces")

// Issue implements storage.NonceStore by failing: NoDPoPNonces stores
// nothing.
func (NoDPoPNonces) Issue(context.Context, storage.NonceIssuance) error { return errNoDPoPNonces }

// Lookup implements storage.NonceStore by failing: NoDPoPNonces stores
// nothing.
func (NoDPoPNonces) Lookup(context.Context, storage.NonceLookup) (storage.NonceRecord, error) {
	return storage.NonceRecord{}, errNoDPoPNonces
}

// declinedDPoPNonces reports whether nonces is NoDPoPNonces, by value
// or pointer.
func declinedDPoPNonces(nonces storage.NonceStore) bool {
	switch nonces.(type) {
	case NoDPoPNonces, *NoDPoPNonces:
		return true
	}
	return false
}

// dpopNonceStore returns the store DPoP nonces are issued from and
// checked against: nonces, or nil when it's nil or NoDPoPNonces.
func dpopNonceStore(nonces storage.NonceStore) storage.NonceStore {
	if declinedDPoPNonces(nonces) {
		return nil
	}
	return nonces
}

// issueDPoPNonce returns the nonce this server currently hands out (see
// internal/dpopnonce.Rotator): the same one for every client and
// response until half of s.cfg.Limits.DPoPNonceLifetime has passed, then
// a fresh one, persisted in s.deps.Nonces. Only ever called once
// s.deps.Nonces is known to be non-nil.
func (s *Server) issueDPoPNonce(ctx context.Context, now time.Time) (string, error) {
	nonce, err := s.nonces.Current(ctx, s.deps.Nonces, s.deps.Random, s.cfg.Limits.DPoPNonceLifetime, now)
	if err != nil {
		return "", fmt.Errorf("server: %w", err)
	}
	return nonce, nil
}

// checkDPoPNonce enforces the nonce challenge (RFC 9449 §8) when
// s.deps.Nonces is configured: presented is the DPoP proof's own
// "nonce" claim (empty if absent) — shared by both the token endpoint
// and PAR, since one nonce store covers everything this server
// verifies (see Dependencies.Nonces's own doc comment). A nonce this
// server issued is valid until it expires, for any number of proofs
// (§8.2: the client uses it "until the server supplies a new nonce");
// each proof's "jti" is what refuses a replay. A missing, unknown or
// expired nonce is rejected with the current nonce attached (via
// *Error's own Nonce method) for the caller to retry with; a valid one
// returns nil, letting the caller proceed.
//
// Called only when s.deps.Nonces != nil — every call site guards that.
// New has already turned NoDPoPNonces into nil, so a declined store
// never gets here.
func (s *Server) checkDPoPNonce(ctx context.Context, presented string, now time.Time) *Error {
	if valid, _ := dpopnonce.Valid(ctx, s.deps.Nonces, presented, now); valid {
		return nil
	}

	current, err := s.issueDPoPNonce(ctx, now)
	if err != nil {
		return newError(ErrorServerError, 500, "failed to issue dpop nonce", err)
	}
	// RFC 9449 §8 token-endpoint nonce errors are ordinary RFC 6749
	// §5.2 OAuth errors — 400, not the 401 WWW-Authenticate challenge
	// resource.ErrorUseDPoPNonce uses for a protected-resource request.
	challenge := newError(ErrorUseDPoPNonce, 400, "DPoP proof must carry a current nonce", nil)
	challenge.nonce = current
	return challenge
}
