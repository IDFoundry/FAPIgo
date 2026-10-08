package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/idfoundry/fapigo/internal/grantrevocation"
)

// maxGrantIDLength bounds GrantedAuthorization.GrantID.
const maxGrantIDLength = 128

// revocationReader is what Dependencies.Revocation must also implement
// for grants to be revocable: the server checks a grant's revocation
// before redeeming its authorization code or refresh token.
// storage/memstore.RevocationStore does; so does any store
// serverresource.NewVerifier can use, which needs the same method
// (resource.RevocationChecker).
type revocationReader interface {
	IsRevoked(ctx context.Context, key string) (bool, error)
}

// validateGrantID checks a GrantedAuthorization.GrantID: empty (no
// grant revocation), or 1 to 128 URL-safe characters with a revocation
// store that can be checked.
func (s *Server) validateGrantID(id string) error {
	if id == "" {
		return nil
	}
	if len(id) > maxGrantIDLength {
		return fmt.Errorf("grant ID is longer than %d characters", maxGrantIDLength)
	}
	for _, r := range id {
		if !isGrantIDChar(r) {
			return fmt.Errorf("grant ID contains %q; use only A-Z, a-z, 0-9, '.', '_', '~' and '-'", r)
		}
	}
	if _, ok := s.grantRevocationReader(); !ok {
		return errors.New("grant ID set, but Dependencies.Revocation can't be checked (it doesn't implement IsRevoked), so the grant couldn't be revoked")
	}
	return nil
}

func isGrantIDChar(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '~' || r == '-'
}

// grantRevocationReader is Dependencies.Revocation as a revocationReader,
// when it is one (NoRevocation isn't).
func (s *Server) grantRevocationReader() (revocationReader, bool) {
	if _, none := s.deps.Revocation.(NoRevocation); none {
		return nil, false
	}
	if _, none := s.deps.Revocation.(*NoRevocation); none {
		return nil, false
	}
	reader, ok := s.deps.Revocation.(revocationReader)
	return reader, ok
}

// RevokeGrant revokes the grant an application named grantID when it
// authorized it (GrantedAuthorization.GrantID): its authorization code,
// if not yet redeemed, its refresh token, and every access token issued
// from it — for a "connected apps" page where a customer withdraws a
// client's access, for example. Every grant carrying the ID is revoked;
// RevokeToken calls this for the client a grant was issued to, so a grant
// ID must name one grant only. Grants without that grant ID are
// unaffected.
//
// It records grantID as revoked in Dependencies.Revocation, which every
// check reads: ExchangeAuthorizationCode, RefreshAccessToken and the
// CIBA token request answer invalid_grant, and resource.Verifier
// answers invalid_token for an access token carrying the grant ID — so
// a resource server must read the same revocation store the
// authorization server writes, as it must for access token revocation
// already. The record lasts as long as anything issued from the grant
// can still be used: the longest of Limits.RefreshTokenLifetime,
// Limits.AuthorizationCodeLifetime and
// Limits.BackchannelAuthenticationRequestLifetime (a refresh token,
// unredeemed code or approved auth_req_id already outstanding), plus
// Limits.AccessTokenLifetime (an access token issued just before) and
// Limits.MaxClockSkew (the leeway resource.Verifier allows on its
// expiry). Those are the current Limits: a refresh token, code or CIBA
// decision issued under a longer lifetime than today's expires at its
// issue time plus today's lifetime, whatever its stored expiry, so
// shortening a lifetime can't let one outlive the record — except one
// written before that issue time was recorded: a refresh token issued
// before v0.50.0 keeps its stored expiry, so after shortening
// Limits.RefreshTokenLifetime it can outlive this record. Until those
// have expired, revoke such a refresh token itself (RevokeToken) rather
// than relying on its grant's record. An access token keeps the exp it was issued with; one issued under a longer
// Limits.AccessTokenLifetime stays covered while that old lifetime is no
// longer than the current record lifetime. To cut such tokens off as
// soon as you shorten Limits.AccessTokenLifetime, lower the resource
// server's maximum accepted lifetime with it (resource.JWTAccessTokens'
// MaxTokenLifetime).
//
// RevokeGrant doesn't check who is asking: the application must make
// sure the user revoking a grant is the one it was granted by. A grant
// ID is revoked for that whole period, so an application must not reuse
// one for a later grant.
//
// It fails when Dependencies.Revocation is NoRevocation or can't be
// checked, rather than revoking nothing.
func (s *Server) RevokeGrant(ctx context.Context, grantID string) error {
	if grantID == "" {
		return errors.New("server: revoke grant: grant ID is empty")
	}
	if _, ok := s.grantRevocationReader(); !ok {
		return errors.New("server: revoke grant: Dependencies.Revocation can't revoke grants (it's NoRevocation, or doesn't implement IsRevoked)")
	}
	until := s.deps.Clock.Now().Add(s.grantRevocationHorizon())
	if err := s.deps.Revocation.Revoke(ctx, grantrevocation.Key(grantID), until); err != nil {
		return fmt.Errorf("server: revoke grant: %w", err)
	}
	return nil
}

// checkGrantNotRevoked refuses a grant that has been revoked with
// RevokeGrant: invalid_grant, as for any other authorization grant that
// is no longer valid (RFC 6749 §5.2).
func (s *Server) checkGrantNotRevoked(ctx context.Context, grant grantRecord) *Error {
	var keys []string
	if grant.GrantID != "" {
		keys = append(keys, grantrevocation.Key(grant.GrantID))
	}
	if grant.CodeGrantID != "" {
		// Revoked when the code it came from was reused.
		keys = append(keys, grantrevocation.CodeKey(grant.CodeGrantID))
	}
	if len(keys) == 0 {
		return nil
	}
	reader, ok := s.grantRevocationReader()
	if !ok {
		// A grant or code grant ID is only set with a checkable store, so
		// this is a deployment that has since changed its
		// Dependencies.Revocation: fail closed.
		return newError(ErrorServerError, 500, "the grant's revocation can't be checked", nil)
	}
	for _, key := range keys {
		revoked, err := reader.IsRevoked(ctx, key)
		if err != nil {
			return newError(ErrorServerError, 500, "failed to check the grant's revocation", err)
		}
		if revoked {
			return newError(ErrorInvalidGrant, 400, "the grant has been revoked", nil)
		}
	}
	return nil
}

// grantRevocationHorizon is how long after now anything issued from a
// grant can still be used — RevokeGrant's record lifetime.
//
// The sum saturates at the largest Duration rather than wrapping, so
// lifetimes configured absurdly long still give a record that outlasts
// them instead of one that has already expired.
func (s *Server) grantRevocationHorizon() time.Duration {
	l := s.cfg.Limits
	return saturatingAdd(saturatingAdd(max(l.RefreshTokenLifetime, l.AuthorizationCodeLifetime, l.BackchannelAuthenticationRequestLifetime),
		l.AccessTokenLifetime), l.MaxClockSkew)
}

// saturatingAdd is a+b for non-negative durations, capped at the largest
// Duration instead of overflowing.
func saturatingAdd(a, b time.Duration) time.Duration {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}
