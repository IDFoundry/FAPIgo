package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/idfoundry/fapigo/internal/grantrevocation"
	"github.com/idfoundry/fapigo/internal/timeutil"
	"github.com/idfoundry/fapigo/storage"
)

// maxGrantIDLength bounds GrantedAuthorization.GrantID.
const maxGrantIDLength = 128

// revocationReader is what Dependencies.Revocation must also implement
// for grants to be revocable: the server checks a grant's revocation
// before redeeming its authorization code or refresh token.
// storage/memstore.RevocationStore does; so does any store
// serverresource.NewVerifier can use, which needs the same method
// (resource.RevocationChecker). One that is also a
// storage.RevocationBatchChecker is asked about all of a grant's keys in
// one IsAnyRevoked call (anyRevoked).
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
// It records grantID as revoked in Dependencies.Revocation, under a key
// namespaced by this server's issuer, so revoking a grant ID can't
// revoke another issuer's grant of the same ID where servers with
// different issuers share the store. Every check reads it: ExchangeAuthorizationCode, RefreshAccessToken and the
// CIBA token request answer invalid_grant, and resource.Verifier
// answers invalid_token for an access token carrying the grant ID — so
// a resource server must read the same revocation store the
// authorization server writes, as it must for access token revocation
// already. Then, when Dependencies.Grants is a
// storage.GrantRefreshTokenRevoker (memstore's GrantStore is, as are
// sqlstore's DB.Grants and DB.BatchingGrants from sqlstore v0.10), it
// revokes the grant's refresh tokens in that store as well, and removes
// them from Dependencies.GrantRegistry. If revoking them fails, the
// grant is revoked all the same, and the error says its refresh tokens
// couldn't all be revoked: call RevokeGrant again to revoke the rest.
// If only removing a registry entry fails, the error says the grant and
// its refresh tokens are revoked. Calling RevokeGrant again may not
// remove that entry, since the store needn't report a refresh token it
// has already revoked, but ListGrants doesn't list the entry while the
// grant's record lasts, the entry expires with its refresh token (with
// refresh token lifetimes of up to 400 days, it's never listed again),
// and RevokeListedGrant and RevokeSubjectGrants remove it.
//
// The record lasts at least 400 days, or as long as anything issued
// from the grant can still be used under the current Limits, if that's
// longer: the longest of Limits.RefreshTokenLifetime,
// Limits.AuthorizationCodeLifetime and
// Limits.BackchannelAuthenticationRequestLifetime (a refresh token,
// unredeemed code or approved auth_req_id already outstanding), plus
// Limits.AccessTokenLifetime (an access token issued just before) and
// Limits.MaxClockSkew (the leeway resource.Verifier allows on its
// expiry). The revocation store keeps one such record for each revoked
// grant. The 400 days are for a refresh token the GrantStore didn't
// revoke — one stored by a GrantStore without that interface, or before
// it had it, or one it failed to revoke — which only the record
// refuses: a longer Limits.RefreshTokenLifetime than the record was
// sized from can apply to it later, raised after the revocation or on
// another instance running other Limits. (A refresh token issued while
// RevokeGrant runs isn't left to the record alone unless the grant's
// other refresh tokens are: the issuance checks the grant's revocation
// again once it has stored the token, and withdraws it instead if the
// record is there by then, so a token it issues was stored before the
// record, which RevokeGrant writes before revoking the grant's refresh
// tokens.) So a revoked grant's refresh tokens that the GrantStore
// revoked can never be redeemed again, and any other is refused for
// good unless a refresh token lifetime over 400 days applies to it.
// With longer lifetimes, use a GrantStore that implements the
// interface, or also revoke the refresh token itself (RevokeListedGrant
// does, and RevokeSubjectGrants does for every grant of the user's
// revoked this way), or call RevokeGrant again once the longer lifetime
// applies.
//
// Shortening a lifetime can't let anything outlive the record either: a
// refresh token, code or CIBA decision issued under a longer lifetime
// than today's expires at its issue time plus today's lifetime, whatever
// its stored expiry. An access token keeps the exp it was issued with;
// one issued under a longer Limits.AccessTokenLifetime stays covered
// while that old lifetime is no longer than the record's. To cut such
// tokens off as soon as you shorten Limits.AccessTokenLifetime, lower
// the resource server's maximum accepted lifetime with it
// (resource.JWTAccessTokens' MaxTokenLifetime).
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
	key := grantrevocation.Key(s.cfg.Issuer.String(), grantID)
	if err := s.deps.Revocation.Revoke(ctx, key, s.deps.Clock.Now().Add(s.grantRevocationRecordLifetime())); err != nil {
		return fmt.Errorf("server: revoke grant: %w", err)
	}
	revokeErr, forgetErr := s.revokeGrantRefreshTokens(ctx, key)
	if revokeErr != nil {
		return fmt.Errorf("server: revoke grant: the grant is revoked, but its refresh tokens couldn't all be revoked (call RevokeGrant again to revoke the rest): %w", errors.Join(revokeErr, forgetErr))
	}
	if forgetErr != nil {
		return fmt.Errorf("server: revoke grant: the grant and its refresh tokens are revoked, but some of their grant registry entries couldn't be removed: %w", forgetErr)
	}
	return nil
}

// revokeGrantRefreshTokens revokes, in Dependencies.Grants, the refresh
// tokens issued from the grant revocationKey (grantrevocation.Key or
// CodeKey) names, and removes each from Dependencies.GrantRegistry, as
// revokeRefreshToken does one token, when Grants can find them: when
// it's a storage.GrantRefreshTokenRevoker. It runs once the grant's
// revocation is recorded, so a token it misses is still refused.
//
// The two failures are told apart. revokeErr is the store's: a later
// call revokes the tokens it left. forgetErr joins the failures to
// remove a reported token's registry entry, which a later call may not
// retry, since the store needn't report a token it has already revoked.
// So every token the store reports has its entry removed, even with
// revokeErr (a store failing part way reports what it did revoke), and
// one entry failing to go doesn't keep the others'.
func (s *Server) revokeGrantRefreshTokens(ctx context.Context, revocationKey string) (revokeErr, forgetErr error) {
	revoker, ok := s.deps.Grants.(storage.GrantRefreshTokenRevoker)
	if !ok {
		return nil, nil
	}
	revoked, revokeErr := revoker.RevokeGrantRefreshTokens(ctx, refreshTokenGrantKey(revocationKey))
	var failures []error
	for _, hash := range revoked {
		if err := s.forgetRevokedRefreshToken(ctx, hash); err != nil {
			failures = append(failures, err)
		}
	}
	return revokeErr, errors.Join(failures...)
}

// confirmGrantNotRevoked checks, once the refresh token stored under
// refreshTokenHash has been created, that grant, the grant it's issued
// from, still isn't revoked, and withdraws the token if it is, or if
// that can't be checked (withdrawRefreshToken), so the token isn't
// issued. The token request checked the grant before, but it may have
// been revoked since: RevokeGrant, or a reuse of the authorization code,
// records the grant as revoked, then revokes the grant's refresh tokens
// in a GrantStore that can find them (storage.GrantRefreshTokenRevoker),
// which misses one stored after. Either this check comes after the
// record, and withdraws the token, or the record, and the revocation of
// the grant's refresh tokens after it, come after the token was stored,
// and that revocation finds it: with such a GrantStore, no refresh token
// is issued that only its revoked grant's record refuses. It reads the
// revocation store only for a grant with a GrantID or code grant ID, as
// checkGrantNotRevoked does.
func (s *Server) confirmGrantNotRevoked(ctx context.Context, grant grantRecord, refreshTokenHash [32]byte) error {
	if revErr := s.checkGrantNotRevoked(ctx, grant); revErr != nil {
		return s.withdrawRefreshToken(ctx, refreshTokenHash, fmt.Errorf("confirm the grant isn't revoked: %w", revErr))
	}
	return nil
}

// refreshTokenGrantKeys are the storage.NewRefreshToken.GrantKeys of a
// refresh token issued from grant: the key RevokeGrant revokes its
// GrantID's refresh tokens by, and the key a reuse of its authorization
// code revokes its CodeGrantID's by, whichever it has.
func (s *Server) refreshTokenGrantKeys(grant grantRecord) []string {
	issuer := s.cfg.Issuer.String()
	var keys []string
	if grant.GrantID != "" {
		keys = append(keys, refreshTokenGrantKey(grantrevocation.Key(issuer, grant.GrantID)))
	}
	if grant.CodeGrantID != "" {
		keys = append(keys, refreshTokenGrantKey(grantrevocation.CodeKey(issuer, grant.CodeGrantID)))
	}
	return keys
}

// refreshTokenGrantKey is the key a GrantStore indexes the refresh
// tokens of the grant revocationKey names by (storage.NewRefreshToken.
// GrantKeys): a digest of that key, which names the grant's issuer and
// ID, so the store keeps a fixed-length digest, never the grant ID the
// application chose, as it keeps a token's digest, never the token.
func refreshTokenGrantKey(revocationKey string) string {
	sum := sha256.Sum256([]byte("fapigo refresh token grant\x00" + revocationKey))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// checkGrantNotRevoked refuses a grant that has been revoked with
// RevokeGrant: invalid_grant, as for any other authorization grant that
// is no longer valid (RFC 6749 §5.2). It also reads the un-namespaced
// key a server before v0.61.0 wrote (grantrevocation.Keys), so a grant
// revoked before an upgrade stays revoked.
func (s *Server) checkGrantNotRevoked(ctx context.Context, grant grantRecord) *Error {
	issuer := s.cfg.Issuer.String()
	var keys []string
	if grant.GrantID != "" {
		keys = append(keys, grantrevocation.Keys(issuer, grant.GrantID)...)
	}
	if grant.CodeGrantID != "" {
		// Revoked when the code it came from was reused.
		keys = append(keys, grantrevocation.CodeKeys(issuer, grant.CodeGrantID)...)
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
	revoked, err := anyRevoked(ctx, reader, keys)
	if err != nil {
		return newError(ErrorServerError, 500, "failed to check the grant's revocation", err)
	}
	if revoked {
		return newError(ErrorInvalidGrant, 400, "the grant has been revoked", nil)
	}
	return nil
}

// anyRevoked reports whether any of keys is revoked: in one call when
// reader is a storage.RevocationBatchChecker, otherwise one IsRevoked
// per key, stopping at the first that is revoked or fails.
func anyRevoked(ctx context.Context, reader revocationReader, keys []string) (bool, error) {
	if batch, ok := reader.(storage.RevocationBatchChecker); ok {
		return batch.IsAnyRevoked(ctx, keys)
	}
	for _, key := range keys {
		revoked, err := reader.IsRevoked(ctx, key)
		if err != nil || revoked {
			return revoked, err
		}
	}
	return false, nil
}

// minGrantRevocationRecordLifetime is the shortest time a grant's
// revocation record lasts, whatever the current Limits: the record
// RevokeGrant writes, the one a reused authorization code's grant gets,
// and the one a code or CIBA grant gets as its refresh token is revoked
// (revokeCodeGrant). A record sized from the current Limits alone lapses
// early once a longer refresh token lifetime applies, raised later or on
// another instance with other Limits, while a refresh token the
// GrantStore still holds would be redeemable under it again (see
// RevokeGrant). 400 days is longer than any refresh token lifetime a
// deployment is likely to set (RecommendedLimits' is a day), at the cost
// of a revocation store keeping each such record that long.
const minGrantRevocationRecordLifetime = 400 * 24 * time.Hour

// grantRevocationRecordLifetime is how long a revoked grant's
// revocation record lasts, however the grant was revoked:
// grantRevocationHorizon, or minGrantRevocationRecordLifetime when
// that's longer.
func (s *Server) grantRevocationRecordLifetime() time.Duration {
	return max(s.grantRevocationHorizon(), minGrantRevocationRecordLifetime)
}

// grantRevocationHorizon is how long after now anything issued from a
// grant can still be used under the current Limits: how long a revoked
// grant's record must last at least (grantRevocationRecordLifetime).
//
// The sum saturates at the largest Duration rather than wrapping, so
// lifetimes configured absurdly long still give a record that outlasts
// them instead of one that has already expired.
func (s *Server) grantRevocationHorizon() time.Duration {
	l := s.cfg.Limits
	return timeutil.SaturatingAdd(max(l.RefreshTokenLifetime, l.AuthorizationCodeLifetime, l.BackchannelAuthenticationRequestLifetime),
		l.AccessTokenLifetime, l.MaxClockSkew)
}
