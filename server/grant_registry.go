package server

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/strictjson"
	"github.com/idfoundry/fapigo/storage"
)

// ErrGrantNotListed is RevokeListedGrant's answer for an ID that isn't
// one of the subject's listed grants: never listed, another subject's,
// expired, or already revoked.
var ErrGrantNotListed = errors.New("server: the grant isn't one of the subject's listed grants")

// ListedGrant is one grant ListGrants returns: one the end user
// authorized that a client still holds a refresh token for.
type ListedGrant struct {
	// ID names the grant for RevokeListedGrant. It's opaque, stable for
	// the grant's life, and safe to put in a page (it's a digest, not
	// the refresh token or anything that redeems it).
	ID string

	// GrantID is the application's GrantedAuthorization.GrantID (or
	// IssueRefreshTokenRequest.GrantID), if it set one.
	GrantID string

	ClientID fapi.ClientID

	// GrantType is the grant the authorization was made under:
	// "authorization_code", CIBAGrantType, or the embedder's own grant
	// type for one it served (IssueRefreshToken).
	GrantType string

	// Scope, AuthorizationDetails and Resources are what was granted,
	// and what the refresh token can be used for.
	Scope                []string
	AuthorizationDetails []json.RawMessage
	Resources            []string

	// IssuedAt is when the refresh token was issued, and ExpiresAt when
	// it expires.
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// grantRegistryRecord is what a GrantRegistry entry holds as its opaque
// Record.
type grantRegistryRecord struct {
	Version int    `json:"v"`
	Issuer  string `json:"iss"`

	// RefreshTokenHash is the GrantStore key of the grant's refresh
	// token, for RevokeListedGrant to delete it.
	RefreshTokenHash []byte `json:"rth"`

	GrantID              string          `json:"grant_id,omitempty"`
	CodeGrantID          string          `json:"code_grant_id,omitempty"`
	Subject              string          `json:"sub"`
	GrantType            string          `json:"grant_type,omitempty"`
	Scope                []string        `json:"scope,omitempty"`
	AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
	Resources            []string        `json:"resources,omitempty"`
	IssuedAt             time.Time       `json:"issued_at"`
}

// grantEntryKey is a GrantRegistry entry's Key for the grant whose
// refresh token is stored under refreshTokenHash: a digest of it, so the
// key, which ListedGrant.ID exposes, is no GrantStore key.
func grantEntryKey(refreshTokenHash [32]byte) string {
	sum := sha256.Sum256(append([]byte("fapigo grant registry entry\x00"), refreshTokenHash[:]...))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// grantSubjectKey is the GrantRegistry SubjectKey for subject at this
// server's issuer, so servers with different issuers sharing a registry
// list only their own grants.
func (s *Server) grantSubjectKey(subject string) string {
	sum := sha256.Sum256([]byte("fapigo grant registry subject\x00" + s.cfg.Issuer.String() + "\x00" + subject))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// recordGrant adds grant, issued to clientID with the refresh token
// stored under refreshTokenHash, to Dependencies.GrantRegistry, when one
// is set. It runs before the refresh token is stored, so no refresh
// token is issued that the registry doesn't list; confirmGrantRecorded,
// after the token is stored, covers a revocation that ran in between.
func (s *Server) recordGrant(ctx context.Context, clientID fapi.ClientID, grant grantRecord, refreshTokenHash [32]byte, issuedAt, expiresAt time.Time) error {
	if s.deps.GrantRegistry == nil {
		return nil
	}
	record, err := strictjson.MarshalUnescaped(grantRegistryRecord{
		Version: recordVersion, Issuer: s.cfg.Issuer.String(), RefreshTokenHash: refreshTokenHash[:],
		GrantID: grant.GrantID, CodeGrantID: grant.CodeGrantID, Subject: grant.Subject, GrantType: grant.GrantType,
		Scope: grant.Scope, AuthorizationDetails: grant.AuthorizationDetails, Resources: grant.Resources, IssuedAt: issuedAt,
	})
	if err != nil {
		return err
	}
	return s.deps.GrantRegistry.RecordGrant(ctx, storage.NewGrantEntry{
		Key: grantEntryKey(refreshTokenHash), SubjectKey: s.grantSubjectKey(grant.Subject),
		ClientID: clientID, Record: record, ExpiresAt: expiresAt,
	})
}

// errGrantRevokedWhileIssued is issueRefreshToken's failure when the
// grant was revoked while its refresh token was being issued.
var errGrantRevokedWhileIssued = errors.New("the grant was revoked while its refresh token was being issued")

// confirmGrantRecorded checks, after the refresh token stored under
// refreshTokenHash was created, that its grant is still in
// Dependencies.GrantRegistry, when one is set. A revocation listing the
// grant between recordGrant and the token's creation found no token to
// delete, then removed the entry: the token would be live, but unlisted
// and so unrevocable by RevokeSubjectGrants. Then this revokes the
// token itself and fails the issuance. A revocation from here on finds
// the token, so revokes it.
func (s *Server) confirmGrantRecorded(ctx context.Context, subject string, refreshTokenHash [32]byte) error {
	if s.deps.GrantRegistry == nil {
		return nil
	}
	entries, err := s.deps.GrantRegistry.ListGrants(ctx, storage.GrantListing{SubjectKey: s.grantSubjectKey(subject), Now: s.deps.Clock.Now()})
	if err != nil {
		return s.withdrawRefreshToken(ctx, refreshTokenHash, fmt.Errorf("confirm the grant is recorded: %w", err))
	}
	key := grantEntryKey(refreshTokenHash)
	if slices.ContainsFunc(entries, func(e storage.GrantEntry) bool { return e.Key == key }) {
		return nil
	}
	return s.withdrawRefreshToken(ctx, refreshTokenHash, errGrantRevokedWhileIssued)
}

// withdrawRefreshToken revokes the refresh token just stored under
// refreshTokenHash, which won't be issued, and returns cause: a failure
// to revoke it is joined to cause, so the token is never issued
// unlisted either way.
func (s *Server) withdrawRefreshToken(ctx context.Context, refreshTokenHash [32]byte, cause error) error {
	if err := s.deps.Grants.RevokeRefreshToken(ctx, refreshTokenHash); err != nil {
		return errors.Join(cause, fmt.Errorf("withdraw the refresh token: %w", err))
	}
	return cause
}

// listedGrant pairs a ListedGrant with its decoded record.
type listedGrant struct {
	listed ListedGrant
	record grantRegistryRecord
}

// ListGrants returns the grants subject authorized that a client still
// holds a refresh token for, oldest first: for a "connected apps" page,
// or to revoke them all when an account closes (RevokeListedGrant on
// each). It needs Dependencies.GrantRegistry, which records a grant when
// its refresh token is issued. A grant whose access tokens alone were
// issued, with no refresh token, isn't listed: they expire within
// Limits.AccessTokenLifetime. A grant revoked another way (RevokeGrant,
// RevokeToken, or the reuse of its authorization code) isn't listed
// either, nor one whose refresh token has expired.
//
// ListGrants doesn't check who is asking: the application must make sure
// the user is subject.
func (s *Server) ListGrants(ctx context.Context, subject SubjectID) ([]ListedGrant, error) {
	grants, err := s.listGrants(ctx, subject)
	if err != nil {
		return nil, err
	}
	out := make([]ListedGrant, len(grants))
	for i, g := range grants {
		out[i] = g.listed
	}
	return out, nil
}

func (s *Server) listGrants(ctx context.Context, subject SubjectID) ([]listedGrant, error) {
	if s.deps.GrantRegistry == nil {
		return nil, errors.New("server: list grants: Dependencies.GrantRegistry isn't set")
	}
	if subject.String() == "" {
		return nil, errors.New("server: list grants: subject is empty")
	}
	entries, err := s.deps.GrantRegistry.ListGrants(ctx, storage.GrantListing{SubjectKey: s.grantSubjectKey(subject.String()), Now: s.deps.Clock.Now()})
	if err != nil {
		return nil, fmt.Errorf("server: list grants: %w", err)
	}
	var out []listedGrant
	for _, entry := range entries {
		g, ok, err := s.listedGrantFrom(ctx, subject, entry)
		if err != nil {
			return nil, fmt.Errorf("server: list grants: %w", err)
		}
		if ok {
			out = append(out, g)
		}
	}
	slices.SortFunc(out, func(a, b listedGrant) int {
		return cmp.Or(a.listed.IssuedAt.Compare(b.listed.IssuedAt), cmp.Compare(a.listed.ID, b.listed.ID))
	})
	return out, nil
}

// listedGrantFrom decodes entry, reporting false for one that isn't a
// live grant of subject's at this server: written by another issuer,
// expired, or revoked.
func (s *Server) listedGrantFrom(ctx context.Context, subject SubjectID, entry storage.GrantEntry) (listedGrant, bool, error) {
	var record grantRegistryRecord
	if err := decodeRecord(entry.Record, &record.Version, &record); err != nil {
		return listedGrant{}, false, fmt.Errorf("stored grant registry entry: %w", err)
	}
	if !s.ownsRecord(record.Issuer) || record.Subject != subject.String() || !s.deps.Clock.Now().Before(entry.ExpiresAt) {
		return listedGrant{}, false, nil
	}
	if revokedErr := s.checkGrantNotRevoked(ctx, grantRecord{GrantID: record.GrantID, CodeGrantID: record.CodeGrantID}); revokedErr != nil {
		if revokedErr.Code() == ErrorInvalidGrant {
			return listedGrant{}, false, nil
		}
		return listedGrant{}, false, revokedErr
	}
	var details []json.RawMessage
	if len(record.AuthorizationDetails) > 0 {
		if err := json.Unmarshal(record.AuthorizationDetails, &details); err != nil {
			return listedGrant{}, false, fmt.Errorf("stored grant registry entry's authorization details: %w", err)
		}
	}
	return listedGrant{
		listed: ListedGrant{
			ID: entry.Key, GrantID: record.GrantID, ClientID: entry.ClientID, GrantType: record.GrantType,
			Scope: slices.Clone(record.Scope), AuthorizationDetails: details, Resources: slices.Clone(record.Resources),
			IssuedAt: record.IssuedAt, ExpiresAt: entry.ExpiresAt,
		},
		record: record,
	}, true, nil
}

// RevokeListedGrant revokes the grant id names (ListedGrant.ID), if it's
// one of subject's listed grants, and ErrGrantNotListed otherwise: its
// refresh token, and every access token issued from it, through its
// GrantID (as RevokeGrant does) and its authorization code or CIBA
// request (as the code's reuse does), whichever it has. A grant served
// with neither (IssueRefreshToken without a GrantID) has its refresh
// token revoked, and its access tokens expire within
// Limits.AccessTokenLifetime.
//
// Taking subject as well as id means an ID from a form can only revoke a
// grant of the subject the application has authenticated: the
// application must still make sure the user is subject.
func (s *Server) RevokeListedGrant(ctx context.Context, subject SubjectID, id string) error {
	grants, err := s.listGrants(ctx, subject)
	if err != nil {
		return fmt.Errorf("server: revoke listed grant: %w", err)
	}
	i := slices.IndexFunc(grants, func(g listedGrant) bool { return g.listed.ID == id })
	if i < 0 {
		return ErrGrantNotListed
	}
	return s.revokeListed(ctx, grants[i])
}

// revokeListed revokes g as RevokeListedGrant describes. The grant goes
// before its refresh token, as in revokeRefreshToken, and the registry
// entry last, so a failure part way leaves it listed for a retry.
func (s *Server) revokeListed(ctx context.Context, g listedGrant) error {
	if g.record.GrantID != "" {
		if err := s.RevokeGrant(ctx, g.record.GrantID); err != nil {
			return fmt.Errorf("server: revoke listed grant: %w", err)
		}
	}
	if revokeErr := s.revokeCodeGrant(ctx, g.record.CodeGrantID); revokeErr != nil {
		return fmt.Errorf("server: revoke listed grant: %w", revokeErr)
	}
	hash, ok := refreshTokenHashOf(g.record.RefreshTokenHash)
	if !ok {
		return errors.New("server: revoke listed grant: stored grant registry entry has no refresh token hash")
	}
	if err := s.deps.Grants.RevokeRefreshToken(ctx, hash); err != nil {
		return fmt.Errorf("server: revoke listed grant: %w", err)
	}
	if err := s.deps.GrantRegistry.DeleteGrant(ctx, g.listed.ID); err != nil {
		return fmt.Errorf("server: revoke listed grant: %w", err)
	}
	return nil
}

func refreshTokenHashOf(b []byte) ([32]byte, bool) {
	var hash [32]byte
	if len(b) != len(hash) {
		return hash, false
	}
	copy(hash[:], b)
	return hash, true
}

// forgetRevokedRefreshToken deletes the GrantRegistry entry of the grant
// whose refresh token, stored under refreshTokenHash, was just revoked,
// when a registry is set.
func (s *Server) forgetRevokedRefreshToken(ctx context.Context, refreshTokenHash [32]byte) error {
	if s.deps.GrantRegistry == nil {
		return nil
	}
	return s.deps.GrantRegistry.DeleteGrant(ctx, grantEntryKey(refreshTokenHash))
}

// RevokeSubjectGrants revokes every grant ListGrants lists for subject,
// as RevokeListedGrant revokes one, and returns how many it revoked: for
// ending a user's access when their account closes, or after it's
// compromised. It stops at the first failure, returning how many it had
// revoked and the error; the rest are still listed, so calling it again
// finishes the job.
//
// Closing an account also means denying the CIBA requests awaiting the
// user, with a BackchannelInbox (DenyBackchannelInteractions), and
// forgetting their pairwise subject identifiers, if the server maps
// them (pairwise.NewMapping): call the store's ForgetSubject
// (storage.PairwiseSubjectEraser) as well. Tokens
// already issued from a revoked grant stop working at every check that
// reads the revocation store; an access token whose resource server
// doesn't, and an ID token, expire on their own.
//
// RevokeSubjectGrants doesn't check who is asking: the application must
// make sure the request is subject's own, or an administrator's.
func (s *Server) RevokeSubjectGrants(ctx context.Context, subject SubjectID) (int, error) {
	grants, err := s.listGrants(ctx, subject)
	if err != nil {
		return 0, fmt.Errorf("server: revoke subject grants: %w", err)
	}
	for i, g := range grants {
		if err := s.revokeListed(ctx, g); err != nil {
			return i, err
		}
	}
	return len(grants), nil
}
