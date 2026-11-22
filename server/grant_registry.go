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
// after the token is stored, and revokeListed's second revocation of the
// token cover a revocation racing the issuance.
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
// Dependencies.GrantRegistry, when one is set. A revocation that lists
// the grant once recordGrant has recorded it can revoke the token
// before the token is created, which the GrantStore needn't remember (a
// SQL store's DELETE finds nothing to delete): the token would be live,
// and, once the revocation deletes the entry, unlisted, so unrevocable
// by RevokeSubjectGrants. Such a revocation revokes the token again
// after deleting the entry (revokeListed). So either this check comes
// after the deletion and finds the entry gone, and then it revokes the
// token itself and fails the issuance, or it finds the entry, and the
// deletion and the second revocation are still to come: the token
// exists by then, so that revocation revokes it.
func (s *Server) confirmGrantRecorded(ctx context.Context, subject string, refreshTokenHash [32]byte) error {
	if s.deps.GrantRegistry == nil {
		return nil
	}
	// Key asks for this entry alone, so the cost doesn't grow with the
	// subject's other grants; a store that lists them all anyway is
	// searched below.
	key := grantEntryKey(refreshTokenHash)
	entries, err := s.deps.GrantRegistry.ListGrants(ctx, storage.GrantListing{SubjectKey: s.grantSubjectKey(subject), Now: s.deps.Clock.Now(), Key: key})
	if err != nil {
		return s.withdrawRefreshToken(ctx, refreshTokenHash, fmt.Errorf("confirm the grant is recorded: %w", err))
	}
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

// listedGrant pairs a ListedGrant with its decoded record, and the
// registry entry both were read from.
type listedGrant struct {
	listed ListedGrant
	record grantRegistryRecord
	entry  storage.GrantEntry
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
	grants, unreadable, err := s.listGrants(ctx, subject)
	if err != nil {
		return nil, err
	}
	if unreadable != nil {
		return nil, unreadable
	}
	out := make([]ListedGrant, len(grants))
	for i, g := range grants {
		out[i] = g.listed
	}
	return out, nil
}

// listGrants returns subject's live grants, and, separately, the
// entries it couldn't read (an undecodable record, or a revocation check
// that failed) joined into unreadable: one bad entry doesn't hide the
// others from a caller revoking them. err is for a listing that failed
// as a whole.
func (s *Server) listGrants(ctx context.Context, subject SubjectID) (grants []listedGrant, unreadable, err error) {
	if s.deps.GrantRegistry == nil {
		return nil, nil, errors.New("server: list grants: Dependencies.GrantRegistry isn't set")
	}
	if subject.String() == "" {
		return nil, nil, errors.New("server: list grants: subject is empty")
	}
	entries, err := s.deps.GrantRegistry.ListGrants(ctx, storage.GrantListing{SubjectKey: s.grantSubjectKey(subject.String()), Now: s.deps.Clock.Now()})
	if err != nil {
		return nil, nil, fmt.Errorf("server: list grants: %w", err)
	}
	var bad []error
	for _, entry := range entries {
		g, ok, err := s.listedGrantFrom(ctx, subject, entry)
		if err != nil {
			bad = append(bad, fmt.Errorf("server: list grants: entry %s: %w", entry.Key, err))
			continue
		}
		if ok {
			grants = append(grants, g)
		}
	}
	slices.SortFunc(grants, func(a, b listedGrant) int {
		return cmp.Or(a.listed.IssuedAt.Compare(b.listed.IssuedAt), cmp.Compare(a.listed.ID, b.listed.ID))
	})
	return grants, errors.Join(bad...), nil
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
	// The entry's key is derived from the refresh token it revokes: an
	// entry naming another token's hash than its own key's, as an
	// unsealed record a database writer forged could, isn't the grant
	// it's listed as.
	if hash, ok := refreshTokenHashOf(record.RefreshTokenHash); !ok || grantEntryKey(hash) != entry.Key {
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
		entry:  entry,
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
	grants, unreadable, err := s.listGrants(ctx, subject)
	if err != nil {
		return fmt.Errorf("server: revoke listed grant: %w", err)
	}
	i := slices.IndexFunc(grants, func(g listedGrant) bool { return g.listed.ID == id })
	if i < 0 {
		if unreadable != nil {
			// It may be one of the entries that couldn't be read.
			return fmt.Errorf("server: revoke listed grant: %w", unreadable)
		}
		return ErrGrantNotListed
	}
	return s.revokeListed(ctx, grants[i])
}

// revokeListed revokes g as RevokeListedGrant describes. The grant goes
// before its refresh token, as in revokeRefreshToken, and the registry
// entry after both, so a failure part way leaves it listed for a retry.
//
// The refresh token is revoked again once the entry is deleted: the
// token's issuance may still be in flight, having recorded the entry
// this listed, and may store the token after the first revocation,
// which the GrantStore needn't remember for a token it didn't hold yet.
// The issuance confirms the entry is still recorded after storing the
// token (confirmGrantRecorded): if it does so after the deletion, it
// withdraws the token itself; if before, the token is stored by the
// time of the second revocation, which revokes it. A second revocation
// that fails records the entry again, so the grant is still listed for
// a retry.
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
	if err := s.deps.Grants.RevokeRefreshToken(ctx, hash); err != nil {
		return fmt.Errorf("server: revoke listed grant: %w", s.relistGrant(ctx, g, err))
	}
	return nil
}

// relistGrant records g's registry entry again, as it was listed, and
// returns cause, the failure that stopped g's revocation after its entry
// was deleted: the grant is then still listed for a retry. A failure to
// record it is joined to cause.
func (s *Server) relistGrant(ctx context.Context, g listedGrant, cause error) error {
	if err := s.deps.GrantRegistry.RecordGrant(ctx, storage.NewGrantEntry{
		Key: g.entry.Key, SubjectKey: s.grantSubjectKey(g.record.Subject),
		ClientID: g.entry.ClientID, Record: g.entry.Record, ExpiresAt: g.entry.ExpiresAt,
	}); err != nil {
		return errors.Join(cause, fmt.Errorf("list the grant again: %w", err))
	}
	return cause
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
// compromised. A grant it fails to revoke, or an entry it can't read,
// doesn't stop it: it revokes every other grant, then returns how many
// it revoked with every failure joined. What failed is still listed, so
// calling it again finishes the job.
//
// A grant whose refresh token isn't issued yet isn't listed: an
// authorization code not yet exchanged, or an approved CIBA request not
// yet polled, can still be redeemed for one within
// Limits.AuthorizationCodeLifetime or
// Limits.BackchannelAuthenticationRequestLifetime. To be sure nothing
// outlives an account, refuse its subject at authentication from then
// on, and call RevokeSubjectGrants again once the longer of those has
// passed.
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
	grants, unreadable, err := s.listGrants(ctx, subject)
	if err != nil {
		return 0, fmt.Errorf("server: revoke subject grants: %w", err)
	}
	revoked := 0
	failures := []error{unreadable}
	for _, g := range grants {
		if err := s.revokeListed(ctx, g); err != nil {
			failures = append(failures, err)
			continue
		}
		revoked++
	}
	if err := errors.Join(failures...); err != nil {
		return revoked, fmt.Errorf("server: revoke subject grants: %w", err)
	}
	return revoked, nil
}
