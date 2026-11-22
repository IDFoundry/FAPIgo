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
	// it expires: its stored expiry, or, when Limits.RefreshTokenLifetime
	// has been shortened since, IssuedAt plus the current lifetime, past
	// which a refresh is refused all the same.
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

// listedGrant pairs a ListedGrant with its decoded record, the registry
// entry both were read from, and the GrantStore key of the grant's
// refresh token, which the entry's key was checked to be derived from.
type listedGrant struct {
	listed           ListedGrant
	record           grantRegistryRecord
	entry            storage.GrantEntry
	refreshTokenHash [32]byte
}

// grantListing is what listGrants read from Dependencies.GrantRegistry
// for one subject, at now.
type grantListing struct {
	// grants are the subject's grants that are neither revoked nor past
	// their refresh tokens' stored expiry, oldest first. ListGrants
	// leaves out those whose refresh tokens were issued longer ago than
	// the current Limits.RefreshTokenLifetime, which a refresh refuses,
	// but RevokeListedGrant and RevokeSubjectGrants still revoke them: a
	// longer lifetime applying again, raised back or on another instance,
	// would make those refresh tokens redeemable.
	grants []listedGrant

	// revoked are the subject's grants revoked another way (RevokeGrant,
	// RevokeToken, or the reuse of the authorization code they came
	// from) whose entries the registry still records. ListGrants lists
	// none of them, but the GrantStore may still hold their refresh
	// tokens (see sweepRevokedGrants).
	revoked []listedGrant

	// unreadable joins the failures to read an entry (an undecodable
	// record, or a revocation check that failed): one bad entry doesn't
	// hide the others from a caller revoking them.
	unreadable error

	now time.Time
}

// grantEntryState is what listedGrantFrom finds a registry entry to be.
type grantEntryState int

const (
	// grantEntryIgnored isn't one of the subject's grants at this
	// server: an entry written by another issuer, for another subject,
	// past its expiry, or naming another refresh token than its key's.
	grantEntryIgnored grantEntryState = iota

	// grantEntryLive is one of grantListing.grants.
	grantEntryLive

	// grantEntryRevoked is one of grantListing.revoked.
	grantEntryRevoked
)

// ListGrants returns the grants subject authorized that a client still
// holds a refresh token for, oldest first: for a "connected apps" page.
// To revoke them all when an account closes, use RevokeSubjectGrants. It
// needs Dependencies.GrantRegistry, which records a grant when its
// refresh token is issued. A grant whose access tokens alone were
// issued, with no refresh token, isn't listed: they expire within
// Limits.AccessTokenLifetime. A grant revoked another way (RevokeGrant,
// RevokeToken, or the reuse of its authorization code) isn't listed
// either, nor one whose refresh token has expired: past its stored
// expiry, or issued longer ago than the current
// Limits.RefreshTokenLifetime, as a refresh judges it. So where
// instances run different Limits, during a rollout or on a canary, one
// with a shorter lifetime doesn't list a grant whose refresh token an
// instance with a longer one still redeems, and a page it serves can't
// show or disconnect that grant: RevokeSubjectGrants revokes it all the
// same, as RevokeListedGrant does with an ID listed before.
//
// ListGrants doesn't check who is asking: the application must make sure
// the user is subject.
func (s *Server) ListGrants(ctx context.Context, subject SubjectID) ([]ListedGrant, error) {
	l, err := s.listGrants(ctx, subject)
	if err != nil {
		return nil, err
	}
	if l.unreadable != nil {
		return nil, l.unreadable
	}
	out := make([]ListedGrant, 0, len(l.grants))
	for _, g := range l.grants {
		if issuedWithin(&g.record.IssuedAt, s.cfg.Limits.RefreshTokenLifetime, l.now) {
			out = append(out, g.listed)
		}
	}
	return out, nil
}

// listGrants reads subject's grants from Dependencies.GrantRegistry (see
// grantListing). err is for a listing that failed as a whole.
func (s *Server) listGrants(ctx context.Context, subject SubjectID) (grantListing, error) {
	if s.deps.GrantRegistry == nil {
		return grantListing{}, errors.New("server: list grants: Dependencies.GrantRegistry isn't set")
	}
	if subject.String() == "" {
		return grantListing{}, errors.New("server: list grants: subject is empty")
	}
	l := grantListing{now: s.deps.Clock.Now()}
	entries, err := s.deps.GrantRegistry.ListGrants(ctx, storage.GrantListing{SubjectKey: s.grantSubjectKey(subject.String()), Now: l.now})
	if err != nil {
		return grantListing{}, fmt.Errorf("server: list grants: %w", err)
	}
	var bad []error
	for _, entry := range entries {
		g, state, err := s.listedGrantFrom(ctx, subject, entry, l.now)
		switch {
		case err != nil:
			bad = append(bad, fmt.Errorf("server: list grants: entry %s: %w", entry.Key, err))
		case state == grantEntryLive:
			l.grants = append(l.grants, g)
		case state == grantEntryRevoked:
			l.revoked = append(l.revoked, g)
		}
	}
	slices.SortFunc(l.grants, func(a, b listedGrant) int {
		return cmp.Or(a.listed.IssuedAt.Compare(b.listed.IssuedAt), cmp.Compare(a.listed.ID, b.listed.ID))
	})
	l.unreadable = errors.Join(bad...)
	return l, nil
}

// listedGrantFrom decodes entry, read at now, and reports what it is to
// subject (grantEntryState).
func (s *Server) listedGrantFrom(ctx context.Context, subject SubjectID, entry storage.GrantEntry, now time.Time) (listedGrant, grantEntryState, error) {
	var record grantRegistryRecord
	if err := decodeRecord(entry.Record, &record.Version, &record); err != nil {
		return listedGrant{}, grantEntryIgnored, fmt.Errorf("stored grant registry entry: %w", err)
	}
	if !s.ownsRecord(record.Issuer) || record.Subject != subject.String() || !now.Before(entry.ExpiresAt) {
		return listedGrant{}, grantEntryIgnored, nil
	}
	// The entry's key is derived from the refresh token it revokes: an
	// entry naming another token's hash than its own key's, as an
	// unsealed record a database writer forged could, isn't the grant
	// it's listed as.
	hash, ok := refreshTokenHashOf(record.RefreshTokenHash)
	if !ok || grantEntryKey(hash) != entry.Key {
		return listedGrant{}, grantEntryIgnored, nil
	}
	g := listedGrant{record: record, entry: entry, refreshTokenHash: hash}
	if revokedErr := s.checkGrantNotRevoked(ctx, grantRecord{GrantID: record.GrantID, CodeGrantID: record.CodeGrantID}); revokedErr != nil {
		if revokedErr.Code() == ErrorInvalidGrant {
			return g, grantEntryRevoked, nil
		}
		return listedGrant{}, grantEntryIgnored, revokedErr
	}
	var details []json.RawMessage
	if len(record.AuthorizationDetails) > 0 {
		if err := json.Unmarshal(record.AuthorizationDetails, &details); err != nil {
			return listedGrant{}, grantEntryIgnored, fmt.Errorf("stored grant registry entry's authorization details: %w", err)
		}
	}
	g.listed = ListedGrant{
		ID: entry.Key, GrantID: record.GrantID, ClientID: entry.ClientID, GrantType: record.GrantType,
		Scope: slices.Clone(record.Scope), AuthorizationDetails: details, Resources: slices.Clone(record.Resources),
		IssuedAt: record.IssuedAt, ExpiresAt: s.refreshTokenExpiry(record.IssuedAt, entry.ExpiresAt),
	}
	return g, grantEntryLive, nil
}

// refreshTokenExpiry is when a refresh token issued at issuedAt, and
// stored to expire at storedExpiry, stops being redeemable under the
// current Limits: its stored expiry, or its issue time plus
// Limits.RefreshTokenLifetime once the lifetime has been shortened since
// (issuedWithin).
func (s *Server) refreshTokenExpiry(issuedAt, storedExpiry time.Time) time.Time {
	if byLifetime := issuedAt.Add(s.cfg.Limits.RefreshTokenLifetime); byLifetime.Before(storedExpiry) {
		return byLifetime
	}
	return storedExpiry
}

// RevokeListedGrant revokes the grant id names (ListedGrant.ID), if it's
// one of subject's listed grants, and ErrGrantNotListed otherwise: its
// refresh token, and every access token issued from it, through its
// GrantID (as RevokeGrant does) and its authorization code or CIBA
// request (as the code's reuse does), whichever it has. A grant served
// with neither (IssueRefreshToken without a GrantID) has its refresh
// token revoked, and its access tokens expire within
// Limits.AccessTokenLifetime. A grant ListGrants no longer lists only
// because its refresh token was issued longer ago than the current
// Limits.RefreshTokenLifetime is revoked all the same: a longer lifetime
// applying again would make that refresh token redeemable.
//
// It also revokes the refresh tokens of subject's grants revoked another
// way that the GrantStore may still hold, as RevokeSubjectGrants does:
// best effort when id names a listed grant, and otherwise reporting a
// failure to, as it reports an entry it couldn't read, rather than
// ErrGrantNotListed, since id may name that grant. A grant whose
// revocation here failed after RevokeGrant had recorded its GrantID as
// revoked is then one of those, so calling RevokeListedGrant again with
// the same id still finishes the job, reporting any failure to: once it
// has, it answers ErrGrantNotListed, as it does for any grant revoked
// another way, which a caller can treat as done, since it never
// answers that when something failed.
//
// Taking subject as well as id means an ID from a form can only revoke a
// grant of the subject the application has authenticated: the
// application must still make sure the user is subject.
func (s *Server) RevokeListedGrant(ctx context.Context, subject SubjectID, id string) error {
	l, err := s.listGrants(ctx, subject)
	if err != nil {
		return fmt.Errorf("server: revoke listed grant: %w", err)
	}
	if i := slices.IndexFunc(l.grants, func(g listedGrant) bool { return g.listed.ID == id }); i >= 0 {
		revokeErr := s.revokeListed(ctx, l.grants[i])
		_ = s.sweepRevokedGrants(ctx, l.revoked)
		return revokeErr
	}
	// id may name a grant revoked another way, or an entry that couldn't
	// be read: a failure to revoke the first's refresh token, or to read
	// the second, is reported rather than claiming it isn't listed.
	if err := errors.Join(s.sweepRevokedGrants(ctx, l.revoked), l.unreadable); err != nil {
		return fmt.Errorf("server: revoke listed grant: %w", err)
	}
	return ErrGrantNotListed
}

// revokeListed revokes g as RevokeListedGrant describes. The grant goes
// before its refresh token, as in revokeRefreshToken, and the registry
// entry after both, so a failure part way leaves it listed for a retry,
// or, once RevokeGrant has recorded its GrantID as revoked, recorded
// among the revoked grants whose refresh tokens a retry revokes
// (sweepRevokedGrants).
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
	if err := s.deps.Grants.RevokeRefreshToken(ctx, g.refreshTokenHash); err != nil {
		return fmt.Errorf("server: revoke listed grant: %w", err)
	}
	if err := s.deps.GrantRegistry.DeleteGrant(ctx, g.listed.ID); err != nil {
		return fmt.Errorf("server: revoke listed grant: %w", err)
	}
	if err := s.deps.Grants.RevokeRefreshToken(ctx, g.refreshTokenHash); err != nil {
		return fmt.Errorf("server: revoke listed grant: %w", s.relistGrant(ctx, g, err))
	}
	return nil
}

// sweepRevokedGrants revokes the refresh token of each of revoked,
// subject's grants revoked another way whose GrantRegistry entries are
// still recorded (grantListing.revoked), then deletes its entry, and
// returns the failures joined. Each grant's revocation record refuses
// its refresh token already, but a GrantStore that isn't a
// storage.GrantRefreshTokenRevoker still holds the token after
// RevokeGrant, as does one that failed to revoke it, and a refresh token
// lifetime longer than the record applying later would make the token
// redeemable again (see RevokeGrant); revoking it ends it for good. The
// entry is how the token is found, so it's deleted only once the token
// is revoked: a failure leaves it recorded for the next call. Most
// revocations delete the entry themselves (RevokeToken, and RevokeGrant
// with a GrantRefreshTokenRevoker), so this finds those they couldn't,
// and those RevokeGrant leaves with any other GrantStore.
func (s *Server) sweepRevokedGrants(ctx context.Context, revoked []listedGrant) error {
	var failures []error
	for _, g := range revoked {
		if err := s.deps.Grants.RevokeRefreshToken(ctx, g.refreshTokenHash); err != nil {
			failures = append(failures, fmt.Errorf("server: revoke the refresh token of revoked grant %s: %w", g.entry.Key, err))
			continue
		}
		if err := s.deps.GrantRegistry.DeleteGrant(ctx, g.entry.Key); err != nil {
			failures = append(failures, fmt.Errorf("server: delete the registry entry of revoked grant %s: %w", g.entry.Key, err))
		}
	}
	return errors.Join(failures...)
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

// RevokeSubjectGrants revokes each of subject's grants RevokeListedGrant
// would revoke, as it revokes one — every grant ListGrants lists, and
// any it no longer lists only because of the current
// Limits.RefreshTokenLifetime — and returns how many it revoked: for
// ending a user's access when their account closes, or after it's
// compromised. It also revokes the refresh tokens of subject's grants
// revoked another way (RevokeGrant, RevokeToken, or the reuse of an
// authorization code), and removes their entries, without counting
// them: such a grant's revocation record refuses its refresh token, but
// a GrantStore that isn't a storage.GrantRefreshTokenRevoker still holds
// the token after RevokeGrant, as does one that failed to revoke it,
// and the record lapses in time (see RevokeGrant).
//
// A grant it fails to revoke, or an entry it can't read, doesn't stop
// it: it revokes every other grant, then returns how many it revoked
// with every failure joined. What failed is still in the GrantRegistry,
// so calling it again finishes the job: a grant whose revocation failed
// is still listed, or, if RevokeGrant had recorded its GrantID as
// revoked before failing to revoke its refresh tokens, is one of the
// grants revoked another way, whose refresh token the next call revokes,
// reporting a failure to.
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
	l, err := s.listGrants(ctx, subject)
	if err != nil {
		return 0, fmt.Errorf("server: revoke subject grants: %w", err)
	}
	revoked := 0
	failures := []error{l.unreadable}
	for _, g := range l.grants {
		if err := s.revokeListed(ctx, g); err != nil {
			failures = append(failures, err)
			continue
		}
		revoked++
	}
	failures = append(failures, s.sweepRevokedGrants(ctx, l.revoked))
	if err := errors.Join(failures...); err != nil {
		return revoked, fmt.Errorf("server: revoke subject grants: %w", err)
	}
	return revoked, nil
}
