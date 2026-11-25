package server

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/internal/strictjson"
	"github.com/idfoundry/fapigo/storage"
)

// BackchannelSubjectResolver resolves a CIBA request's hint to the end
// user it names — see Dependencies.BackchannelSubjects.
type BackchannelSubjectResolver interface {
	// ResolveBackchannelSubject is called for a request that has passed
	// every other check, BackchannelHints included, before it is stored,
	// with the hints it carries (exactly one field set). It returns the
	// internal subject identifier of the end user the hint names; an
	// error wrapping ErrUnknownUserID or ErrExpiredLoginHintToken to
	// refuse the request with that CIBA §13 error; or any other error
	// for a failure to decide (refused with server_error).
	//
	// For an id_token_hint, hints.IDTokenHint is already verified, and
	// the user it names, when the server can tell, must be the one
	// returned, or the request is refused with server_error: the user
	// it names at a public client, whose sub is the internal subject,
	// and at a pairwise client whose subs the server can map back.
	ResolveBackchannelSubject(ctx context.Context, clientID fapi.ClientID, hints BackchannelAuthenticationHints) (SubjectID, error)
}

// hintUncheckedDescription is the public description of a CIBA request
// refused because its hint couldn't be checked or resolved.
const hintUncheckedDescription = "the hint could not be checked"

// backchannelHintError is the *Error refusing a CIBA request for err, a
// BackchannelHints or BackchannelSubjects failure. The public
// descriptions are fixed: the dependency's own error text stays out of
// the response.
func backchannelHintError(err error) *Error {
	switch {
	case errors.Is(err, ErrUnknownUserID):
		return newError(ErrorUnknownUserID, 400, "the hint does not identify an end user this server can authenticate", err)
	case errors.Is(err, ErrExpiredLoginHintToken):
		return newError(ErrorExpiredLoginHintToken, 400, "the login_hint_token has expired", err)
	default:
		return newError(ErrorServerError, 500, hintUncheckedDescription, err)
	}
}

// resolveBackchannelSubject checks the request's hints
// (checkBackchannelHints), then applies Dependencies.BackchannelSubjects,
// when set, returning the internal subject the request is bound to, or
// "" without a resolver. requiredInternal is the internal subject the
// request already named, if the server could tell
// (backchannelRequiredSubjects.resolverMust): the resolver must agree
// with it.
func (s *Server) resolveBackchannelSubject(ctx context.Context, clientID fapi.ClientID, hints BackchannelAuthenticationHints, requiredInternal string) (string, *Error) {
	if hintErr := s.checkBackchannelHints(ctx, clientID, hints); hintErr != nil {
		return "", hintErr
	}
	if s.deps.BackchannelSubjects == nil {
		return "", nil
	}
	subject, err := s.deps.BackchannelSubjects.ResolveBackchannelSubject(ctx, clientID, hints)
	if err != nil {
		return "", backchannelHintError(err)
	}
	if subject.String() == "" {
		return "", newError(ErrorServerError, 500, hintUncheckedDescription, errors.New("BackchannelSubjects resolved the hint to no subject"))
	}
	if requiredInternal != "" && subject.String() != requiredInternal {
		return "", newError(ErrorServerError, 500, hintUncheckedDescription, errors.New("BackchannelSubjects resolved the id_token_hint to another subject than the one it names"))
	}
	return subject.String(), nil
}

// PendingBackchannelInteraction is one CIBA request
// ListBackchannelInteractions returns: awaiting the end user's
// decision, with what to show them and the handle to complete it with.
type PendingBackchannelInteraction struct {
	// ID names the request among the user's pending ones, for a page to
	// link to or a form to send back: opaque, stable while the request is
	// pending, and safe to put in a URL, since it can't complete the
	// request. Find the request again by listing and matching it, a
	// listing Limits.MaxPendingBackchannelAuthenticationRequests bounds;
	// Handle is what completes it, and stays on the server.
	ID string

	Handle      BackchannelAuthenticationHandle
	Interaction BackchannelInteractionRequest
	ExpiresAt   time.Time
}

// backchannelInboxRecord is what a BackchannelInbox entry holds as its
// opaque Record.
type backchannelInboxRecord struct {
	Version int    `json:"v"`
	Issuer  string `json:"iss"`
	Handle  string `json:"handle"`
	Subject string `json:"sub"`
}

// backchannelInboxSubjectKey is the BackchannelInbox SubjectKey for
// subject at this server's issuer.
func (s *Server) backchannelInboxSubjectKey(subject string) string {
	sum := sha256.Sum256([]byte("fapigo backchannel inbox subject\x00" + s.cfg.Issuer.String() + "\x00" + subject))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// backchannelInboxID is PendingBackchannelInteraction.ID for the request
// whose handle hashes to handleHash: a digest of the hash, so the ID is
// neither the handle nor the store's key for it.
func backchannelInboxID(handleHash [32]byte) string {
	sum := sha256.Sum256(append([]byte("fapigo backchannel inbox id\x00"), handleHash[:]...))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// inboxFilingFailedDescription is the public description of a CIBA
// request refused because its end user's inbox couldn't take it, or
// couldn't count the requests it holds.
const inboxFilingFailedDescription = "failed to file the backchannel authentication request in the end user's inbox"

// storeBackchannelRequest stores the CIBA request
// BeginBackchannelAuthentication accepted: filed in the inbox of
// subject, the end user it's bound to (fileBackchannelRequest), refused
// if that leaves them over a cap on pending requests
// (checkPendingBackchannelRequests), and then persisted as stored. A
// request refused or not persisted is taken out of the inbox again
// (unfileBackchannelRequest), so it doesn't count against the caps
// until it expires. That includes one whose filing failed, since a
// store can keep an entry it reports failed.
//
// Neither the filing nor the removal ends with ctx, which net/http ends
// once the client hangs up. A removal that ended with it wouldn't run,
// and a filing that did could still land after its removal had run: a
// database client can return as soon as its context ends, while the
// database goes on to commit the write it was sent. Either way a client
// hanging up would leave its entry behind, and enough of them would
// take the user past a cap for every other client. Each write has
// inboxWriteTimeout of its own instead, so a store that stalls can hold
// the handler that long for the filing and again for the removal, even
// once the client has gone. Only a store that fails to remove an entry,
// or that stalls on a filing past that timeout and commits it later,
// leaves the entry behind.
func (s *Server) storeBackchannelRequest(ctx context.Context, handleRaw, subject string, stored storage.NewBackchannelAuthentication) *Error {
	fileCtx, cancelFile := context.WithTimeout(context.WithoutCancel(ctx), inboxWriteTimeout)
	defer cancelFile()
	if err := s.fileBackchannelRequest(fileCtx, stored.ClientID, handleRaw, subject, stored.ExpiresAt); err != nil {
		s.unfileBackchannelRequest(ctx, stored.HandleHash)
		return newError(ErrorServerError, 500, inboxFilingFailedDescription, err)
	}
	if capErr := s.checkPendingBackchannelRequests(ctx, stored.ClientID, subject); capErr != nil {
		s.unfileBackchannelRequest(ctx, stored.HandleHash)
		return capErr
	}
	if err := s.deps.Backchannel.CreateBackchannelAuthentication(ctx, stored); err != nil {
		s.unfileBackchannelRequest(ctx, stored.HandleHash)
		return newError(ErrorServerError, 500, "failed to persist backchannel authentication request", err)
	}
	return nil
}

// fileBackchannelRequest adds the request handleRaw names, bound to
// subject, to Dependencies.BackchannelInbox, when one is set. It runs
// before the request is stored, so no pending request exists that its
// user's inbox doesn't show.
func (s *Server) fileBackchannelRequest(ctx context.Context, clientID fapi.ClientID, handleRaw, subject string, expiresAt time.Time) error {
	if s.deps.BackchannelInbox == nil || subject == "" {
		return nil
	}
	record, err := strictjson.MarshalUnescaped(backchannelInboxRecord{Version: recordVersion, Issuer: s.cfg.Issuer.String(), Handle: handleRaw, Subject: subject})
	if err != nil {
		return err
	}
	return s.deps.BackchannelInbox.AddBackchannelRequest(ctx, storage.NewBackchannelInboxEntry{
		HandleHash: sha256.Sum256([]byte(handleRaw)), SubjectKey: s.backchannelInboxSubjectKey(subject),
		ClientID: clientID, Record: record, ExpiresAt: expiresAt,
	})
}

// checkPendingBackchannelRequests refuses the request clientID has just
// filed for subject if subject now has more pending requests than
// Limits.MaxPendingBackchannelAuthenticationRequests allows, or more from
// clientID than MaxPendingBackchannelAuthenticationRequestsPerClient:
// with access_denied, which CIBA Core §13 gives a request the OpenID
// Provider itself denies, and sends with HTTP 403. It counts the
// unexpired entries the inbox lists, by their ClientID, without reading
// their records. A request is counted from the moment it's filed, before
// it's checked, so requests filed at the same moment can be refused
// together but are never admitted together past a cap: whichever lists
// last counts every one still filed, since storage.BackchannelInbox
// requires an add to show at once. A listing that fails refuses the
// request as a filing failure does.
func (s *Server) checkPendingBackchannelRequests(ctx context.Context, clientID fapi.ClientID, subject string) *Error {
	if s.deps.BackchannelInbox == nil || subject == "" {
		return nil
	}
	now := s.deps.Clock.Now()
	entries, err := s.deps.BackchannelInbox.ListBackchannelRequests(ctx, storage.BackchannelInboxListing{
		SubjectKey: s.backchannelInboxSubjectKey(subject), Now: now,
	})
	if err != nil {
		return newError(ErrorServerError, 500, inboxFilingFailedDescription, err)
	}
	maxPending, maxFromClient := s.cfg.Limits.pendingBackchannelAuthenticationRequestCaps()
	pending, fromClient := 0, 0
	for _, entry := range entries {
		if !now.Before(entry.ExpiresAt) {
			continue
		}
		pending++
		if entry.ClientID == clientID {
			fromClient++
		}
	}
	if pending > maxPending || fromClient > maxFromClient {
		return newError(ErrorAccessDenied, 403, "too many backchannel authentication requests are awaiting this end user",
			fmt.Errorf("%d requests pending for the end user (at most %d), %d of them from the client (at most %d)", pending, maxPending, fromClient, maxFromClient))
	}
	return nil
}

// ListBackchannelInteractions returns the CIBA requests awaiting
// subject's decision, soonest to expire first: what subject's
// authentication device shows, on any instance sharing the store. It
// needs Dependencies.BackchannelInbox (and BackchannelSubjects, which
// files each request under the user its hint names). Complete one with
// CompleteBackchannelAuthentication and its Handle: only subject may
// approve it.
//
// A request leaves the inbox once decided, or when it expires. One whose
// decision was recorded but whose removal failed is still listed until
// it expires, and completing it again is refused as already decided.
//
// Each request listed costs store reads. Once ctx ends,
// ListBackchannelInteractions reads no more of them and fails with
// ctx's error, rather than returning part of the inbox.
//
// ListBackchannelInteractions doesn't check who is asking: the
// application must make sure the user is subject, as it does before
// approving.
func (s *Server) ListBackchannelInteractions(ctx context.Context, subject SubjectID) ([]PendingBackchannelInteraction, error) {
	pending, unreadable, err := s.listBackchannelInteractions(ctx, subject)
	if err != nil {
		return nil, err
	}
	if unreadable != nil {
		return nil, unreadable
	}
	return pending, nil
}

// listBackchannelInteractions returns the requests awaiting subject,
// and, separately, the entries it couldn't read (an undecodable record,
// or a request the backchannel store couldn't answer for) joined into
// unreadable, so one bad entry doesn't hide the others from
// DenyBackchannelInteractions. err is for a listing that failed as a
// whole, ctx ending before it finished among them.
func (s *Server) listBackchannelInteractions(ctx context.Context, subject SubjectID) (pending []PendingBackchannelInteraction, unreadable, err error) {
	if s.deps.BackchannelInbox == nil {
		return nil, nil, errors.New("server: list backchannel interactions: Dependencies.BackchannelInbox isn't set")
	}
	if subject.String() == "" {
		return nil, nil, errors.New("server: list backchannel interactions: subject is empty")
	}
	entries, err := s.deps.BackchannelInbox.ListBackchannelRequests(ctx, storage.BackchannelInboxListing{
		SubjectKey: s.backchannelInboxSubjectKey(subject.String()), Now: s.deps.Clock.Now(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("server: list backchannel interactions: %w", err)
	}
	var bad []error
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		p, ok, err := s.pendingBackchannelInteraction(ctx, subject, entry)
		if err != nil {
			bad = append(bad, fmt.Errorf("server: list backchannel interactions: %w", err))
			continue
		}
		if ok {
			pending = append(pending, p)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("server: list backchannel interactions: %w", err)
	}
	slices.SortFunc(pending, func(a, b PendingBackchannelInteraction) int {
		return cmp.Or(a.ExpiresAt.Compare(b.ExpiresAt), cmp.Compare(a.ID, b.ID))
	})
	return pending, errors.Join(bad...), nil
}

// pendingBackchannelInteraction rebuilds entry's request, reporting
// false for one that isn't a live request of subject's at this server:
// written by another issuer, expired, gone from the backchannel store,
// from a client no longer registered, or bound to another subject than
// the one it's filed under.
func (s *Server) pendingBackchannelInteraction(ctx context.Context, subject SubjectID, entry storage.BackchannelInboxEntry) (PendingBackchannelInteraction, bool, error) {
	var record backchannelInboxRecord
	if err := decodeRecord(entry.Record, &record.Version, &record); err != nil {
		return PendingBackchannelInteraction{}, false, fmt.Errorf("stored backchannel inbox entry: %w", err)
	}
	if !s.ownsRecord(record.Issuer) || record.Subject != subject.String() || !s.deps.Clock.Now().Before(entry.ExpiresAt) {
		return PendingBackchannelInteraction{}, false, nil
	}
	handle, err := ParseBackchannelAuthenticationHandle(record.Handle)
	if err != nil || sha256.Sum256([]byte(record.Handle)) != entry.HandleHash {
		return PendingBackchannelInteraction{}, false, nil
	}
	interaction, resolved, err := s.lookupBackchannelInteraction(ctx, handle)
	if err != nil {
		var serverErr *Error
		if errors.As(err, &serverErr) && (serverErr.Code() == ErrorInvalidRequest || serverErr.Code() == ErrorUnauthorizedClient) {
			return PendingBackchannelInteraction{}, false, nil
		}
		return PendingBackchannelInteraction{}, false, err
	}
	// The request itself names who may approve it: an entry filed under
	// someone else, as one a database writer moved could be, isn't theirs.
	if resolved != subject.String() {
		return PendingBackchannelInteraction{}, false, nil
	}
	return PendingBackchannelInteraction{ID: backchannelInboxID(entry.HandleHash), Handle: handle, Interaction: interaction, ExpiresAt: entry.ExpiresAt}, true, nil
}

// inboxWriteTimeout bounds each inbox write that doesn't end with its
// caller's context, storeBackchannelRequest's filing and
// unfileBackchannelRequest's removal: long enough for a store waiting on
// a write lock, as sqlstore's SQLite writes do for up to 10 seconds by
// default, and short enough that a store that never answers can't hold
// its caller for good.
const inboxWriteTimeout = 30 * time.Second

// unfileBackchannelRequest removes the request handleHash names from
// Dependencies.BackchannelInbox, when one is set: one decided, or one
// filed but then refused or not stored (storeBackchannelRequest).
// Best-effort, as the ping notification is: an entry left behind
// expires with its request, and completing a decided one again is
// refused, while one never stored isn't listed; until it expires,
// though, it counts against its end user's caps on pending requests. So
// ctx ending doesn't stop the removal: net/http ends a request's context
// once its client hangs up, which would otherwise let a client leave
// its refused requests' entries behind. inboxWriteTimeout bounds the
// removal instead.
func (s *Server) unfileBackchannelRequest(ctx context.Context, handleHash [32]byte) {
	if s.deps.BackchannelInbox == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), inboxWriteTimeout)
	defer cancel()
	_ = s.deps.BackchannelInbox.RemoveBackchannelRequest(ctx, handleHash)
}

// DenyBackchannelInteractions denies every CIBA request awaiting
// subject's decision (ListBackchannelInteractions), with reason, and
// returns how many it denied: for closing an account, or a user who
// wants every pending request refused at once. Each is completed as
// CompleteBackchannelAuthentication with Deny(reason) would: its client
// gets access_denied, a ping client is notified, and it leaves the
// inbox. One CompleteBackchannelAuthentication refuses as invalid or
// expired is passed over and not counted: decided meanwhile, by another
// call or instance, or expired — or not recorded because the store
// failed, which CompleteBackchannelAuthentication reports the same way,
// so check ListBackchannelInteractions when every request must be gone.
// Any other failure, or an entry it can't read, doesn't stop it: it
// denies every other request, then returns how many it denied with every
// failure joined. What failed is still listed, so calling it again
// finishes the job. If ctx ends before the requests are all listed, it
// denies none of them and returns ctx's error.
//
// Every denial is recorded before any ping client is notified, so a
// client whose notification endpoint doesn't answer can't hold up the
// other denials, or keep their requests approvable meanwhile. The
// notifications are then sent eight at a time, and the call returns
// once each has been sent or has failed; each can take as long as the
// notifier allows, backchannelhttp's Config.Timeout. So run it on a
// context that isn't tied to an interactive request's deadline, such as
// context.WithoutCancel(ctx) or a background job's: a store that honours
// ctx records no denial once ctx has ended, and a notification ctx's end
// overtakes is cut short. To empty an inbox for good, as when closing an
// account, have Dependencies.BackchannelSubjects stop resolving the
// user's hints first, so no new request is filed, then call it again
// until ListBackchannelInteractions lists nothing.
//
// DenyBackchannelInteractions doesn't check who is asking: the
// application must make sure the request is subject's own, or an
// administrator's.
func (s *Server) DenyBackchannelInteractions(ctx context.Context, subject SubjectID, reason string) (int, error) {
	pending, unreadable, err := s.listBackchannelInteractions(ctx, subject)
	if err != nil {
		return 0, fmt.Errorf("server: deny backchannel interactions: %w", err)
	}
	failures := []error{unreadable}
	var decided []storage.DecidedBackchannelAuthentication
	for _, p := range pending {
		denial, failure := s.recordBackchannelDecision(ctx, CompleteBackchannelAuthenticationRequest{Handle: p.Handle, Result: Deny(reason)})
		switch {
		case failure == nil:
			decided = append(decided, denial)
		case failure.Code() == ErrorInvalidRequest || failure.Code() == ErrorExpiredToken:
			// Decided or expired since it was listed: its entry is stale.
			s.unfileBackchannelRequest(ctx, backchannelHandleHash(p.Handle))
		default:
			failures = append(failures, failure)
		}
	}
	// Only now, with every denial recorded, are ping clients notified.
	s.notifyBackchannelPings(ctx, decided)
	if err := errors.Join(failures...); err != nil {
		return len(decided), fmt.Errorf("server: deny backchannel interactions: %w", err)
	}
	return len(decided), nil
}
