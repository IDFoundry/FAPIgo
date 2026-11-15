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
	// returned.
	ResolveBackchannelSubject(ctx context.Context, clientID fapi.ClientID, hints BackchannelAuthenticationHints) (SubjectID, error)
}

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
		return newError(ErrorServerError, 500, "the hint could not be checked", err)
	}
}

// resolveBackchannelSubject applies Dependencies.BackchannelSubjects,
// when set, returning the internal subject the request is bound to, or
// "" without a resolver. requiredInternal is the subject an
// id_token_hint already named, if the server could map it: the
// resolver must agree with it.
func (s *Server) resolveBackchannelSubject(ctx context.Context, clientID fapi.ClientID, hints BackchannelAuthenticationHints, requiredInternal string) (string, *Error) {
	if s.deps.BackchannelSubjects == nil {
		return "", nil
	}
	subject, err := s.deps.BackchannelSubjects.ResolveBackchannelSubject(ctx, clientID, hints)
	if err != nil {
		return "", backchannelHintError(err)
	}
	if subject.String() == "" {
		return "", newError(ErrorServerError, 500, "the hint could not be checked", errors.New("BackchannelSubjects resolved the hint to no subject"))
	}
	if requiredInternal != "" && subject.String() != requiredInternal {
		return "", newError(ErrorServerError, 500, "the hint could not be checked", errors.New("BackchannelSubjects resolved the id_token_hint to another subject than the one it names"))
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
	// request. Find the request again by listing and matching it; Handle
	// is what completes it, and stays on the server.
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
// ListBackchannelInteractions doesn't check who is asking: the
// application must make sure the user is subject, as it does before
// approving.
func (s *Server) ListBackchannelInteractions(ctx context.Context, subject SubjectID) ([]PendingBackchannelInteraction, error) {
	if s.deps.BackchannelInbox == nil {
		return nil, errors.New("server: list backchannel interactions: Dependencies.BackchannelInbox isn't set")
	}
	if subject.String() == "" {
		return nil, errors.New("server: list backchannel interactions: subject is empty")
	}
	entries, err := s.deps.BackchannelInbox.ListBackchannelRequests(ctx, storage.BackchannelInboxListing{
		SubjectKey: s.backchannelInboxSubjectKey(subject.String()), Now: s.deps.Clock.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("server: list backchannel interactions: %w", err)
	}
	var out []PendingBackchannelInteraction
	for _, entry := range entries {
		pending, ok, err := s.pendingBackchannelInteraction(ctx, subject, entry)
		if err != nil {
			return nil, fmt.Errorf("server: list backchannel interactions: %w", err)
		}
		if ok {
			out = append(out, pending)
		}
	}
	slices.SortFunc(out, func(a, b PendingBackchannelInteraction) int {
		return cmp.Or(a.ExpiresAt.Compare(b.ExpiresAt), cmp.Compare(a.ID, b.ID))
	})
	return out, nil
}

// pendingBackchannelInteraction rebuilds entry's request, reporting
// false for one that isn't a live request of subject's at this server:
// written by another issuer, expired, or gone from the backchannel
// store.
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
	interaction, err := s.LookupBackchannelInteraction(ctx, handle)
	if err != nil {
		var serverErr *Error
		if errors.As(err, &serverErr) && serverErr.Code() == ErrorInvalidRequest {
			return PendingBackchannelInteraction{}, false, nil
		}
		return PendingBackchannelInteraction{}, false, err
	}
	return PendingBackchannelInteraction{ID: backchannelInboxID(entry.HandleHash), Handle: handle, Interaction: interaction, ExpiresAt: entry.ExpiresAt}, true, nil
}

// unfileBackchannelRequest removes the decided request handleHash names
// from Dependencies.BackchannelInbox, when one is set. Best-effort, as
// the ping notification is: the decision is recorded, and an entry left
// behind is refused as already decided and expires with the request.
func (s *Server) unfileBackchannelRequest(ctx context.Context, handleHash [32]byte) {
	if s.deps.BackchannelInbox == nil {
		return
	}
	_ = s.deps.BackchannelInbox.RemoveBackchannelRequest(ctx, handleHash)
}
