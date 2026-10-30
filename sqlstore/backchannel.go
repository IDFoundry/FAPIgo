package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"
)

// BackchannelAuthenticationStore is a
// storage.BackchannelAuthenticationStore: server.Dependencies.Backchannel,
// for CIBA. Each request is one row, keyed by the server's digest of
// its auth_req_id and found by the digest of its handle too; its
// status, poll bookkeeping and expiry are columns, and the request and
// decision sealable blobs.
type BackchannelAuthenticationStore struct{ d *DB }

// Backchannel returns d's storage.BackchannelAuthenticationStore.
func (d *DB) Backchannel() *BackchannelAuthenticationStore { return &BackchannelAuthenticationStore{d} }

// backchannelRecordVersion is the version of backchannelRecord's and
// backchannelDecision's JSON.
const backchannelRecordVersion = 1

// backchannelRecord is a request's record column: what the server
// needs back from it. The auth_req_id and client notification token are
// set for ping delivery only, and are secrets the server presents, so
// they're here, where a Sealer seals them, rather than in columns.
type backchannelRecord struct {
	Version                 int    `json:"v"`
	Request                 []byte `json:"request,omitempty"`
	AuthReqID               string `json:"auth_req_id,omitempty"`
	ClientNotificationToken string `json:"client_notification_token,omitempty"`
}

// backchannelDecision is a request's decision column: empty but for its
// version while the request is pending.
type backchannelDecision struct {
	Version int    `json:"v"`
	Grant   []byte `json:"grant,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

var (
	// errBackchannelOtherClient is PollBackchannelAuthentication's
	// answer for another client's auth_req_id.
	errBackchannelOtherClient = errors.New("sqlstore: poll backchannel authentication: auth_req_id belongs to another client")

	// errBackchannelDecided is DecideBackchannelAuthentication's answer
	// for a request already decided.
	errBackchannelDecided = errors.New("sqlstore: decide backchannel authentication: already decided")

	// errRefused rolls back a transaction whose outcome is a refusal
	// that leaves the row as it was.
	errRefused = errors.New("sqlstore: refused")
)

// CreateBackchannelAuthentication implements
// storage.BackchannelAuthenticationStore, storing the request pending.
func (s *BackchannelAuthenticationStore) CreateBackchannelAuthentication(ctx context.Context, record storage.NewBackchannelAuthentication) error {
	if !validTextKey(string(record.ClientID)) {
		return errors.New("sqlstore: create backchannel authentication: client_id isn't valid UTF-8 without NUL")
	}
	if record.DeliveryMode != "poll" && record.DeliveryMode != "ping" {
		return fmt.Errorf("sqlstore: create backchannel authentication: delivery mode %q isn't poll or ping", record.DeliveryMode)
	}
	plainRecord, err := json.Marshal(backchannelRecord{
		Version: backchannelRecordVersion, Request: record.Request,
		AuthReqID: record.AuthReqID, ClientNotificationToken: record.ClientNotificationToken.Reveal(),
	})
	if err != nil {
		return fmt.Errorf("sqlstore: create backchannel authentication: %w", err)
	}
	plainDecision, err := json.Marshal(backchannelDecision{Version: backchannelRecordVersion})
	if err != nil {
		return fmt.Errorf("sqlstore: create backchannel authentication: %w", err)
	}
	expires := nanos(record.ExpiresAt)
	key, clientID := string(record.AuthReqIDHash[:]), string(record.ClientID)
	err = s.d.writeOne(ctx, func(q querier) error {
		sealedRecord, err := s.d.seal(blobRef{backchannelTable, recordColumn, key, clientID}, plainRecord)
		if err != nil {
			return err
		}
		sealedDecision, err := s.d.seal(blobRef{backchannelTable, decisionColumn, key, clientID}, plainDecision)
		if err != nil {
			return err
		}
		_, err = q.ExecContext(ctx, s.d.q("INSERT INTO {backchannel_authentications} (auth_req_id_hash, handle_hash, client_id, delivery_mode, record, decision, status, poll_interval, expires_at, sweep_after) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
			record.AuthReqIDHash[:], record.HandleHash[:], clientID, record.DeliveryMode, sealedRecord, sealedDecision,
			int(storage.BackchannelAuthenticationPending), int64(record.PollInterval), expires, expires)
		return err
	})
	if err != nil {
		return unavailable("create backchannel authentication", err)
	}
	return nil
}

// LookupBackchannelAuthentication implements
// storage.BackchannelAuthenticationStore: a read, which changes nothing.
func (s *BackchannelAuthenticationStore) LookupBackchannelAuthentication(ctx context.Context, handleHash [32]byte) (storage.LookedUpBackchannelAuthentication, error) {
	var key []byte
	var clientID string
	var stored []byte
	err := s.d.queryRow(ctx, "SELECT auth_req_id_hash, client_id, record FROM {backchannel_authentications} WHERE handle_hash = ?",
		handleHash[:]).Scan(&key, &clientID, &stored)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return storage.LookedUpBackchannelAuthentication{}, fmt.Errorf("sqlstore: look up backchannel authentication: %w", notFound("handle"))
	case err != nil:
		return storage.LookedUpBackchannelAuthentication{}, unavailable("look up backchannel authentication", err)
	}
	record, err := s.openRecord(string(key), clientID, stored)
	if err != nil {
		return storage.LookedUpBackchannelAuthentication{}, fmt.Errorf("sqlstore: look up backchannel authentication: %w", err)
	}
	return storage.LookedUpBackchannelAuthentication{ClientID: fapi.ClientID(clientID), Request: rawJSON(record.Request)}, nil
}

// DecideBackchannelAuthentication implements
// storage.BackchannelAuthenticationStore. In one transaction, an UPDATE
// … RETURNING records the status only if the request is still pending —
// of concurrent decisions exactly one finds it so — locking its row,
// clears a ping request's last poll, so its next poll isn't held to the
// interval, and then the decision is written.
func (s *BackchannelAuthenticationStore) DecideBackchannelAuthentication(ctx context.Context, decision storage.DecideBackchannelAuthentication) (storage.DecidedBackchannelAuthentication, error) {
	switch decision.Status {
	case storage.BackchannelAuthenticationApproved, storage.BackchannelAuthenticationDenied, storage.BackchannelAuthenticationAuthenticationFailed:
	default:
		return storage.DecidedBackchannelAuthentication{}, fmt.Errorf("sqlstore: decide backchannel authentication: status %d isn't a decision", decision.Status)
	}
	plainDecision, err := json.Marshal(backchannelDecision{Version: backchannelRecordVersion, Grant: decision.Grant, Reason: decision.Reason})
	if err != nil {
		return storage.DecidedBackchannelAuthentication{}, fmt.Errorf("sqlstore: decide backchannel authentication: %w", err)
	}
	var out storage.DecidedBackchannelAuthentication
	err = s.d.write(ctx, func(q querier) error {
		var key []byte
		var clientID, deliveryMode string
		var stored []byte
		if err := q.QueryRowContext(ctx, s.d.q("UPDATE {backchannel_authentications} SET status = ?, last_polled_at = CASE WHEN delivery_mode = ? THEN NULL ELSE last_polled_at END WHERE handle_hash = ? AND status = ? RETURNING auth_req_id_hash, client_id, delivery_mode, record"),
			int(decision.Status), "ping", decision.HandleHash[:], int(storage.BackchannelAuthenticationPending)).Scan(&key, &clientID, &deliveryMode, &stored); err != nil {
			return err
		}
		sealed, err := s.d.seal(blobRef{backchannelTable, decisionColumn, string(key), clientID}, plainDecision)
		if err != nil {
			return err
		}
		if _, err := q.ExecContext(ctx, s.d.q("UPDATE {backchannel_authentications} SET decision = ? WHERE auth_req_id_hash = ?"), sealed, key); err != nil {
			return err
		}
		record, err := s.openRecord(string(key), clientID, stored)
		if err != nil {
			return err
		}
		out = storage.DecidedBackchannelAuthentication{
			ClientID: fapi.ClientID(clientID), DeliveryMode: deliveryMode,
			ClientNotificationToken: fapi.NewSecret(record.ClientNotificationToken), AuthReqID: record.AuthReqID,
		}
		return nil
	})
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return storage.DecidedBackchannelAuthentication{}, s.whyUndecided(ctx, decision.HandleHash)
	case err != nil:
		return storage.DecidedBackchannelAuthentication{}, unavailable("decide backchannel authentication", err)
	}
	return out, nil
}

// whyUndecided is DecideBackchannelAuthentication's error for a handle
// its UPDATE didn't decide: unknown, or already decided.
func (s *BackchannelAuthenticationStore) whyUndecided(ctx context.Context, handleHash [32]byte) error {
	var n int
	if err := s.d.queryRow(ctx, "SELECT COUNT(*) FROM {backchannel_authentications} WHERE handle_hash = ?", handleHash[:]).Scan(&n); err != nil {
		return unavailable("decide backchannel authentication", err)
	}
	if n == 0 {
		return fmt.Errorf("sqlstore: decide backchannel authentication: %w", notFound("handle"))
	}
	return errBackchannelDecided
}

// polledRow is a request's row as PollBackchannelAuthentication locks
// it.
type polledRow struct {
	clientID         string
	record, decision []byte
	status, redeemed int
	interval         int64
	lastPolled       sql.NullInt64
	expires          int64
}

// refusal is the error a poll gets, leaving the row unchanged, before
// anything else is checked: another client's request, an approval
// already spent, or an expired request.
func (r polledRow) refusal(poll storage.PollBackchannelAuthentication) error {
	switch {
	case poll.ClientID != "" && string(poll.ClientID) != r.clientID:
		return errBackchannelOtherClient
	case r.redeemed != 0:
		return &storage.BackchannelAuthenticationAlreadyRedeemedError{}
	case !poll.Now.Before(timeOf(r.expires)):
		return &storage.BackchannelAuthenticationExpiredError{}
	}
	return nil
}

// tooSoon reports whether a poll at now comes before the interval since
// the last counted poll has elapsed.
func (r polledRow) tooSoon(now time.Time) bool {
	return r.lastPolled.Valid && now.Sub(timeOf(r.lastPolled.Int64)) < time.Duration(r.interval)
}

// PollBackchannelAuthentication implements
// storage.BackchannelAuthenticationStore. In one transaction, an UPDATE
// … RETURNING that changes nothing locks the row and reads it; then the
// poll is checked (another client's, already redeemed and expired
// requests are refused, the row left as it was), recorded — a poll
// before the interval has elapsed is too, and gets slow_down — and, if
// the request is approved, marked redeemed. Of concurrent polls of an
// approval, exactly one finds it unredeemed.
func (s *BackchannelAuthenticationStore) PollBackchannelAuthentication(ctx context.Context, poll storage.PollBackchannelAuthentication) (storage.PolledBackchannelAuthentication, error) {
	var out storage.PolledBackchannelAuthentication
	var refusal error
	err := s.d.write(ctx, func(q querier) error {
		var err error
		out, err = s.pollLocked(ctx, q, poll, &refusal)
		return err
	})
	switch {
	case refusal != nil && (err == nil || errors.Is(err, errRefused)):
		return storage.PolledBackchannelAuthentication{}, refusal
	case errors.Is(err, sql.ErrNoRows):
		return storage.PolledBackchannelAuthentication{}, fmt.Errorf("sqlstore: poll backchannel authentication: %w", notFound("auth_req_id"))
	case err != nil:
		return storage.PolledBackchannelAuthentication{}, unavailable("poll backchannel authentication", err)
	}
	return out, nil
}

// pollLocked is PollBackchannelAuthentication's transaction on q,
// setting *refusal to the poll's refusal, if any. A refusal that leaves
// the row as it was comes with errRefused, which rolls the transaction
// back; slow_down comes with a nil error, so its poll is recorded.
func (s *BackchannelAuthenticationStore) pollLocked(ctx context.Context, q querier, poll storage.PollBackchannelAuthentication, refusal *error) (storage.PolledBackchannelAuthentication, error) {
	var r polledRow
	if err := q.QueryRowContext(ctx, s.d.q("UPDATE {backchannel_authentications} SET sweep_after = sweep_after WHERE auth_req_id_hash = ? RETURNING client_id, record, decision, status, redeemed, poll_interval, last_polled_at, expires_at"),
		poll.AuthReqIDHash[:]).Scan(&r.clientID, &r.record, &r.decision, &r.status, &r.redeemed, &r.interval, &r.lastPolled, &r.expires); err != nil {
		return storage.PolledBackchannelAuthentication{}, err
	}
	if *refusal = r.refusal(poll); *refusal != nil {
		return storage.PolledBackchannelAuthentication{}, errRefused
	}
	redeemed := 0
	if r.tooSoon(poll.Now) {
		*refusal = &storage.BackchannelAuthenticationSlowDownError{}
	} else if r.status == int(storage.BackchannelAuthenticationApproved) {
		redeemed = 1
	}
	if _, err := q.ExecContext(ctx, s.d.q("UPDATE {backchannel_authentications} SET last_polled_at = ?, redeemed = ? WHERE auth_req_id_hash = ?"),
		nanos(poll.Now), redeemed, poll.AuthReqIDHash[:]); err != nil || *refusal != nil {
		return storage.PolledBackchannelAuthentication{}, err
	}
	return s.polled(string(poll.AuthReqIDHash[:]), r)
}

// polled is what a poll of r, keyed by key, returns.
func (s *BackchannelAuthenticationStore) polled(key string, r polledRow) (storage.PolledBackchannelAuthentication, error) {
	record, err := s.openRecord(key, r.clientID, r.record)
	if err != nil {
		return storage.PolledBackchannelAuthentication{}, err
	}
	plain, err := s.d.open(blobRef{backchannelTable, decisionColumn, key, r.clientID}, r.decision)
	if err != nil {
		return storage.PolledBackchannelAuthentication{}, err
	}
	var decision backchannelDecision
	if err := decodeRecord(plain, &decision, &decision.Version, backchannelRecordVersion); err != nil {
		return storage.PolledBackchannelAuthentication{}, err
	}
	return storage.PolledBackchannelAuthentication{
		Status: storage.BackchannelAuthenticationStatus(r.status), ClientID: fapi.ClientID(r.clientID), //nolint:gosec // a status this store wrote
		Request: rawJSON(record.Request), Grant: rawJSON(decision.Grant), Reason: decision.Reason,
	}, nil
}

// openRecord opens and decodes the record column of the request keyed
// by key.
func (s *BackchannelAuthenticationStore) openRecord(key, clientID string, stored []byte) (backchannelRecord, error) {
	plain, err := s.d.open(blobRef{backchannelTable, recordColumn, key, clientID}, stored)
	if err != nil {
		return backchannelRecord{}, err
	}
	var record backchannelRecord
	if err := decodeRecord(plain, &record, &record.Version, backchannelRecordVersion); err != nil {
		return backchannelRecord{}, err
	}
	return record, nil
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation.
func (s *BackchannelAuthenticationStore) Capabilities() storage.Capabilities {
	return s.d.sealedCapabilities()
}
