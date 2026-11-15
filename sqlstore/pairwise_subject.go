package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/idfoundry/fapigo/storage"
)

// errPairwiseSubjectNotFound is Lookup's answer for a body it holds no
// subject for.
var errPairwiseSubjectNotFound = fmt.Errorf("sqlstore: look up pairwise subject: %w: %w", ErrNotFound, storage.ErrPairwiseSubjectNotFound)

// opGetOrCreatePairwiseSubject names GetOrCreate in its errors.
const opGetOrCreatePairwiseSubject = "get or create pairwise subject"

// PairwiseSubjectStore is a storage.PairwiseSubjectStore: the store of
// pairwise.NewMapping, whose MappingDeriver is
// server.Dependencies.PairwiseSubjects. Its table's primary key is
// (issuer, sector, subject), and (issuer, sector, body) is unique, so
// the database itself keeps one body per user and sector, and each body
// to one user. Rows are never deleted, Sweep included.
type PairwiseSubjectStore struct{ d *DB }

// PairwiseSubjects returns d's storage.PairwiseSubjectStore.
func (d *DB) PairwiseSubjects() *PairwiseSubjectStore { return &PairwiseSubjectStore{d} }

// GetOrCreate implements storage.PairwiseSubjectStore. A returning
// user's key already has a body, which one SELECT reads. Otherwise one
// INSERT … ON CONFLICT DO NOTHING stores candidate unless the key has
// a body by then or the body is already another subject's in the same
// issuer and sector — of concurrent calls for one key, on any
// instance, exactly one inserts — then the key's body is read back. No
// body means the insert conflicted on the body alone: a collision, with
// nothing stored. A row, once stored, is never deleted, and only
// ForgetSubject changes it, so a body the first SELECT finds is the one
// the INSERT would have kept.
func (s *PairwiseSubjectStore) GetOrCreate(ctx context.Context, key storage.PairwiseSubjectKey, candidate string) (string, error) {
	for _, v := range []string{key.Issuer, key.Sector, key.Subject, candidate} {
		if !validTextKey(v) {
			return "", errors.New("sqlstore: get or create pairwise subject: issuer, sector, subject or candidate isn't valid UTF-8 without NUL")
		}
	}
	switch body, err := s.body(ctx, key); {
	case err == nil:
		return body, nil
	case !errors.Is(err, sql.ErrNoRows):
		return "", unavailable(opGetOrCreatePairwiseSubject, err)
	}
	var n int64
	err := s.d.writeOne(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, s.d.q("INSERT INTO {pairwise_subjects} (issuer, sector, subject, body) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING"),
			key.Issuer, key.Sector, key.Subject, candidate)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return "", unavailable(opGetOrCreatePairwiseSubject, err)
	}
	if n == 1 {
		return candidate, nil
	}
	body, err := s.body(ctx, key)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("sqlstore: get or create pairwise subject: %w", storage.ErrPairwiseSubjectCollision)
	case err != nil:
		return "", unavailable(opGetOrCreatePairwiseSubject, err)
	}
	return body, nil
}

// body reads key's body: sql.ErrNoRows if it has none.
func (s *PairwiseSubjectStore) body(ctx context.Context, key storage.PairwiseSubjectKey) (string, error) {
	var body string
	err := s.d.queryRow(ctx, "SELECT body FROM {pairwise_subjects} WHERE issuer = ? AND sector = ? AND subject = ?",
		key.Issuer, key.Sector, key.Subject).Scan(&body)
	return body, err
}

// Lookup implements storage.PairwiseSubjectStore. Every argument is
// compared exactly.
func (s *PairwiseSubjectStore) Lookup(ctx context.Context, issuer, sector, body string) (string, error) {
	if !validTextKey(issuer) || !validTextKey(sector) || !validTextKey(body) {
		return "", errPairwiseSubjectNotFound
	}
	var subject string
	err := s.d.queryRow(ctx, "SELECT subject FROM {pairwise_subjects} WHERE issuer = ? AND sector = ? AND body = ?",
		issuer, sector, body).Scan(&subject)
	switch {
	case errors.Is(err, sql.ErrNoRows), err == nil && strings.HasPrefix(subject, forgottenSubjectPrefix):
		return "", errPairwiseSubjectNotFound
	case err != nil:
		return "", unavailable("look up pairwise subject", err)
	}
	return subject, nil
}

// forgottenSubjectPrefix starts the subject column of a forgotten
// mapping (ForgetSubject): the forgotten body follows it, keeping the
// primary key unique per row. A control character, so no subject
// identifier the server issues (printable ASCII, server.SubjectID) can
// be one, and one valid in a Postgres TEXT, unlike NUL.
const forgottenSubjectPrefix = "\x01forgotten\x01"

// ForgetSubject implements storage.PairwiseSubjectEraser: one UPDATE
// moves each of subject's rows under issuer to a forgotten subject of
// its own (forgottenSubjectPrefix and the body). The row, and with it
// the UNIQUE (issuer, sector, body) constraint, stays, so the body is
// never stored again for anyone, while the subject, its primary key
// freed, gets a new body at its next GetOrCreate. Lookup finds no one
// for a forgotten body.
func (s *PairwiseSubjectStore) ForgetSubject(ctx context.Context, issuer, subject string) (int, error) {
	if !validTextKey(issuer) || !validTextKey(subject) || strings.HasPrefix(subject, forgottenSubjectPrefix) {
		return 0, nil
	}
	var n int64
	err := s.d.writeOne(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, s.d.q("UPDATE {pairwise_subjects} SET subject = ? || body WHERE issuer = ? AND subject = ?"),
			forgottenSubjectPrefix, issuer, subject)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return 0, unavailable("forget pairwise subject", err)
	}
	return int(n), nil
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation. Never EncryptedAtRest: the stores look rows up by
// every column, so none is sealed.
func (s *PairwiseSubjectStore) Capabilities() storage.Capabilities { return s.d.capabilities() }
