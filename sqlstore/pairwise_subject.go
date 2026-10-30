package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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

// GetOrCreate implements storage.PairwiseSubjectStore: one INSERT … ON
// CONFLICT DO NOTHING stores candidate unless the key already has a
// body or the body is already another subject's in the same issuer and
// sector — of concurrent calls for one key, on any instance, exactly
// one inserts — then the key's body is read back. No body means the
// insert conflicted on the body alone: a collision, with nothing
// stored.
func (s *PairwiseSubjectStore) GetOrCreate(ctx context.Context, key storage.PairwiseSubjectKey, candidate string) (string, error) {
	for _, v := range []string{key.Issuer, key.Sector, key.Subject, candidate} {
		if !validTextKey(v) {
			return "", errors.New("sqlstore: get or create pairwise subject: issuer, sector, subject or candidate isn't valid UTF-8 without NUL")
		}
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
	var body string
	err = s.d.queryRow(ctx, "SELECT body FROM {pairwise_subjects} WHERE issuer = ? AND sector = ? AND subject = ?",
		key.Issuer, key.Sector, key.Subject).Scan(&body)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", fmt.Errorf("sqlstore: get or create pairwise subject: %w", storage.ErrPairwiseSubjectCollision)
	case err != nil:
		return "", unavailable(opGetOrCreatePairwiseSubject, err)
	}
	return body, nil
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
	case errors.Is(err, sql.ErrNoRows):
		return "", errPairwiseSubjectNotFound
	case err != nil:
		return "", unavailable("look up pairwise subject", err)
	}
	return subject, nil
}

// Capabilities implements storage.StoreAssurance — see the package
// documentation. Never EncryptedAtRest: the stores look rows up by
// every column, so none is sealed.
func (s *PairwiseSubjectStore) Capabilities() storage.Capabilities { return s.d.capabilities() }
