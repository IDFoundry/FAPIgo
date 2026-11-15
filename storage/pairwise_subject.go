package storage

import (
	"context"
	"errors"
)

// PairwiseSubjectKey names one end user's pairwise subject identifier:
// the user (Subject, the internal subject identifier the server
// authenticates) as seen by one sector (OpenID Connect Core §8.1) of
// one issuer. Every field is compared exactly.
type PairwiseSubjectKey struct {
	Issuer  string
	Sector  string
	Subject string
}

// PairwiseSubjectStore keeps a random pairwise subject identifier per
// PairwiseSubjectKey: the mapping-table alternative to deriving one
// with a key, so the identifier can be mapped back to the user without
// any key whose loss would let it be computed for everyone. The stored
// value is the identifier's body, without any prefix the server adds.
//
// GetOrCreate returns the body stored for key, first storing candidate
// as it if there is none. It must be atomic: concurrent calls for the
// same key, on any instance sharing the store, all return the same
// body — the first one stored. A body is unique within its issuer and
// sector: when key has no body yet and candidate is already another
// key's body in the same issuer and sector, GetOrCreate stores nothing
// and returns an error wrapping ErrPairwiseSubjectCollision, so the
// caller can retry with a fresh candidate. When key already has a body,
// candidate is ignored, collision or not.
//
// Lookup returns the internal subject whose body under issuer and
// sector is body, and an error wrapping ErrPairwiseSubjectNotFound when
// there is none — including for a body stored under another issuer or
// sector.
//
// A store that couldn't answer at all wraps ErrStoreUnavailable, which
// callers treat as a server error, never as "not found". Records are
// never deleted, except by a PairwiseSubjectEraser forgetting a user
// whose account has closed: a user's identifier for a sector must stay
// the same for as long as relying parties may hold it. Run
// TestPairwiseSubjectStoreContract against an implementation.
type PairwiseSubjectStore interface {
	GetOrCreate(ctx context.Context, key PairwiseSubjectKey, candidate string) (string, error)
	Lookup(ctx context.Context, issuer, sector, body string) (string, error)
}

// PairwiseSubjectEraser is a PairwiseSubjectStore that can forget an end
// user: for closing their account, when the identifiers relying
// parties hold for them must stop resolving to anyone. It's optional,
// and called by the application on the store itself, not by the server.
//
// ForgetSubject removes every mapping of subject under issuer, in every
// sector, and returns how many it removed (0 when there were none).
// After it, Lookup finds no subject for those bodies, and a later
// GetOrCreate for subject in a sector stores a new body, as for a user
// never seen. Each removed body stays retired, never stored again for
// anyone in its issuer and sector: GetOrCreate refuses it as a
// candidate with ErrPairwiseSubjectCollision, so an identifier a
// relying party held for the forgotten user can never come to name
// another. Mappings under other issuers are untouched. Run
// TestPairwiseSubjectEraserContract against an implementation.
type PairwiseSubjectEraser interface {
	PairwiseSubjectStore
	ForgetSubject(ctx context.Context, issuer, subject string) (int, error)
}

// ErrPairwiseSubjectNotFound is the error PairwiseSubjectStore.Lookup
// wraps when no subject has the body under the issuer and sector.
var ErrPairwiseSubjectNotFound = errors.New("storage: pairwise subject not found")

// ErrPairwiseSubjectCollision is the error PairwiseSubjectStore.GetOrCreate
// wraps when its candidate body already belongs to another subject in
// the same issuer and sector, and nothing was stored.
var ErrPairwiseSubjectCollision = errors.New("storage: pairwise subject body already in use")
