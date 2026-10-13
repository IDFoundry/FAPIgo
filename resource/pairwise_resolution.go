package resource

// PairwiseResolution is what a Verifier does with an access token whose
// sub is pairwise (OpenID Connect Core §8): Config.PairwiseResolution.
//
// Only the OpenID Provider may map a pairwise sub back to its end user
// (Core §8.1), so only the OP's own resource servers resolve it: through
// Dependencies.PairwiseSubjects or Dependencies.PairwiseSubjectResolver,
// which hold the keys, store or mapping that reverse every pairwise sub.
// A resource server outside the OP's trust boundary must never be given
// those; it uses PairwiseClientSubjectsOnly and knows each end user only
// as the client does.
type PairwiseResolution uint8

const (
	// The zero value resolves a pairwise sub to the end user's internal
	// subject (AuthorizationContext.InternalSubject) through
	// Dependencies.PairwiseSubjects or Dependencies.PairwiseSubjectResolver,
	// and refuses the request with server_error when neither is set,
	// rather than give a pairwise sub as an internal subject.
	_ PairwiseResolution = iota

	// PairwiseClientSubjectsOnly accepts a pairwise sub without mapping
	// it back: AuthorizationContext.InternalSubject is "" and
	// ClientSubject is the sub the client was given. Authorize by
	// ClientSubject together with ClientID: a pairwise sub only names an
	// end user within its client's sector. It is the choice for a
	// resource server outside the OpenID Provider (a third party's API
	// accepting the OP's access tokens), which needs no keys, store or
	// resolver at all. It applies to opaque access tokens too: their
	// record's internal subject isn't reported, so the verifier behaves
	// the same whichever format the OP issues. A token with a public sub
	// reports it as both InternalSubject and ClientSubject, as always.
	// It can't be combined with Dependencies.PairwiseSubjects,
	// Dependencies.PairwiseSubjectResolver or Config.PairwisePrefix.
	PairwiseClientSubjectsOnly
)

// IsValid reports whether r is the zero value or
// PairwiseClientSubjectsOnly.
func (r PairwiseResolution) IsValid() bool {
	return r == 0 || r == PairwiseClientSubjectsOnly
}
