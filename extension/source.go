package extension

// Cardinality is a closed set describing whether a Definition's Go type
// represents one value or a list of values on the wire.
type Cardinality uint8

const (
	_ Cardinality = iota

	// Single means the Definition's T is one value.
	Single

	// Multiple means T is a slice — the wire value is a JSON array.
	Multiple
)

// Source is a bitmask of where a Definition's value may legitimately
// originate on an authorization request. A Definition must permit at
// least one.
type Source uint8

const (
	// SourcePlainParameter permits the value to appear as a plain,
	// unprotected top-level PAR/authorization parameter.
	SourcePlainParameter Source = 1 << iota

	// SourceRequestObject permits the value to appear inside a signed
	// request object — required for any Definition whose value must be
	// integrity-protected rather than accepted as a bare, unsigned
	// parameter.
	SourceRequestObject
)

// Allows reports whether s permits one.
func (s Source) Allows(one Source) bool { return s&one != 0 }
