package extension

import "errors"

var (
	// ErrUnregisteredParameter indicates an authorization parameter had
	// no matching registered Definition — the default-reject behavior
	// this package requires (see doc.go).
	ErrUnregisteredParameter = errors.New("extension: unregistered parameter")

	// ErrSourceNotAllowed indicates a parameter arrived somewhere its
	// Definition's AllowedSources does not permit (e.g. a
	// SourceRequestObject-only value submitted as a plain parameter).
	ErrSourceNotAllowed = errors.New("extension: parameter is not permitted from this source")

	// ErrValueTooLarge indicates an encoded value exceeded its
	// Definition's MaxBytes.
	ErrValueTooLarge = errors.New("extension: value exceeds the configured size limit")

	// ErrDuplicateDefinition indicates two Definitions (or RARDefinitions)
	// were registered under the same wire name (or RAR type).
	ErrDuplicateDefinition = errors.New("extension: duplicate definition")

	// ErrCardinalityMismatch indicates a Definition's declared
	// Cardinality does not match its Go type T (e.g. Cardinality: Single
	// with a slice T, or vice versa).
	ErrCardinalityMismatch = errors.New("extension: cardinality does not match the definition's type")

	// ErrDuplicateMember indicates a RAR detail object had the same
	// top-level JSON member name more than once.
	ErrDuplicateMember = errors.New("extension: duplicate JSON member")

	// ErrRARTooLarge indicates an authorization_details array exceeded
	// its RARRegistry's MaxTotalBytes.
	ErrRARTooLarge = errors.New("extension: authorization_details exceeds the configured total size limit")

	// ErrRARTooDeep indicates an authorization_details array (or one of
	// its objects) exceeded its RARRegistry's MaxDepth.
	ErrRARTooDeep = errors.New("extension: authorization_details exceeds the configured nesting depth limit")

	// ErrRARUnregisteredType indicates a detail object's "type" member
	// had no matching registered RARDefinition.
	ErrRARUnregisteredType = errors.New("extension: unregistered authorization_details type")

	// ErrRARTooManyObjects indicates more detail objects of one type
	// appeared than that type's RARDefinition.MaxObjects permits.
	ErrRARTooManyObjects = errors.New("extension: too many authorization_details objects of this type")

	// ErrRARObjectTooLarge indicates one detail object exceeded its
	// RARDefinition.MaxBytesPerObject.
	ErrRARObjectTooLarge = errors.New("extension: authorization_details object exceeds the configured size limit")
)
