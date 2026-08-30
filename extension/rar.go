package extension

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// RARDefinition captures the wire contract for one Rich Authorization
// Requests (RFC 9396) detail type: the "type" discriminator value, the
// Go type its type-specific fields decode into, and per-object bounds.
// Registered alongside plain Definitions in the same package, but kept
// in its own RARRegistry — an authorization_details array is validated
// as a whole (total size, nesting depth), not parameter-by-parameter.
type RARDefinition[T any] struct {
	// Type is the detail object's "type" member (RFC 9396 §2).
	Type string

	// MaxObjects bounds how many objects of this type may appear in one
	// authorization_details array.
	MaxObjects int

	// MaxBytesPerObject bounds the size of one detail object's raw JSON.
	MaxBytesPerObject int

	// Validate, if non-nil, applies extra semantic checks beyond T's JSON
	// shape.
	Validate func(T) error

	// ValidateGrant, if non-nil, decides whether a granted detail object
	// (typically a resource owner's narrowed subset of what a client
	// requested — see RARRegistry.ValidateGrant) is an acceptable
	// narrowing of the requested object it's matched against, e.g.
	// approving a lower payment amount or a subset of an "actions" list.
	// If nil, a granted object of this type must be byte-for-byte
	// identical (once canonically re-encoded) to the requested object it
	// matches — no narrowing beyond dropping whole objects is permitted.
	ValidateGrant func(requested, granted T) error
}

// RARDetail is one validated authorization_details object: its type and
// decoded type-specific fields.
type RARDetail[T any] struct {
	Type   string
	Fields T
}

// registeredRAR is RARDefinition's type-erased handle, the RAR
// equivalent of Registered.
type registeredRAR interface {
	rarType() string
	maxObjects() int
	maxBytesPerObject() int
	decodeCheck(raw json.RawMessage) error
	validateGrant(requestedRaw, grantedRaw json.RawMessage) error
}

func (d RARDefinition[T]) rarType() string        { return d.Type }
func (d RARDefinition[T]) maxObjects() int        { return d.MaxObjects }
func (d RARDefinition[T]) maxBytesPerObject() int { return d.MaxBytesPerObject }

func (d RARDefinition[T]) decodeCheck(raw json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var v T
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("extension: authorization_details type %q: malformed value: %w", d.Type, err)
	}
	if d.Validate != nil {
		if err := d.Validate(v); err != nil {
			return fmt.Errorf("extension: authorization_details type %q: %w", d.Type, err)
		}
	}
	return nil
}

// validateGrant decides whether grantedRaw is an acceptable narrowing of
// requestedRaw — see RARDefinition.ValidateGrant's own doc comment for the
// default (exact-match) behavior when it is nil.
func (d RARDefinition[T]) validateGrant(requestedRaw, grantedRaw json.RawMessage) error {
	var requested, granted T
	if err := json.Unmarshal(requestedRaw, &requested); err != nil {
		return fmt.Errorf("extension: authorization_details type %q: malformed requested value: %w", d.Type, err)
	}
	if err := json.Unmarshal(grantedRaw, &granted); err != nil {
		return fmt.Errorf("extension: authorization_details type %q: malformed granted value: %w", d.Type, err)
	}
	if d.ValidateGrant != nil {
		if err := d.ValidateGrant(requested, granted); err != nil {
			return fmt.Errorf("extension: authorization_details type %q: %w", d.Type, err)
		}
		return nil
	}

	canonicalRequested, err := json.Marshal(requested)
	if err != nil {
		return fmt.Errorf("extension: authorization_details type %q: %w", d.Type, err)
	}
	canonicalGranted, err := json.Marshal(granted)
	if err != nil {
		return fmt.Errorf("extension: authorization_details type %q: %w", d.Type, err)
	}
	if !bytes.Equal(canonicalRequested, canonicalGranted) {
		return fmt.Errorf("%w: type %q", ErrRARGrantExceedsRequest, d.Type)
	}
	return nil
}

// RARValues holds validated authorization_details objects, grouped by
// type. Like Values, it has no public accessor of its own — RARGet is
// the only way to read validated objects back out, typed.
type RARValues struct {
	byType map[string][]json.RawMessage
}

// RARGet decodes every validated object of def's type.
func RARGet[T any](values RARValues, def RARDefinition[T]) ([]RARDetail[T], error) {
	raws := values.byType[def.Type]
	out := make([]RARDetail[T], 0, len(raws))
	for _, raw := range raws {
		var v T
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("extension: authorization_details type %q: %w", def.Type, err)
		}
		out = append(out, RARDetail[T]{Type: def.Type, Fields: v})
	}
	return out, nil
}

// RARSet encodes v as one authorization_details detail object, ready to
// append to an outgoing array (e.g.
// client.BeginAuthorizationRequest.AuthorizationDetails) — RARGet's
// write-side counterpart. def.Type is always stamped into the result's
// "type" member, overriding whatever T's own JSON encoding produced for
// it (or adding it, if T has no such field at all) — the one thing a
// bare json.Marshal(v) can't do on its own, so a caller's struct never
// has to declare and keep in sync its own redundant Type string field.
//
// Unlike Set, there is no MaxBytes/Validate check here: those bound and
// validate data an authorization server doesn't trust from a client:
// RARSet runs on the sending side, encoding data the caller just
// constructed itself, so there is nothing to validate against.
func RARSet[T any](def RARDefinition[T], v T) (json.RawMessage, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("extension: authorization_details type %q: %w", def.Type, err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &obj); err != nil {
		return nil, fmt.Errorf("extension: authorization_details type %q: value must encode as a JSON object: %w", def.Type, err)
	}
	if obj == nil {
		// encoded was the literal "null" (e.g. T is a nil pointer type) —
		// valid JSON, so Unmarshal above didn't error, but not a JSON
		// object either.
		return nil, fmt.Errorf("extension: authorization_details type %q: value must encode as a JSON object", def.Type)
	}
	typeValue, _ := json.Marshal(def.Type) // marshaling a string cannot fail
	obj["type"] = typeValue
	// Every value in obj is already valid JSON — either captured verbatim
	// by the Unmarshal above (each json.RawMessage decode target only
	// ever holds one already-well-formed sub-value) or typeValue,
	// freshly marshaled just above — so re-marshaling the map cannot
	// fail.
	out, _ := json.Marshal(obj)
	return out, nil
}

// RARRegistry is an immutable set of registered RARDefinitions, plus the
// bounds that apply to the authorization_details array as a whole.
type RARRegistry struct {
	byType        map[string]registeredRAR
	maxTotalBytes int
	maxDepth      int
}

// NewRARRegistry validates and indexes defs. maxTotalBytes bounds the
// entire authorization_details array's raw size; maxDepth bounds its
// JSON nesting depth (an object or array literal one level deep counts
// as depth 1). Both are required — a zero value rejects every request
// rather than silently permitting unbounded nesting or size.
func NewRARRegistry(maxTotalBytes, maxDepth int, defs ...registeredRAR) (*RARRegistry, error) {
	if maxTotalBytes <= 0 {
		return nil, fmt.Errorf("extension: rar registry: max total bytes must be positive")
	}
	if maxDepth <= 0 {
		return nil, fmt.Errorf("extension: rar registry: max depth must be positive")
	}
	byType := make(map[string]registeredRAR, len(defs))
	for _, d := range defs {
		if d.rarType() == "" {
			return nil, fmt.Errorf("extension: rar definition has an empty type")
		}
		if d.maxObjects() <= 0 {
			return nil, fmt.Errorf("extension: rar definition %q: max objects must be positive", d.rarType())
		}
		if d.maxBytesPerObject() <= 0 {
			return nil, fmt.Errorf("extension: rar definition %q: max bytes per object must be positive", d.rarType())
		}
		if _, exists := byType[d.rarType()]; exists {
			return nil, fmt.Errorf("%w: type %q", ErrDuplicateDefinition, d.rarType())
		}
		byType[d.rarType()] = d
	}
	return &RARRegistry{byType: byType, maxTotalBytes: maxTotalBytes, maxDepth: maxDepth}, nil
}

// rarObjectHead reads only a detail object's "type" discriminator,
// leaving the rest for the matching RARDefinition to decode strictly.
type rarObjectHead struct {
	Type string `json:"type"`
}

// Parse validates raw — the authorization_details parameter's raw JSON
// array — against the registry: total size and nesting depth bounds,
// then per object: a registered type, no duplicate top-level JSON
// members, its own size and per-type object-count bounds, and strict
// decoding against its RARDefinition's type.
func (r *RARRegistry) Parse(raw json.RawMessage) (RARValues, error) {
	if len(raw) > r.maxTotalBytes {
		return RARValues{}, ErrRARTooLarge
	}
	if err := checkJSONDepth(raw, r.maxDepth); err != nil {
		return RARValues{}, err
	}

	var objects []json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&objects); err != nil {
		return RARValues{}, fmt.Errorf("extension: authorization_details must be a JSON array: %w", err)
	}

	values := RARValues{byType: make(map[string][]json.RawMessage)}
	counts := make(map[string]int, len(r.byType))
	for _, objRaw := range objects {
		if err := checkNoDuplicateTopLevelKeys(objRaw); err != nil {
			return RARValues{}, err
		}

		var head rarObjectHead
		if err := json.Unmarshal(objRaw, &head); err != nil || head.Type == "" {
			return RARValues{}, fmt.Errorf("extension: authorization_details object is missing type")
		}
		def, ok := r.byType[head.Type]
		if !ok {
			return RARValues{}, fmt.Errorf("%w: %q", ErrRARUnregisteredType, head.Type)
		}
		if len(objRaw) > def.maxBytesPerObject() {
			return RARValues{}, fmt.Errorf("%w: type %q", ErrRARObjectTooLarge, head.Type)
		}
		counts[head.Type]++
		if counts[head.Type] > def.maxObjects() {
			return RARValues{}, fmt.Errorf("%w: type %q", ErrRARTooManyObjects, head.Type)
		}
		if err := def.decodeCheck(objRaw); err != nil {
			return RARValues{}, err
		}
		values.byType[head.Type] = append(values.byType[head.Type], objRaw)
	}
	return values, nil
}

// ValidateGrant checks that granted is no more than requested was: every
// granted detail object must correspond to one of the requested objects of
// the same type not already matched to another granted object. Per type, a
// registered RARDefinition's own ValidateGrant hook decides whether a
// granted object may narrow the requested object it's matched against
// (e.g. a lower payment amount, or a subset of an "actions" list); when a
// type's ValidateGrant is nil, the two must be byte-for-byte identical once
// canonically re-encoded. Matching is greedy, in array order — RFC 9396
// does not mandate a matching algorithm, only that an authorization server
// "may grant less" than was requested; this is a deliberate, documented
// choice, not a spec requirement.
//
// granted must already have been produced by this same registry's own
// Parse (so every type it names is registered and every object already
// passed its own decodeCheck) — ValidateGrant only checks granted against
// requested, not granted's own well-formedness again.
func (r *RARRegistry) ValidateGrant(requested, granted RARValues) error {
	consumed := make(map[string][]bool, len(requested.byType))
	for typ, raws := range requested.byType {
		consumed[typ] = make([]bool, len(raws))
	}
	for typ, grantedRaws := range granted.byType {
		def, ok := r.byType[typ]
		if !ok {
			return fmt.Errorf("%w: %q", ErrRARUnregisteredType, typ)
		}
		requestedRaws := requested.byType[typ]
		usedIdx := consumed[typ]
		for _, grantedRaw := range grantedRaws {
			matched := false
			for i, requestedRaw := range requestedRaws {
				if usedIdx[i] {
					continue
				}
				if err := def.validateGrant(requestedRaw, grantedRaw); err == nil {
					usedIdx[i] = true
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("%w: type %q", ErrRARGrantExceedsRequest, typ)
			}
		}
	}
	return nil
}

// checkJSONDepth reports whether raw's JSON nesting ever exceeds
// maxDepth, without otherwise validating its shape.
func checkJSONDepth(raw []byte, maxDepth int) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("extension: %w", err)
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
				if depth > maxDepth {
					return ErrRARTooDeep
				}
			case '}', ']':
				depth--
			}
		}
	}
}

// checkNoDuplicateTopLevelKeys reports whether raw — expected to be a
// JSON object — repeats a top-level member name. It does not recurse
// into nested objects/arrays; encoding/json's own decode already applies
// DisallowUnknownFields for whatever shape a RARDefinition's T declares,
// so a duplicate nested member can only smuggle in a value the target
// struct doesn't expose to begin with.
func checkNoDuplicateTopLevelKeys(raw json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("extension: %w", err)
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("extension: authorization_details object must be a JSON object")
	}

	seen := make(map[string]struct{})
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("extension: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("extension: malformed object key")
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicateMember, key)
		}
		seen[key] = struct{}{}

		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return fmt.Errorf("extension: %w", err)
		}
	}
	return nil
}
