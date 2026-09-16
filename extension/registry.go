package extension

import (
	"encoding/json"
	"fmt"
)

// Registry is an immutable set of registered Definitions, built once via
// NewRegistry (typically at server startup) and reused to validate every
// incoming request against the same rules.
type Registry struct {
	byName map[string]Registered
}

// NewRegistry validates and indexes defs. It fails if two Definitions
// share a wire name, or if any Definition's declared Cardinality does
// not match its Go type.
func NewRegistry(defs ...Registered) (*Registry, error) {
	byName := make(map[string]Registered, len(defs))
	for _, d := range defs {
		if d.name() == "" {
			return nil, fmt.Errorf("extension: definition has an empty name")
		}
		if !d.cardinalityOK() {
			return nil, fmt.Errorf("%w: %q", ErrCardinalityMismatch, d.name())
		}
		if _, exists := byName[d.name()]; exists {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateDefinition, d.name())
		}
		byName[d.name()] = d
	}
	return &Registry{byName: byName}, nil
}

// Parse validates params against the registry: every name not present
// in core (the caller's own set of standard protocol parameter names,
// already handled elsewhere) must have a registered Definition to be
// parsed and validated. A name with neither is an unrecognized
// authorization request parameter — RFC 6749 §3.1 and RFC 9126 §2.1
// require an authorization server to accept an otherwise-valid request
// in spite of one (OIDC Core §3.1.2.2 asks the same of an OIDC request),
// so Parse does not fail the request over it. It also does not merely
// tolerate it: Parse deletes the name from params in place before
// returning, so an unrecognized parameter's value never reaches
// storage, an audit sink, or a token claim — "ignored" and "silently
// preserved" are different things, and this package only does the
// former (see doc.go). params is therefore mutated as a side effect;
// callers that need the original request as submitted must copy it
// first. source identifies where params came from (a plain parameter or
// a signed request object), checked against each matching Definition's
// AllowedSources.
//
// This is authorization-request-parameter scoped, not a general
// extensibility stance: an authorization_details array (RFC 9396) is a
// structurally distinct, closed schema validated by RARRegistry.Parse
// instead, which does reject an unknown "type" or unknown JSON member —
// RFC 9396 defines it as a bounded array of typed detail objects, not an
// open parameter list, so RFC 6749 §3.1's rule doesn't apply to it.
func (r *Registry) Parse(params map[string]json.RawMessage, core map[string]struct{}, source Source) (Values, error) {
	var values Values
	for name, raw := range params {
		if _, isCore := core[name]; isCore {
			continue
		}
		def, ok := r.byName[name]
		if !ok {
			delete(params, name)
			continue
		}
		if err := def.validate(raw, source, &values); err != nil {
			return Values{}, err
		}
	}
	return values, nil
}

// Definitions returns every Definition r was built with, for use with
// AsParameters.
func (r *Registry) Definitions() []Registered {
	out := make([]Registered, 0, len(r.byName))
	for _, d := range r.byName {
		out = append(out, d)
	}
	return out
}
