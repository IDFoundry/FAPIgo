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
// already handled elsewhere) must have a registered Definition — a name
// with neither is rejected with ErrUnregisteredParameter, the
// default-reject behavior this package requires. source identifies
// where params came from (a plain parameter or a signed request
// object), checked against each matching Definition's AllowedSources.
func (r *Registry) Parse(params map[string]json.RawMessage, core map[string]struct{}, source Source) (Values, error) {
	var values Values
	for name, raw := range params {
		if _, isCore := core[name]; isCore {
			continue
		}
		def, ok := r.byName[name]
		if !ok {
			return Values{}, fmt.Errorf("%w: %q", ErrUnregisteredParameter, name)
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
