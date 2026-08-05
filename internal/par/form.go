package par

import (
	"fmt"
	"net/url"
)

// maxFormBytes bounds how large a form-encoded body this package will
// attempt to parse, so an inbound PAR submission can't force unbounded
// parsing work before any other check runs.
const maxFormBytes = 64 * 1024

// EncodeForm builds a deterministic application/x-www-form-urlencoded
// body from params. Key order in the output is sorted, not
// caller-controlled, since url.Values.Encode does the sorting.
func EncodeForm(params map[string]string) []byte {
	values := make(url.Values, len(params))
	for k, v := range params {
		values.Set(k, v)
	}
	return []byte(values.Encode())
}

// DecodeForm parses an application/x-www-form-urlencoded body into a
// single-valued parameter map. It rejects a body larger than this
// package is willing to parse, and rejects any parameter name that
// appears more than once — resolving a duplicate by picking the first
// or last occurrence would let it be used as a request-smuggling
// primitive, so this package refuses to guess.
func DecodeForm(body []byte) (map[string]string, error) {
	if len(body) > maxFormBytes {
		return nil, ErrFormTooLarge
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedForm, err)
	}
	params := make(map[string]string, len(values))
	for k, v := range values {
		if len(v) != 1 {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateParameter, k)
		}
		params[k] = v[0]
	}
	return params, nil
}
