package redact

import (
	"log/slog"
	"unique"
)

// Handle holds an identifier the library makes and hands out by value:
// a handle type's value, a request_uri, an auth_req_id. Like a
// fapi.Secret, it keeps the value out of every string field, so fmt's
// reflection fallback prints only an address; unlike one, it is
// comparable by value, so a type holding it keeps the == its callers
// rely on, such as Parse(h.String()) == h.
//
// It holds the canonical handle unique.Make returns for the value. Two
// Handles of one value share it, so == compares values and equal
// values print the same address. The handles are shared process-wide,
// and MakeHandle of a value some live Handle already holds takes a
// fraction of the time a new value does: hold only values too long and
// random to guess, as the library's identifiers and a client's
// notification tokens are.
type Handle struct {
	h unique.Handle[string]
}

// MakeHandle holds value. MakeHandle("") is the zero Handle.
func MakeHandle(value string) Handle {
	if value == "" {
		return Handle{}
	}
	return Handle{h: unique.Make(value)}
}

// Reveal returns the held value: "" for the zero Handle.
func (h Handle) Reveal() string {
	if h.IsZero() {
		// The zero unique.Handle points nowhere: Value would dereference nil.
		return ""
	}
	return h.h.Value()
}

// IsZero reports whether h is the zero Handle, which MakeHandle("")
// returns too.
func (h Handle) IsZero() bool {
	return h == Handle{}
}

// LogValue implements slog.LogValuer: h is logged as Redacted.
func (h Handle) LogValue() slog.Value {
	return slog.StringValue(Redacted)
}
