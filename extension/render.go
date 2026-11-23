package extension

import (
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// redactedValue is what every rendering of Values prints in place of a
// value.
const redactedValue = "[REDACTED]"

// names is values' parameter names, sorted.
func (values Values) names() []string {
	return slices.Sorted(maps.Keys(values.rawValues()))
}

// shadow is what fmt prints for values: each parameter name with the
// placeholder for its value.
func (values Values) shadow() map[string]string {
	raw := values.rawValues()
	out := make(map[string]string, len(raw))
	for name := range raw {
		out[name] = redactedValue
	}
	return out
}

// Format implements fmt.Formatter: values print as a map of their
// parameter names, each with [REDACTED] in place of its value, under
// every verb and flag (map[x_purpose:[REDACTED]] under %v), and %#v
// prints extension.Values{"x_purpose":[REDACTED]}. No value prints,
// whatever its Definition's Sensitivity.
func (values Values) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, values.GoString())
		return
	}
	_, _ = fmt.Fprintf(f, fmt.FormatString(f, verb), values.shadow())
}

// String is values' %v rendering: its parameter names, and no value.
func (values Values) String() string {
	return fmt.Sprint(values.shadow())
}

// GoString is values' %#v rendering: its parameter names, quoted, and no
// value.
func (values Values) GoString() string {
	var b strings.Builder
	b.WriteString("extension.Values{")
	for i, name := range values.names() {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Quote(name) + ":" + redactedValue)
	}
	b.WriteString("}")
	return b.String()
}

// LogValue implements slog.LogValuer: a group of values' parameter
// names, each logged as [REDACTED]. log/slog takes it before
// MarshalJSON, which carries every value.
func (values Values) LogValue() slog.Value {
	names := values.names()
	attrs := make([]slog.Attr, len(names))
	for i, name := range names {
		attrs[i] = slog.String(name, redactedValue)
	}
	return slog.GroupValue(attrs...)
}
