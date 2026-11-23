package redact

import (
	"bytes"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const handleTestValue = "H4NDLE-RAW-VALUE-2c9e"

// TestHandleComparesByValue pins what the handle types rely on: two
// Handles of one value are ==, as map keys too, and the zero Handle is
// MakeHandle("").
func TestHandleComparesByValue(t *testing.T) {
	a, b := MakeHandle(handleTestValue), MakeHandle(strings.Clone(handleTestValue))
	if a != b || map[Handle]int{a: 1}[b] != 1 {
		t.Error("two Handles of one value compare unequal")
	}
	if a == MakeHandle(handleTestValue+"x") {
		t.Error("Handles of different values compare equal")
	}
	if MakeHandle("") != (Handle{}) || !MakeHandle("").IsZero() || a.IsZero() {
		t.Error(`MakeHandle("") isn't the zero Handle, or IsZero is wrong`)
	}
	if (Handle{}).Reveal() != "" || b.Reveal() != handleTestValue {
		t.Errorf("Reveal() = %q and %q, want \"\" and %q", (Handle{}).Reveal(), b.Reveal(), handleTestValue)
	}
	if !reflect.TypeFor[Handle]().Comparable() {
		t.Error("Handle isn't comparable")
	}
	if Mask(Handle{}) != "" || Mask(a) != Redacted {
		t.Error("Mask doesn't give an absent Handle no placeholder and a present one Redacted")
	}
}

// TestHandlePrintsNoValue pins that a Handle prints only an address
// where fmt reaches it by reflection, and logs as Redacted.
func TestHandlePrintsNoValue(t *testing.T) {
	type holder struct{ h Handle }
	got := fmt.Sprintf("%+v", holder{MakeHandle(handleTestValue)})
	if !regexp.MustCompile(`^\{h:\{h:\{\w+:0x[0-9a-f]+\}\}\}$`).MatchString(got) {
		t.Errorf("Sprintf(%%+v) of a Handle in an unexported field = %q, want only an address", got)
	}
	var text bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("m", "h", MakeHandle(handleTestValue))
	if !strings.Contains(text.String(), "h=[REDACTED]") || strings.Contains(text.String(), handleTestValue) {
		t.Errorf("slog text = %q, want h=[REDACTED]", text.String())
	}
}
