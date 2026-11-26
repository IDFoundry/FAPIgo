package strictjson

import "testing"

// TestCompareCopiesReportsAnUncompactableSpan: sameAsFirst and
// compactValue report a span that isn't a JSON value. The walker only
// hands them spans its decoder has already read as values, so this is
// the defence behind that, exercised directly.
func TestCompareCopiesReportsAnUncompactableSpan(t *testing.T) {
	if _, err := compactValue([]byte(`:{"a"`)); err == nil {
		t.Error(`compactValue(:{"a") = nil error, want one`)
	}
	w := &conflictWalker{data: []byte(`{"a" 1}`)}
	if err := w.sameAsFirst(&firstCopy{name: "a", start: 0, end: 4}, 5, 6); err == nil {
		t.Error("sameAsFirst with an uncompactable first copy = nil error, want one")
	}
	w = &conflictWalker{data: []byte(`1 {"a"`)}
	if err := w.sameAsFirst(&firstCopy{name: "a", start: 0, end: 1}, 2, 6); err == nil {
		t.Error("sameAsFirst with an uncompactable second copy = nil error, want one")
	}
}
