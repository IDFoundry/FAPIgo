package sqlstore

import "testing"

// checkStrictJSON refuses duplicate and case-variant members at each
// depth it knows the type of, and text that doesn't decode losslessly,
// and leaves everything else — unknown members, malformed JSON — to the
// decode.
func TestCheckStrictJSON(t *testing.T) {
	type inner struct {
		Name string `json:"name"`
	}
	type doc struct {
		A     string   `json:"a"`
		List  []inner  `json:"list"`
		In    *inner   `json:"in"`
		Plain []string `json:"plain"`
		Any   any      `json:"any"`
	}
	for raw, want := range map[string]bool{
		`{"a":"x","list":[{"name":"n"},{"name":"m"}],"in":{"name":"n"},"plain":["a","a"]}`: true,
		`{"a":"é😀","plain":["\\ud800"]}`:                                                   true,
		`{"unknown":1,"Unknown":2}`:                                                        true, // left to DisallowUnknownFields
		`{"any":{"x":1,"X":2}}`:                                                            true, // not a struct: any name goes
		`{"a":`:                                                                            true, // not JSON: left to the decode
		`[{"a":1},{"a":2}]`:                                                                true,
		`{"a":"x","a":"y"}`:                                                                false,
		`{"A":"x"}`:                                                                        false,
		`{"list":[{"name":"n"},{"NAME":"m"}]}`:                                             false,
		`{"list":[{"name":"n","name":"m"}]}`:                                               false,
		`{"in":{"Name":"n"}}`:                                                              false,
		`{"any":{"x":1,"x":2}}`:                                                            false,
		`{"a":"\ud800"}`:                                                                   false,
		`{"a":"\udc00"}`:                                                                   false,
		`{"a":"\ud83dx"}`:                                                                  false,
		`{"a":"\u00"}`:                                                                     false,
		"{\"a\":\"\xff\"}":                                                                 false,
	} {
		if got := checkStrictJSON([]byte(raw), doc{}) == nil; got != want {
			t.Errorf("checkStrictJSON(%s) accepted = %v, want %v", raw, got, want)
		}
	}
}
