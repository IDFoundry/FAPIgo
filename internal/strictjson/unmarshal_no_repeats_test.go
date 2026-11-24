package strictjson

import "testing"

// TestUnmarshalNoRepeats: UnmarshalNoRepeats refuses everything
// Unmarshal does (a case-variant field, data after the value) and a
// member repeated in one object at any depth, exactly or under FoldKey,
// while unknown members are left to encoding/json.
func TestUnmarshalNoRepeats(t *testing.T) {
	type target struct {
		A string         `json:"a"`
		M map[string]int `json:"m"`
	}
	for body, ok := range map[string]bool{
		`{"a":"x"}`:                   true,
		`{"a":"x","unknown":1}`:       true,
		`{"a":"x","m":{"k":1,"j":2}}`: true,
		`{"a":"x","a":"y"}`:           false,
		`{"A":"x"}`:                   false,
		`{"a":"x","U":1,"u":2}`:       false,
		`{"a":"x","m":{"k":1,"K":2}}`: false,
		`{"a":"x"} {}`:                false,
		`{"a":"x"`:                    false,
	} {
		var v target
		if err := UnmarshalNoRepeats([]byte(body), &v); (err == nil) != ok {
			t.Errorf("UnmarshalNoRepeats(%s) = %v, want ok %v", body, err, ok)
		}
	}
}
