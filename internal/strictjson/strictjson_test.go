package strictjson

import (
	"encoding/json"
	"strings"
	"testing"
)

type inner struct {
	Kid string `json:"kid"`
}

type Embedded struct {
	Typ string `json:"typ"`
}

type target struct {
	Embedded
	Alg     string `json:"alg"`
	Untag   string
	Skipped string           `json:"-"`
	Raw     json.RawMessage  `json:"raw"`
	Custom  selfDecoding     `json:"custom"`
	Bytes   []byte           `json:"bytes"`
	Nested  inner            `json:"nested"`
	Ptr     *inner           `json:"ptr"`
	List    []inner          `json:"list"`
	ByName  map[string]inner `json:"by_name"`
	Opt     string           `json:"opt,omitempty"`
}

type selfDecoding struct{ v string }

func (s *selfDecoding) UnmarshalJSON(b []byte) error { s.v = string(b); return nil }

func TestUnmarshalAcceptsExactNames(t *testing.T) {
	data := `{"alg":"ES256","typ":"JWT","Untag":"x","raw":{"ALG":1},"custom":{"ALG":1},"bytes":"AQI=",
		"nested":{"kid":"a"},"ptr":{"kid":"b"},"list":[{"kid":"c"}],"by_name":{"k":{"kid":"d"}},"opt":"o","unknown":1,"-":"dash"}`
	var v target
	if err := Unmarshal([]byte(data), &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if v.Alg != "ES256" || v.Typ != "JWT" || v.Untag != "x" || v.Nested.Kid != "a" || v.Ptr.Kid != "b" ||
		v.List[0].Kid != "c" || v.ByName["k"].Kid != "d" || v.Opt != "o" {
		t.Fatalf("decoded %+v", v)
	}
}

func TestUnmarshalRejectsCaseVariants(t *testing.T) {
	for name, data := range map[string]string{
		"top-level tag":   `{"ALG":"none"}`,
		"duplicate fold":  `{"alg":"ES256","Alg":"none"}`,
		"untagged name":   `{"untag":"x"}`,
		"embedded":        `{"TYP":"JWT"}`,
		"tag option":      `{"OPT":"o"}`,
		"nested struct":   `{"nested":{"KID":"a"}}`,
		"pointer":         `{"ptr":{"Kid":"a"}}`,
		"slice element":   `{"list":[{"kid":"a"},{"KID":"b"}]}`,
		"map value":       `{"by_name":{"k":{"KID":"a"}}}`,
		"top-level slice": `[{"KID":"a"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			if strings.HasPrefix(data, "[") {
				var v []inner
				err = Unmarshal([]byte(data), &v)
			} else {
				var v target
				err = Unmarshal([]byte(data), &v)
			}
			if err == nil || !strings.Contains(err.Error(), "case-sensitive") {
				t.Fatalf("err = %v, want case-sensitivity rejection", err)
			}
		})
	}
}

func TestUnmarshalLeavesMalformedJSONToDecoder(t *testing.T) {
	var v target
	err := Unmarshal([]byte(`{"alg":`), &v)
	if err == nil || strings.Contains(err.Error(), "strictjson") {
		t.Fatalf("err = %v, want encoding/json's own error", err)
	}
	if err := CheckFieldCase([]byte(`{}`), nil); err != nil {
		t.Fatalf("nil target: %v", err)
	}
	if err := CheckFieldCase([]byte(`"str"`), &v); err != nil {
		t.Fatalf("non-object: %v", err)
	}
	if err := CheckFieldCase([]byte(`{"list":"str","by_name":1}`), &v); err != nil {
		t.Fatalf("mistyped containers: %v", err)
	}
}
