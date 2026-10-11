package strictjson

import (
	"encoding/json"
	"reflect"
	"testing"
)

// fuzzHeader is a JOSE-header-shaped target for
// FuzzUnmarshalMatchesCaseSensitiveReading, with a nested object.
type fuzzHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Crit []string `json:"crit,omitempty"`
	Cnf  *struct {
		Jkt string `json:"jkt"`
	} `json:"cnf,omitempty"`
}

// FuzzUnmarshalMatchesCaseSensitiveReading: whenever Unmarshal accepts
// a document, each tagged member's value is exactly what a
// case-sensitive reader taking that member by its exact name (the last
// occurrence, as both readers do) would see. A disagreement is the
// parser differential strictjson exists to close.
func FuzzUnmarshalMatchesCaseSensitiveReading(f *testing.F) {
	for _, s := range []string{
		`{"alg":"ES256","kid":"a"}`, `{"ALG":"none","alg":"ES256"}`, `{"Kid":"x","alg":"ES256"}`,
		`{"alg":"ES256","ſig":1}`, `{"cnf":{"JKT":"x"}}`, `{"cnf":{"jkt":"a","jkt":"b"}}`, `{"alg":"a","alg":"b"}`,
		`{"alg":"ES256"}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, doc string) {
		var h fuzzHeader
		if Unmarshal([]byte(doc), &h) != nil {
			return
		}
		want, ok := readHeaderCaseSensitively(doc)
		if !ok {
			return
		}
		if !reflect.DeepEqual(h, want) {
			t.Fatalf("Unmarshal(%q) = %+v, case-sensitive reading = %+v", doc, h, want)
		}
	})
}

// readHeaderCaseSensitively reads doc into a fuzzHeader by exact member
// names, one member at a time, as a case-sensitive reader would.
func readHeaderCaseSensitively(doc string) (fuzzHeader, bool) {
	var members map[string]json.RawMessage
	if json.Unmarshal([]byte(doc), &members) != nil {
		return fuzzHeader{}, false
	}
	var want fuzzHeader
	readExact(members, "alg", &want.Alg)
	readExact(members, "kid", &want.Kid)
	readExact(members, "typ", &want.Typ)
	readExact(members, "crit", &want.Crit)
	if raw, ok := members["cnf"]; ok {
		var cnf map[string]json.RawMessage
		if json.Unmarshal(raw, &cnf) == nil && cnf != nil {
			want.Cnf = &struct {
				Jkt string `json:"jkt"`
			}{}
			readExact(cnf, "jkt", &want.Cnf.Jkt)
		}
	}
	return want, true
}

// readExact decodes members[name], if present, into into.
func readExact(members map[string]json.RawMessage, name string, into any) {
	if raw, ok := members[name]; ok {
		_ = json.Unmarshal(raw, into)
	}
}
