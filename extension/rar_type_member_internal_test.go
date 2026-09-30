package extension

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestDeclaresTypeMember(t *testing.T) {
	type tagged struct {
		Kind string `json:"type"`
	}
	type holder struct {
		Type string
	}
	type plain struct {
		A string
	}
	for name, tc := range map[string]struct {
		typ  reflect.Type
		want bool
	}{
		"tagged": {reflect.TypeFor[tagged](), true},
		"tagged with options": {reflect.TypeFor[struct {
			K string `json:"type,omitempty"`
		}](), true},
		"untagged Type":    {reflect.TypeFor[holder](), true},
		"pointer":          {reflect.TypeFor[*tagged](), true},
		"embedded":         {reflect.TypeFor[struct{ holder }](), true},
		"embedded pointer": {reflect.TypeFor[struct{ *tagged }](), true},
		"ignored": {reflect.TypeFor[struct {
			Type string `json:"-"`
		}](), false},
		"renamed": {reflect.TypeFor[struct {
			Type string `json:"kind"`
		}](), false},
		"unexported":            {reflect.TypeFor[struct{ typ string }](), false},
		"embedded without type": {reflect.TypeFor[struct{ plain }](), false},
		"no type field":         {reflect.TypeFor[struct{ Amount string }](), false},
		"not a struct":          {reflect.TypeFor[map[string]any](), false},
	} {
		if got := declaresTypeMember(tc.typ); got != tc.want {
			t.Errorf("declaresTypeMember(%s) = %v, want %v", name, got, tc.want)
		}
	}
}

func TestDecodeCheckRejectsNonObject(t *testing.T) {
	type untyped struct {
		Amount string `json:"amount"`
	}
	def := RARDefinition[untyped]{Type: "payment", MaxObjects: 1, MaxBytesPerObject: 64}
	if err := def.decodeCheck(json.RawMessage(`[1]`)); err == nil {
		t.Error("decodeCheck(array) = nil, want error")
	}
}
