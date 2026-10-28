package querystring

import (
	"slices"
	"testing"
)

func TestAppend(t *testing.T) {
	for _, tc := range []struct{ raw, add, want string }{
		{"", "code=x", "code=x"},
		{"b=2&a=1", "code=x", "b=2&a=1&code=x"},
		{"flag", "code=x", "flag&code=x"},
		{"x=1;y=2", "code=x", "x=1;y=2&code=x"},
		{"bad=%zz&keep=1", "code=x", "bad=%zz&keep=1&code=x"},
		{"a=1&", "code=x", "a=1&code=x"},
		{"a=1", "", "a=1"},
	} {
		if got := Append(tc.raw, tc.add); got != tc.want {
			t.Errorf("Append(%q, %q) = %q, want %q", tc.raw, tc.add, got, tc.want)
		}
	}
}

func TestNames(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want []string
	}{
		{"", nil},
		{"b=2&a=1", []string{"b", "a"}},
		{"flag", []string{"flag"}},
		{"x=1;state=2", []string{"x", "state"}},
		{"st%61te=1", []string{"state"}},
		{"bad%zz=1&&code", []string{"bad%zz", "code"}},
	} {
		if got := Names(tc.raw); !slices.Equal(got, tc.want) {
			t.Errorf("Names(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestFirstReserved(t *testing.T) {
	if name, ok := FirstReserved("a=1&iss=x&state=y", "state", "iss"); !ok || name != "iss" {
		t.Fatalf("FirstReserved = %q, %v; want iss, true", name, ok)
	}
	if _, ok := FirstReserved("a=1&States=y", "state"); ok {
		t.Fatal("FirstReserved matched a name differing in case")
	}
}
