package jose

import (
	"errors"
	"testing"
)

func TestTypeIs(t *testing.T) {
	for _, tc := range []struct {
		typ, want string
		is        bool
	}{
		{"at+jwt", "at+jwt", true},
		{"application/at+jwt", "at+jwt", true},
		{"AT+JWT", "at+jwt", true},
		{"Application/At+Jwt", "at+jwt", true},
		{"at+jwt", "application/at+jwt", true},
		{"", "at+jwt", false},
		{"JWT", "at+jwt", false},
		{"text/at+jwt", "at+jwt", false},
		{"at+jwt ", "at+jwt", false},
		{"dpop+jwt", "at+jwt", false},
	} {
		if got := TypeIs(tc.typ, tc.want); got != tc.is {
			t.Errorf("TypeIs(%q, %q) = %v, want %v", tc.typ, tc.want, got, tc.is)
		}
	}
}

func TestRefuseOtherExplicitType(t *testing.T) {
	for _, tc := range []struct {
		typ     string
		own     []string
		refused bool
	}{
		{"", nil, false},
		{"JWT", nil, false},
		{"jwt", nil, false},
		{"application/jwt", nil, false},
		{"something-new+jwt", nil, false},
		{"at+jwt", nil, true},
		{"application/AT+JWT", nil, true},
		{"dpop+jwt", nil, true},
		{"oauth-authz-req+jwt", nil, true},
		{"entity-statement+jwt", nil, true},
		{"logout+jwt", nil, true},
		{"client-authentication+jwt", nil, true},
		{"client-authentication+jwt", []string{"client-authentication+jwt"}, false},
		{"application/Client-Authentication+JWT", []string{"client-authentication+jwt"}, false},
		{"at+jwt", []string{"client-authentication+jwt"}, true},
	} {
		err := RefuseOtherExplicitType(tc.typ, tc.own...)
		if errors.Is(err, ErrOtherExplicitType) != tc.refused {
			t.Errorf("RefuseOtherExplicitType(%q, %v) = %v, want refused = %v", tc.typ, tc.own, err, tc.refused)
		}
	}
}
