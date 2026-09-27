package authchallenge

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	cases := map[string]struct {
		values []string
		want   []Challenge
	}{
		"bearer with params": {
			[]string{`Bearer realm="example", error="invalid_token", error_description="The access token expired"`},
			[]Challenge{{Scheme: "bearer", Params: map[string]string{"realm": "example", "error": "invalid_token", "error_description": "The access token expired"}}},
		},
		"scheme only": {[]string{"DPoP"}, []Challenge{{Scheme: "dpop"}}},
		"two challenges one value": {
			[]string{`DPoP algs="ES256 PS256", error="use_dpop_nonce", Bearer realm="r"`},
			[]Challenge{
				{Scheme: "dpop", Params: map[string]string{"algs": "ES256 PS256", "error": "use_dpop_nonce"}},
				{Scheme: "bearer", Params: map[string]string{"realm": "r"}},
			},
		},
		"two field values": {
			[]string{`Bearer error=invalid_token`, `DPoP error="invalid_dpop_proof"`},
			[]Challenge{
				{Scheme: "bearer", Params: map[string]string{"error": "invalid_token"}},
				{Scheme: "dpop", Params: map[string]string{"error": "invalid_dpop_proof"}},
			},
		},
		"comma and escapes inside quotes": {
			[]string{`Bearer error_description="a, \"b\" \\ c", error=invalid_request`},
			[]Challenge{{Scheme: "bearer", Params: map[string]string{"error_description": `a, "b" \ c`, "error": "invalid_request"}}},
		},
		"case-insensitive names and BWS": {
			[]string{`BEARER Error = "invalid_token" ,, Realm=x`},
			[]Challenge{{Scheme: "bearer", Params: map[string]string{"error": "invalid_token", "realm": "x"}}},
		},
		"token68": {
			[]string{"Negotiate abc+/def==, Bearer"},
			[]Challenge{{Scheme: "negotiate", Token68: "abc+/def=="}, {Scheme: "bearer"}},
		},
		"token68 without padding": {
			[]string{"Negotiate abc, Bearer error=x"},
			[]Challenge{{Scheme: "negotiate", Token68: "abc"}, {Scheme: "bearer", Params: map[string]string{"error": "x"}}},
		},
		"empty": {nil, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Parse(tc.values)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Parse = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for name, v := range map[string]string{
		"unterminated quote":    `Bearer error="invalid_token`,
		"bad escape":            "Bearer error=\"a\\\x01\"",
		"control in quotes":     "Bearer error=\"a\x01\"",
		"duplicate parameter":   `Bearer error=a, error=b`,
		"missing value":         `Bearer realm="r", error=`,
		"leading equals":        `Bearer =x`,
		"no space after scheme": `Bearer"x"`,
		"junk after param":      `Bearer error=a b`,
		"non-ascii":             "Bearer error=\"caf\xc3\xa9\"",
		"too long":              "Bearer realm=\"" + string(make([]byte, maxValueBytes)) + "\"",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := Parse([]string{v}); err == nil {
				t.Fatalf("Parse(%q) = %#v, want error", v, got)
			}
		})
	}
}

func TestFind(t *testing.T) {
	values := []string{`Bearer error="invalid_token"`, `DPoP error="invalid_dpop_proof"`}
	c, ok, err := Find(values, "DPoP")
	if err != nil || !ok || c.Params["error"] != "invalid_dpop_proof" {
		t.Fatalf("Find(DPoP) = %#v, %v, %v", c, ok, err)
	}
	if _, ok, err := Find(values, "Basic"); ok || err != nil {
		t.Fatalf("Find(Basic) = %v, %v, want not found", ok, err)
	}
	if _, _, err := Find([]string{`Bearer error="x`}, "Bearer"); err == nil {
		t.Fatal("Find(malformed) = nil error")
	}
}
