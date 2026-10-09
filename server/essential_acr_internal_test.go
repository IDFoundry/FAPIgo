package server

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestEssentialACRValues(t *testing.T) {
	for _, tc := range []struct {
		name    string
		claims  string // the raw "claims" value; "" for none
		want    []string
		wantErr bool
	}{
		{name: "no claims"},
		{name: "object form", claims: `{"id_token":{"acr":{"essential":true,"values":["a","b"]}}}`, want: []string{"a", "b"}},
		{name: "string form", claims: `"{\"id_token\":{\"acr\":{\"essential\":true,\"value\":\"a\"}}}"`, want: []string{"a"}},
		{name: "value and values joined once each", claims: `{"id_token":{"acr":{"essential":true,"value":"a","values":["b","a"]}}}`, want: []string{"a", "b"}},
		{name: "voluntary", claims: `{"id_token":{"acr":{"values":["a"]}}}`},
		{name: "null entry", claims: `{"id_token":{"acr":null}}`},
		{name: "userinfo acr ignored", claims: `{"userinfo":{"acr":{"essential":true,"value":"a"}}}`},
		{name: "no acr entry", claims: `{"id_token":{"email":null}}`},
		{name: "unparseable claims left alone", claims: `{"id_token":`},
		{name: "entry not an object", claims: `{"id_token":{"acr":true}}`, wantErr: true},
		{name: "essential not a bool", claims: `{"id_token":{"acr":{"essential":1}}}`, wantErr: true},
		{name: "values with a non-string", claims: `{"id_token":{"acr":{"essential":true,"values":["a",2]}}}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := map[string]json.RawMessage{}
			if tc.claims != "" {
				params["claims"] = json.RawMessage(tc.claims)
			}
			got, err := essentialACRValues(params)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("values = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMeetsEssentialACR(t *testing.T) {
	if !meetsEssentialACR(nil, "") || !meetsEssentialACR(nil, "x") {
		t.Error("no requirement must always be met")
	}
	if !meetsEssentialACR([]string{"a", "b"}, "b") {
		t.Error("a listed acr must meet the requirement")
	}
	if meetsEssentialACR([]string{"a"}, "") || meetsEssentialACR([]string{"a"}, "A") {
		t.Error("an unlisted or differently-cased acr must not meet the requirement")
	}
}
