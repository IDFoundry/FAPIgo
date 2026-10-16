package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/idfoundry/fapigo/internal/resourceindicator"
	"github.com/idfoundry/fapigo/storage"
)

// replacementCharacterEscape matches a \ufffd escape in any letter case.
// It's matched against raw bytes: lowercasing raw first (bytes.ToLower)
// would itself turn invalid UTF-8 into U+FFFD.
var replacementCharacterEscape = regexp.MustCompile(`(?i)\\ufffd`)

// encodesReplacementCharacter reports whether raw, a JSON value, spells
// U+FFFD itself: as its UTF-8 bytes or as a \ufffd escape.
func encodesReplacementCharacter(raw []byte) bool {
	return bytes.Contains(raw, []byte("\uFFFD")) || replacementCharacterEscape.Match(raw)
}

// FuzzResourcesFromParameters decodes an arbitrary JSON value as a
// request object's "resource" member, then runs what it yields through
// the server's request-time check, as PAR and CIBA do. Whatever both
// accept is what an access token's aud is built from, so it must be
// what the client signed: within the per-request limit, each passing
// resourceindicator.Check, and none altered by decoding. encoding/json
// replaces invalid UTF-8 and unpaired surrogate escapes with U+FFFD
// rather than failing, so an accepted resource containing U+FFFD that
// raw doesn't spell is one the decode changed.
func FuzzResourcesFromParameters(f *testing.F) {
	f.Add([]byte(`"https://rs.example"`))
	f.Add([]byte(`["https://a.example","https://b.example/x?y=z"]`))
	f.Add([]byte(`["https://a.example","https://a.example"]`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[null]`))
	f.Add([]byte(`[["https://a.example"]]`))
	f.Add([]byte(`"https://a.example/#frag"`))
	f.Add([]byte(`"https://a.example/\ud800"`))
	f.Add([]byte("\"https://a.example/\xff\""))
	f.Add([]byte(`"https://a.example/\ufffd"`))
	f.Add([]byte(`"urn:example:\u00e9"`))
	f.Add([]byte(`["` + strings.Repeat(`https://a.example","`, 16) + `https://z.example"]`))

	s := resourceTestServer()
	f.Fuzz(func(t *testing.T, raw []byte) {
		requested, decodeErr := s.resourcesFromParameters(map[string]json.RawMessage{resourceParameter: raw})
		if decodeErr != nil {
			return
		}
		accepted, checkErr := s.checkRequestedResources(context.Background(), storage.RegisteredClient{}, requested)
		if checkErr != nil {
			return
		}
		checkAcceptedResources(t, raw, accepted)
	})
}

// checkAcceptedResources fails t unless accepted, decoded from raw, is
// within the per-request limit, passes resourceindicator.Check, and
// wasn't altered by decoding.
func checkAcceptedResources(t *testing.T, raw []byte, accepted []string) {
	t.Helper()
	if len(accepted) > resourceindicator.MaxPerRequest {
		t.Fatalf("accepted %d resources, more than %d", len(accepted), resourceindicator.MaxPerRequest)
	}
	for _, r := range accepted {
		if err := resourceindicator.Check(r); err != nil {
			t.Fatalf("accepted %q, which Check refuses: %v", r, err)
		}
		if strings.ContainsRune(r, utf8.RuneError) && !encodesReplacementCharacter(raw) {
			t.Fatalf("accepted %q from %q: decoding replaced part of it with U+FFFD", r, raw)
		}
	}
}

// FuzzSplitResourceParameters runs an arbitrary form body through
// FormRequestFromHTTP and takeResourceParameters, with resource
// indicators enabled, as every endpoint taking "resource" does. RFC 8707
// lets "resource" repeat, and nothing else: every resource value must
// come out, in order and unchanged, while a repeat of any other
// parameter is still refused by formParametersToMap, which also still
// bounds the request.
func FuzzSplitResourceParameters(f *testing.F) {
	f.Add([]byte(`grant_type=authorization_code&resource=https%3A%2F%2Fa.example&resource=https%3A%2F%2Fb.example`))
	f.Add([]byte(`resource=x&client_id=a&client_id=b`))
	f.Add([]byte(`resource=&resource=&resource=`))
	f.Add([]byte(`resource=%zz`))
	f.Add([]byte(`Resource=a&resource=b`))
	f.Add([]byte(strings.Repeat("resource=https%3A%2F%2Fa.example&", 120)))
	f.Add([]byte(strings.Repeat("a=1&", 120)))

	s := resourceTestServer()
	f.Fuzz(func(t *testing.T, body []byte) {
		req, err := http.NewRequest(http.MethodPost, "https://as.example/token", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		form, err := FormRequestFromHTTP(req)
		if err != nil {
			return
		}
		checkResourceSplit(t, s, form.Parameters)
	})
}

// checkResourceSplit fails t unless takeResourceParameters splits params
// as RFC 8707 allows: over maxFormParameters, not at all (and
// formParametersToMap refuses them); otherwise every resource value out,
// in order, and the rest unchanged, with a repeat of any of those still
// refused by formParametersToMap.
func checkResourceSplit(t *testing.T, s *Server, params []FormParameter) {
	t.Helper()
	rest, resources := s.takeResourceParameters(params)
	if len(params) > maxFormParameters {
		if !slices.Equal(rest, params) || resources != nil {
			t.Fatal("a request over the parameter bound was split")
		}
		if _, err := formParametersToMap(rest); err == nil {
			t.Fatalf("formParametersToMap accepted %d parameters", len(rest))
		}
		return
	}

	wantRest, wantResources := splitByName(params, resourceParameter)
	if !slices.Equal(resources, wantResources) {
		t.Fatalf("resources = %q, want %q", resources, wantResources)
	}
	if !slices.Equal(rest, wantRest) {
		t.Fatalf("other parameters = %v, want %v", rest, wantRest)
	}
	if _, err := formParametersToMap(rest); hasRepeatedName(rest) && err == nil {
		t.Fatal("a repeated parameter other than resource was accepted")
	}
}

// splitByName separates params named name, as values, from the rest.
func splitByName(params []FormParameter, name string) (rest []FormParameter, values []string) {
	rest = []FormParameter{}
	for _, p := range params {
		if p.Name == name {
			values = append(values, p.Value)
			continue
		}
		rest = append(rest, p)
	}
	return rest, values
}

// hasRepeatedName reports whether two of params share a name.
func hasRepeatedName(params []FormParameter) bool {
	seen := make(map[string]bool, len(params))
	for _, p := range params {
		if seen[p.Name] {
			return true
		}
		seen[p.Name] = true
	}
	return false
}
