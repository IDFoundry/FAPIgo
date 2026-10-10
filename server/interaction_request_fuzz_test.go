package server

import (
	"reflect"
	"testing"
)

// FuzzInteractionRequestRoundTrip: anything ParseInteractionRequest
// accepts re-encodes and parses back to the same value, and parsing
// never panics.
func FuzzInteractionRequestRoundTrip(f *testing.F) {
	enc, _ := InteractionRequest{Prompt: Prompt{PromptLogin}}.MarshalText()
	f.Add(string(enc))
	f.Add("")
	f.Add("{}")
	f.Fuzz(func(t *testing.T, text string) {
		req, err := ParseInteractionRequest(text)
		if err != nil {
			return
		}
		again, err := req.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText of a parsed request: %v", err)
		}
		back, err := ParseInteractionRequest(string(again))
		if err != nil {
			t.Fatalf("re-parse of %q: %v", again, err)
		}
		if !reflect.DeepEqual(req, back) {
			t.Fatalf("round trip changed the request:\n %+v\n %+v", req, back)
		}
	})
}
