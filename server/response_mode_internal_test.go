package server

import (
	"encoding/json"
	"testing"
)

// TestCheckResponseModeUnderMessageSigning: under
// ProfileFAPISecurityWithMessageSigning the server answers in JARM, so
// "jwt" and "query.jwt" (the code flow's "jwt") pass and "query" is
// refused.
func TestCheckResponseModeUnderMessageSigning(t *testing.T) {
	s := &Server{cfg: Config{Profile: ProfileFAPISecurityWithMessageSigning}}
	for mode, wantOK := range map[string]bool{"jwt": true, "query.jwt": true, "query": false, "form_post.jwt": false} {
		raw, _ := json.Marshal(mode)
		err := s.checkResponseMode(map[string]json.RawMessage{"response_mode": raw})
		if (err == nil) != wantOK {
			t.Errorf("response_mode=%q: %v, want accepted %v", mode, err, wantOK)
		}
	}
	if err := s.checkResponseMode(map[string]json.RawMessage{}); err != nil {
		t.Errorf("no response_mode: %v", err)
	}
}
