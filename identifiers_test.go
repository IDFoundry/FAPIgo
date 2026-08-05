package fapi

import "testing"

func TestRegisteredRedirectURIEqualIsExact(t *testing.T) {
	r := RegisteredRedirectURI("https://rp.example/callback")

	cases := []struct {
		candidate string
		want      bool
	}{
		{"https://rp.example/callback", true},
		{"https://rp.example/callback/", false},
		{"https://rp.example:443/callback", false},
		{"HTTPS://rp.example/callback", false},
		{"https://rp.example/callback?extra=1", false},
	}
	for _, c := range cases {
		if got := r.Equal(c.candidate); got != c.want {
			t.Fatalf("Equal(%q) = %v, want %v", c.candidate, got, c.want)
		}
	}
}
