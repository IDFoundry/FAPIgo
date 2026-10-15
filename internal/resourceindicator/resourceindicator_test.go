package resourceindicator

import (
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	for value, wantOK := range map[string]bool{
		"https://api.example.com/":           true,
		"https://api.example.com/app/":       true,
		"https://api.example.com/x?tenant=1": true,
		"urn:example:resource":               true,
		"":                                   false,
		"/relative/path":                     false,
		"api.example.com":                    false,
		"https://api.example.com/#frag":      false,
		"https://api.example.com/#":          false,
		"https://api.example.com/ x":         false,
		"https://api.example.com/\x00":       false,
		"https://api.example.com/\xff":       false,
		"https://api.example.com/" + strings.Repeat("a", MaxLength): false,
	} {
		if err := Check(value); (err == nil) != wantOK {
			t.Errorf("Check(%q) = %v, want ok %v", value, err, wantOK)
		}
	}
}
