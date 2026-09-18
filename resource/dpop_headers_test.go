package resource_test

import (
	"net/http"
	"testing"

	"github.com/idfoundry/fapigo/resource"
)

func TestDPoPProofsFromHTTPPreservesDuplicates(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://rs.example/accounts", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Add("DPoP", "proof-one")
	req.Header.Add("DPoP", "proof-two")

	got := resource.DPoPProofsFromHTTP(req)
	want := []string{"proof-one", "proof-two"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("DPoPProofsFromHTTP = %v, want %v", got, want)
	}
}

func TestDPoPProofsFromHTTPAbsent(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://rs.example/accounts", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	if got := resource.DPoPProofsFromHTTP(req); len(got) != 0 {
		t.Fatalf("DPoPProofsFromHTTP = %v, want empty", got)
	}
}
