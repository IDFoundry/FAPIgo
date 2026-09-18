package server_test

import (
	"net/http"
	"testing"

	"github.com/idfoundry/fapigo/server"
)

func TestDPoPProofsFromHTTPPreservesDuplicates(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://as.example/token", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Add("DPoP", "proof-one")
	req.Header.Add("DPoP", "proof-two")

	got := server.DPoPProofsFromHTTP(req)
	want := []string{"proof-one", "proof-two"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("DPoPProofsFromHTTP = %v, want %v", got, want)
	}
}

func TestDPoPProofsFromHTTPAbsent(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://as.example/token", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	if got := server.DPoPProofsFromHTTP(req); len(got) != 0 {
		t.Fatalf("DPoPProofsFromHTTP = %v, want empty", got)
	}
}

func TestClientAttestationHeadersFromHTTPPreservesDuplicates(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://as.example/token", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Add("OAuth-Client-Attestation", "attestation-one")
	req.Header.Add("OAuth-Client-Attestation", "attestation-two")
	req.Header.Add("OAuth-Client-Attestation-PoP", "pop-one")
	req.Header.Add("OAuth-Client-Attestation-PoP", "pop-two")

	attestations, pops := server.ClientAttestationHeadersFromHTTP(req)
	if len(attestations) != 2 || attestations[0] != "attestation-one" || attestations[1] != "attestation-two" {
		t.Fatalf("attestations = %v, want [attestation-one attestation-two]", attestations)
	}
	if len(pops) != 2 || pops[0] != "pop-one" || pops[1] != "pop-two" {
		t.Fatalf("pops = %v, want [pop-one pop-two]", pops)
	}
}

func TestClientAttestationHeadersFromHTTPAbsent(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://as.example/token", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	attestations, pops := server.ClientAttestationHeadersFromHTTP(req)
	if len(attestations) != 0 || len(pops) != 0 {
		t.Fatalf("attestations=%v pops=%v, want both empty", attestations, pops)
	}
}
