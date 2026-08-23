package server_test

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
)

func TestKeyManagementAlgorithmSetContains(t *testing.T) {
	set := server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
	if !set.Contains(fapi.RSAOAEP256) {
		t.Fatalf("Contains(RSAOAEP256) = false, want true")
	}
	if set.Contains(fapi.ECDHESA256KW) {
		t.Fatalf("Contains(ECDHESA256KW) = true, want false")
	}
}

func TestContentEncryptionAlgorithmSetContains(t *testing.T) {
	set := server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
	if !set.Contains(fapi.A256GCM) {
		t.Fatalf("Contains(A256GCM) = false, want true")
	}
	if set.Contains(fapi.ContentEncryptionAlgorithm(99)) {
		t.Fatalf("Contains(unknown) = true, want false")
	}
}
