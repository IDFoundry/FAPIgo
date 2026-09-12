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

func TestAlgorithmSetStrings(t *testing.T) {
	set := server.AlgorithmSet{fapi.ES256, fapi.PS256, fapi.EdDSA}
	got := set.Strings()
	want := []string{fapi.ES256.String(), fapi.PS256.String(), fapi.EdDSA.String()}
	if len(got) != len(want) {
		t.Fatalf("Strings() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Strings()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAlgorithmSetStringsEmpty(t *testing.T) {
	var set server.AlgorithmSet
	if got := set.Strings(); len(got) != 0 {
		t.Fatalf("Strings() = %v, want empty", got)
	}
}

func TestKeyManagementAlgorithmSetStrings(t *testing.T) {
	set := server.KeyManagementAlgorithmSet{fapi.RSAOAEP256}
	got := set.Strings()
	want := []string{fapi.RSAOAEP256.String()}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("Strings() = %v, want %v", got, want)
	}
}

func TestContentEncryptionAlgorithmSetStrings(t *testing.T) {
	set := server.ContentEncryptionAlgorithmSet{fapi.A256GCM}
	got := set.Strings()
	want := []string{fapi.A256GCM.String()}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("Strings() = %v, want %v", got, want)
	}
}
