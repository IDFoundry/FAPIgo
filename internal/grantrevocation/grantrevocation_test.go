package grantrevocation

import (
	"crypto/sha256"
	"testing"
)

// TestBackchannelGrantIDIsDomainSeparated: a CIBA grant's ID and a code
// grant's ID share CodeKey's namespace, so one derived from the same
// hash must never equal the other, and each is stable for its input.
func TestBackchannelGrantIDIsDomainSeparated(t *testing.T) {
	hash := sha256.Sum256([]byte("same input"))
	if BackchannelGrantID(hash) == CodeGrantID(hash) {
		t.Fatal("BackchannelGrantID equals CodeGrantID for the same hash")
	}
	again := sha256.Sum256([]byte("same input"))
	if BackchannelGrantID(hash) != BackchannelGrantID(again) {
		t.Fatal("BackchannelGrantID isn't deterministic")
	}
	if BackchannelGrantID(hash) == BackchannelGrantID(sha256.Sum256([]byte("other input"))) {
		t.Fatal("BackchannelGrantID ignores its input")
	}
}
