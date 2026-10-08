package replaykey

import "testing"

func TestDigestSeparatesScopes(t *testing.T) {
	if Digest("client-a", "jti-1") == Digest("client-b", "jti-1") {
		t.Fatal("the same jti from two scopes has one digest")
	}
	first, second := Digest("client-a", "jti-1"), Digest("client-a", "jti-1")
	if first != second {
		t.Fatal("Digest isn't deterministic")
	}
	// Without the length prefix, ("ab", "c") and ("a", "bc") would
	// collide.
	if Digest("ab", "c") == Digest("a", "bc") {
		t.Fatal("shifting a byte between scope and jti keeps the digest")
	}
}
