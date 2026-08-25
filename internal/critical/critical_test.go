package critical

import "testing"

func TestCheckAcceptsEmptyCrit(t *testing.T) {
	if err := Check(nil, map[string]bool{}); err != nil {
		t.Fatalf("Check(nil, ...) = %v, want nil", err)
	}
}

func TestCheckAcceptsUnderstoodNames(t *testing.T) {
	understood := map[string]bool{"alg": true, "kid": true}
	if err := Check([]string{"alg", "kid"}, understood); err != nil {
		t.Fatalf("Check(understood names) = %v, want nil", err)
	}
}

func TestCheckRejectsUnunderstoodName(t *testing.T) {
	understood := map[string]bool{"alg": true, "kid": true}
	if err := Check([]string{"alg", "unexpected"}, understood); err == nil {
		t.Fatalf("Check(unexpected name) = nil, want error")
	}
}
