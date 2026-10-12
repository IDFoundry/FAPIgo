package fapi

import "testing"

func TestSubjectTypeRoundTrips(t *testing.T) {
	for _, st := range []SubjectType{SubjectTypePublic, SubjectTypePairwise} {
		if !st.IsValid() {
			t.Errorf("%v.IsValid() = false", st)
		}
		parsed, err := ParseSubjectType(st.String())
		if err != nil || parsed != st {
			t.Errorf("ParseSubjectType(%q) = %v, %v; want %v", st.String(), parsed, err, st)
		}
	}
}

func TestSubjectTypeZeroAndUnknownAreInvalid(t *testing.T) {
	for _, st := range []SubjectType{0, 3, 255} {
		if st.IsValid() {
			t.Errorf("SubjectType(%d).IsValid() = true", st)
		}
		if st.String() != "" {
			t.Errorf("SubjectType(%d).String() = %q, want \"\"", st, st.String())
		}
	}
}

func TestParseSubjectTypeRefusesOtherValues(t *testing.T) {
	for _, value := range []string{"", "Public", "Pairwise", "PAIRWISE", " public", "pairwise ", "public\x00", "ppid"} {
		if st, err := ParseSubjectType(value); err == nil {
			t.Errorf("ParseSubjectType(%q) = %v, want an error", value, st)
		}
	}
}

func FuzzParseSubjectType(f *testing.F) {
	for _, seed := range []string{"public", "pairwise", "", "Public", "pairwise\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		st, err := ParseSubjectType(value)
		if err != nil {
			if st != 0 {
				t.Fatalf("ParseSubjectType(%q) returned %v with an error", value, st)
			}
			return
		}
		if !st.IsValid() || st.String() != value {
			t.Fatalf("ParseSubjectType(%q) = %v, which doesn't round-trip", value, st)
		}
	})
}
