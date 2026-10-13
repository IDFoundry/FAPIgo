package server

import (
	"bytes"
	"slices"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/pairwise"
)

// TestSubjectTypesSupported covers discovery for configurations New
// can't build yet (while pairwise subjects aren't issued).
func TestSubjectTypesSupported(t *testing.T) {
	deriver, err := pairwise.NewHMAC(bytes.Repeat([]byte{0x33, 0x94}, 16))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		cfg     Config
		deriver pairwise.Deriver
		want    []string
	}{
		"public":                 {Config{Subjects: PublicSubjects()}, nil, []string{"public"}},
		"OAuthOnly, zero":        {Config{OAuthOnly: true}, nil, []string{"public"}},
		"public, with a deriver": {Config{Subjects: PublicSubjects()}, deriver, []string{"public", "pairwise"}},
		"pairwise default":       {Config{Subjects: SubjectConfig{Default: fapi.SubjectTypePairwise, Enforcement: SubjectTypesPerClient}}, deriver, []string{"public", "pairwise"}},
		"pairwise only":          {Config{Subjects: SubjectConfig{Default: fapi.SubjectTypePairwise, Enforcement: SubjectTypesPairwiseOnly}}, deriver, []string{"pairwise"}},
	}
	for name, tc := range tests {
		s := &Server{cfg: tc.cfg, deps: Dependencies{PairwiseSubjects: tc.deriver}}
		if got := s.subjectTypesSupported(); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

func TestSubjectTypeEnforcementIsValid(t *testing.T) {
	for e, want := range map[SubjectTypeEnforcement]bool{0: false, SubjectTypesPerClient: true, SubjectTypesPairwiseOnly: true, 3: false} {
		if e.IsValid() != want {
			t.Errorf("SubjectTypeEnforcement(%d).IsValid() = %v", e, !want)
		}
	}
}
