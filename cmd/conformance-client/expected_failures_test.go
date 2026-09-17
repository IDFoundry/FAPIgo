package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestLoadExpectedFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expected.json")
	body := `[
		{"test-name": "module-a", "note": "reason a"},
		{"test-name": "module-b", "note": "reason b"}
	]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	got, err := loadExpectedFailures(path)
	if err != nil {
		t.Fatalf("loadExpectedFailures() error = %v", err)
	}
	want := map[string]string{"module-a": "reason a", "module-b": "reason b"}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("got[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestLoadExpectedFailuresMissingFile(t *testing.T) {
	if _, err := loadExpectedFailures(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Fatal("loadExpectedFailures() = nil error, want error for a missing file")
	}
}

func TestCheckExpectedFailuresNoDeviations(t *testing.T) {
	summary := map[string]string{
		"module-a": "PASSED",
		"module-b": "FAILED [driver: some error]",
		"module-c": "PASSED",
	}
	moduleNames := []string{"module-a", "module-b", "module-c"}
	expected := map[string]string{"module-b": "known suite gap"}

	got := checkExpectedFailures(summary, moduleNames, expected)
	if len(got) != 0 {
		t.Errorf("checkExpectedFailures() = %v, want no deviations", got)
	}
}

// A suite-graded PASSED verdict can still carry this driver's own
// "[driver: ...]" suffix — several of this plan's own negative-test
// modules are supposed to make the driver hit an error before the
// suite grades PASSED regardless (confirmed live). That combination
// must count as passed, not as a deviation.
func TestCheckExpectedFailuresPassedWithDriverSuffixIsStillPassed(t *testing.T) {
	summary := map[string]string{
		"module-a": `PASSED [driver: discover issuer via federation: some expected validation error]`,
	}
	moduleNames := []string{"module-a"}
	expected := map[string]string{} // NOT allowlisted — this must not be flagged

	got := checkExpectedFailures(summary, moduleNames, expected)
	if len(got) != 0 {
		t.Errorf("checkExpectedFailures() = %v, want no deviations for a PASSED verdict with a driver suffix", got)
	}
}

func TestCheckExpectedFailuresUnexpectedFailure(t *testing.T) {
	summary := map[string]string{
		"module-a": "PASSED",
		"module-b": "FAILED [driver: some error]",
	}
	moduleNames := []string{"module-a", "module-b"}
	expected := map[string]string{} // module-b not allowlisted

	got := checkExpectedFailures(summary, moduleNames, expected)
	if len(got) != 1 {
		t.Fatalf("checkExpectedFailures() = %v, want exactly 1 deviation", got)
	}
	if !strings.Contains(got[0], "module-b") || !strings.Contains(got[0], "expected to PASS") {
		t.Errorf("deviation = %q, want it to mention module-b and \"expected to PASS\"", got[0])
	}
}

func TestCheckExpectedFailuresUnexpectedPass(t *testing.T) {
	summary := map[string]string{"module-a": "PASSED"}
	moduleNames := []string{"module-a"}
	expected := map[string]string{"module-a": "was supposed to be permanently broken"}

	got := checkExpectedFailures(summary, moduleNames, expected)
	if len(got) != 1 {
		t.Fatalf("checkExpectedFailures() = %v, want exactly 1 deviation", got)
	}
	if !strings.Contains(got[0], "module-a") || !strings.Contains(got[0], "PASSED") {
		t.Errorf("deviation = %q, want it to mention module-a and PASSED", got[0])
	}
}

func TestCheckExpectedFailuresStaleEntry(t *testing.T) {
	summary := map[string]string{"module-a": "PASSED"}
	moduleNames := []string{"module-a"}
	expected := map[string]string{"module-gone": "used to be a real module"}

	got := checkExpectedFailures(summary, moduleNames, expected)
	if len(got) != 1 {
		t.Fatalf("checkExpectedFailures() = %v, want exactly 1 deviation", got)
	}
	if !strings.Contains(got[0], "module-gone") {
		t.Errorf("deviation = %q, want it to mention module-gone", got[0])
	}
}

func TestCheckExpectedFailuresMultipleDeviationsSorted(t *testing.T) {
	summary := map[string]string{
		"module-a": "FAILED [driver: x]", // unexpected failure
		"module-b": "PASSED",             // unexpected pass
	}
	moduleNames := []string{"module-a", "module-b"}
	expected := map[string]string{"module-b": "note"}

	got := checkExpectedFailures(summary, moduleNames, expected)
	if len(got) != 2 {
		t.Fatalf("checkExpectedFailures() = %v, want exactly 2 deviations", got)
	}
	sort.Strings(got)
	if !strings.Contains(got[0], "module-a") || !strings.Contains(got[1], "module-b") {
		t.Errorf("deviations = %v, want one mentioning module-a and one mentioning module-b", got)
	}
}
