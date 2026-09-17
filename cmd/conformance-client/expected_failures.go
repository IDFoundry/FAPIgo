// This file adds an expected-failures allowlist for -profile=federation
// — the RP conformance plan's own permanent, confirmed-suite-side gap
// (conformance/client/scripts/README.md's "Federation" section: 3 of 10
// modules never PASS, traced to the suite's own mock OP never setting
// the "issuer" metadata field OIDC Discovery 1.0 §3 requires). Every
// other profile this driver runs is expected 100% clean, so this is the
// first (and so far only) profile that needs it — the AS-side
// conformance/server scripts have had an equivalent mechanism
// (expected-skips-federation.json/expected-warnings-federation.json)
// for a while; this is the RP-side counterpart, at this driver's own
// coarser module-level grain (that side tracks individual FAILURE/
// WARNING log entries within a module; this driver's own summary line
// is already one verdict per module, so there is no finer grain to
// track here).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// expectedFailure is one entry in an expected-failures JSON file: a
// module this driver's own live run is known to never get a PASSED
// verdict for, and why — see loadExpectedFailures.
type expectedFailure struct {
	TestName string `json:"test-name"`
	Note     string `json:"note"`
}

// loadExpectedFailures reads path (a JSON array of expectedFailure) and
// returns it as a map keyed by TestName for checkExpectedFailures'
// own O(1) lookups.
func loadExpectedFailures(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is this driver's own -expected-failures flag value, not untrusted input
	if err != nil {
		return nil, fmt.Errorf("read expected failures file: %w", err)
	}
	var entries []expectedFailure
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parse expected failures file: %w", err)
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		out[e.TestName] = e.Note
	}
	return out, nil
}

// checkExpectedFailures compares summary (moduleName -> this driver's
// own result.String(), main.go's moduleResult) against expected
// (moduleName -> note, loadExpectedFailures) for every module named in
// moduleNames, and returns one deviation line per module whose actual
// PASSED-or-not state doesn't match what's expected — in either
// direction: a module expected to fail that actually PASSED is exactly
// as reportable as one that unexpectedly didn't, mirroring the AS
// side's own bidirectional philosophy (a silently-fixed suite bug
// should prompt removing its allowlist entry, not just accumulate an
// ever-growing list that nobody re-checks). A stale expected-failures
// entry naming a module that isn't in moduleNames at all (the suite
// renamed or removed it) is also reported, for the same reason.
//
// A "PASSED" prefix counts as passed, not an exact match: confirmed
// live that main.go's moduleResult.String() still leads with "PASSED"
// even when this driver's own DriverErr is set alongside it (the
// "[driver: ...]" suffix) — several of this plan's own negative-test
// modules are *supposed* to make this driver hit an error before the
// suite grades the module PASSED regardless, so that suffix on an
// otherwise-passing module is expected, common, and not itself a
// deviation. Every other outcome (a different leading verdict, a
// driver-side ERROR with no suite-graded verdict at all) is "not
// passed" for this comparison.
func checkExpectedFailures(summary map[string]string, moduleNames []string, expected map[string]string) []string {
	var deviations []string
	seen := make(map[string]bool, len(moduleNames))
	for _, name := range moduleNames {
		seen[name] = true
		result, ok := summary[name]
		if !ok {
			continue // module never ran (shouldn't happen; nothing to compare)
		}
		passed := strings.HasPrefix(result, "PASSED")
		note, expectedToFail := expected[name]
		switch {
		case passed && expectedToFail:
			deviations = append(deviations, fmt.Sprintf(
				"%s: expected to fail (%s) but PASSED — remove its expected-failures entry", name, note))
		case !passed && !expectedToFail:
			deviations = append(deviations, fmt.Sprintf(
				"%s: expected to PASS but got %q", name, result))
		}
	}
	for name, note := range expected {
		if !seen[name] {
			deviations = append(deviations, fmt.Sprintf(
				"%s: has an expected-failures entry (%s) but the suite's own plan no longer includes this module", name, note))
		}
	}
	return deviations
}
