// This file adds OIDF RP-certification evidence output: one named log
// file per test module, rather than the one shared stdout log run's own
// main loop already prints. OIDF's own RP certification requirements
// call for evidence showing what the client itself did for every test
// — a bare PASSED/FAILED grade from the suite doesn't demonstrate that,
// since the suite can't see inside the client under test — and for a
// file appropriately named per test, not one giant combined log
// covering the whole run. See conformance/client/scripts/README.md's
// "Certification evidence" section.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// unsafeEvidenceFilenameChars matches anything outside a conservative
// filename-safe allow-list. testName is suite-assigned, not attacker
// input, but it still becomes a filesystem path component here, so
// it's sanitized defensively rather than trusted outright.
var unsafeEvidenceFilenameChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// writeEvidence writes one evidence file for a single test module into
// dir, named after the module's own suite-assigned test name. The
// content is structured, not just the bare verdict word: DRIVER
// already carries a specific, human-readable account of what this
// driver's own client detected for every negative-test module today
// (e.g. "complete authorization: jarm: signature verification failed")
// — this just gives it a home of its own instead of one shared log
// covering every module in the run.
func writeEvidence(dir, testName string, result moduleResult, apiBase string) error {
	safeName := unsafeEvidenceFilenameChars.ReplaceAllString(testName, "_")
	path := filepath.Join(dir, safeName+".log")

	driverLine := result.DriverErr
	if driverLine == "" {
		driverLine = "none — client completed the full discover/authorize/token/resource flow without error"
	}
	suiteLog := "unavailable — module instance was never created"
	if result.ModuleID != "" {
		suiteLog = apiBase + "api/log/" + result.ModuleID
	}

	content := fmt.Sprintf(
		"TEST: %s\nRESULT: %s\nDRIVER: %s\nSUITE LOG: %s\n",
		testName, result.Verdict, driverLine, suiteLog,
	)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create evidence directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write evidence file: %w", err)
	}
	return nil
}
