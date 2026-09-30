package demokit

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// chromeArgs opens urls in a separate Chrome profile under profileDir
// that accepts the certificate whose key hashes to spki without a
// warning. Only that key: every other site is checked as usual. Chrome
// honours the SPKI list only with its own --user-data-dir, which also
// keeps the demo out of your normal profile.
func chromeArgs(profileDir, spki string, urls ...string) []string {
	args := []string{
		"--user-data-dir=" + profileDir,
		"--ignore-certificate-errors-spki-list=" + spki,
		"--no-first-run",
		"--no-default-browser-check",
	}
	return append(args, urls...)
}

// chromeCandidates are where Chrome (or Chromium) usually is on this OS.
func chromeCandidates() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	case "windows":
		var out []string
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
			if dir := os.Getenv(env); dir != "" {
				out = append(out, filepath.Join(dir, "Google", "Chrome", "Application", "chrome.exe"))
			}
		}
		return out
	default:
		return []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"}
	}
}

// findChrome returns the Chrome executable to run: path if given,
// otherwise the first of chromeCandidates that exists.
func findChrome(path string) (string, error) {
	if path != "" {
		return path, nil
	}
	for _, c := range chromeCandidates() {
		if found, err := exec.LookPath(c); err == nil {
			return found, nil
		}
	}
	return "", errors.New("no Chrome or Chromium found in the usual places; pass its path with -chrome")
}

// OpenChrome starts Chrome on urls with its profile in
// state/chrome-profile, accepting the certificate whose key hashes to
// spki (Net.ServingSPKIHash). chromePath is Chrome's executable, or ""
// to look in the usual places. It doesn't wait for Chrome to exit.
func OpenChrome(chromePath, state, spki string, urls ...string) error {
	path, err := findChrome(chromePath)
	if err != nil {
		return err
	}
	profile, err := filepath.Abs(filepath.Join(state, "chrome-profile"))
	if err != nil {
		return err
	}
	cmd := exec.Command(path, chromeArgs(profile, spki, urls...)...) //nolint:gosec // G204: the operator's own browser, with arguments built here
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
