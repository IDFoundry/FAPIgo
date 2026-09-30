package demokit

import (
	"slices"
	"strings"
	"testing"
)

func TestChromeArgs(t *testing.T) {
	const spki = "nK7A5m80WasFupfX6hSSsB7bZXyI7mV2LJ5mXwN4aeI="
	args := chromeArgs("/tmp/profile", spki, "https://console.localhost:8443/")
	for _, a := range []string{
		"--user-data-dir=/tmp/profile",
		"--ignore-certificate-errors-spki-list=" + spki,
		"https://console.localhost:8443/",
	} {
		if !slices.Contains(args, a) {
			t.Errorf("chromeArgs is missing %q: %v", a, args)
		}
	}
	for _, a := range args {
		if a == "--ignore-certificate-errors" || strings.HasPrefix(a, "--ignore-certificate-errors=") {
			t.Error("chromeArgs turns off certificate checking for every site")
		}
	}
}

func TestFindChromeExplicitPath(t *testing.T) {
	if got, err := findChrome("/opt/custom/chrome"); err != nil || got != "/opt/custom/chrome" {
		t.Errorf("findChrome(explicit) = %q, %v", got, err)
	}
}
