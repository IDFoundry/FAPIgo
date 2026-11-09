//go:build ignore

// Command mutation-check is mutation.yml's runner. It applies each
// mutant in .github/mutation/mutants.json to a security check, runs
// the tests that should catch it, restores the file and fails if any
// mutant survives: a check the tests no longer protect.
//
// Each mutant names a literal snippet ("old") that must occur exactly
// once in its file and the text that replaces it ("new"), so an entry
// is anchored by text, never by line number. A refactor that moves or
// rewrites an anchored check makes its anchor stale, and the run fails
// until the entry is updated to match.
//
// Every mutated file is restored from the copy read before mutating it,
// never from git, so uncommitted work in the tree is safe. An interrupt
// restores it too.
//
// Run from the repository root:
//
//	go run .github/scripts/mutation-check.go           # every mutant
//	go run .github/scripts/mutation-check.go S1 C3     # just these
//
// The mutants marked "postgres" need FAPIGO_SQLSTORE_POSTGRES_DSN (see
// sqlstore/README.md). Without it they're skipped locally; under CI a
// missing DSN fails the run.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const listPath = ".github/mutation/mutants.json"

type mutant struct {
	ID       string   `json:"id"`
	File     string   `json:"file"`
	Old      string   `json:"old"`
	New      string   `json:"new"`
	Module   string   `json:"module"`
	Packages []string `json:"packages"`
	Run      string   `json:"run,omitempty"`
	Postgres bool     `json:"postgres,omitempty"`
	Why      string   `json:"why"`
}

type result struct {
	m      mutant
	status string
	detail string
	took   time.Duration
}

// The module directories, relative to the repository root.
var modules = map[string]string{"root": ".", "sqlstore": "sqlstore"}

// restore holds the file being mutated and its original contents, for
// the interrupt handler.
var restore struct {
	sync.Mutex
	path string
	data []byte
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mutation-check:", err)
		os.Exit(1)
	}
}

func run(only []string) error {
	mutants, err := load(only)
	if err != nil {
		return err
	}
	watchInterrupt()

	ci := os.Getenv("CI") != ""
	havePG := os.Getenv("FAPIGO_SQLSTORE_POSTGRES_DSN") != ""
	if !havePG && ci && needsPostgres(mutants) {
		return errors.New("FAPIGO_SQLSTORE_POSTGRES_DSN is unset under CI: the postgres mutants must run there")
	}

	if err := baseline(mutants, havePG); err != nil {
		return err
	}

	start := time.Now()
	var results []result
	for _, m := range mutants {
		r := apply(m, havePG)
		fmt.Printf("%-45s %-12s %6.1fs  %s\n", m.ID, r.status, r.took.Seconds(), r.detail)
		results = append(results, r)
	}
	failed := report(results, time.Since(start))
	if failed > 0 {
		return fmt.Errorf("%d of %d mutants not killed (see the table above)", failed, len(results))
	}
	return nil
}

func load(only []string) ([]mutant, error) {
	data, err := os.ReadFile(listPath)
	if err != nil {
		return nil, fmt.Errorf("run from the repository root: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var all []mutant
	if err := dec.Decode(&all); err != nil {
		return nil, fmt.Errorf("%s: %w", listPath, err)
	}
	seen := map[string]bool{}
	for _, m := range all {
		switch {
		case m.ID == "" || seen[m.ID]:
			return nil, fmt.Errorf("%s: missing or duplicate id %q", listPath, m.ID)
		case modules[m.Module] == "":
			return nil, fmt.Errorf("%s: %s: module must be root or sqlstore", listPath, m.ID)
		case !filepath.IsLocal(m.File) || filepath.Clean(m.File) != m.File:
			return nil, fmt.Errorf("%s: %s: file must be a clean path inside the repository", listPath, m.ID)
		case m.Module == "sqlstore" && !strings.HasPrefix(m.File, "sqlstore/"):
			return nil, fmt.Errorf("%s: %s: a sqlstore mutant's file must be under sqlstore/", listPath, m.ID)
		case m.Old == "" || m.Old == m.New || len(m.Packages) == 0 || m.Why == "":
			return nil, fmt.Errorf("%s: %s: needs old, a different new, packages and why", listPath, m.ID)
		}
		if _, err := regexp.Compile(m.Run); err != nil {
			return nil, fmt.Errorf("%s: %s: run: %w", listPath, m.ID, err)
		}
		seen[m.ID] = true
	}
	if len(only) == 0 {
		return all, nil
	}
	var picked []mutant
	for _, id := range only {
		if !seen[id] {
			return nil, fmt.Errorf("no mutant %q in %s", id, listPath)
		}
		for _, m := range all {
			if m.ID == id {
				picked = append(picked, m)
			}
		}
	}
	return picked, nil
}

func needsPostgres(mutants []mutant) bool {
	for _, m := range mutants {
		if m.Postgres {
			return true
		}
	}
	return false
}

// baseline runs, unmutated, every test a mutant below will run, once per
// package: a test that already fails would kill its mutant for the
// wrong reason. It also checks each mutant's run filter names a test in
// its packages, or the mutant would survive with nothing run.
func baseline(mutants []mutant, havePG bool) error {
	type pkgKey struct{ module, pkg string }
	runs := map[pkgKey][]string{}
	whole := map[pkgKey]bool{}
	for _, m := range mutants {
		if m.Postgres && !havePG {
			continue
		}
		for _, p := range m.Packages {
			k := pkgKey{m.Module, p}
			if m.Run == "" {
				whole[k] = true
			} else {
				runs[k] = append(runs[k], m.Run)
			}
		}
	}
	keys := make([]pkgKey, 0, len(runs)+len(whole))
	for k := range runs {
		keys = append(keys, k)
	}
	for k := range whole {
		if _, ok := runs[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].module+keys[i].pkg < keys[j].module+keys[j].pkg
	})
	start := time.Now()
	ran := map[pkgKey][]string{}
	for _, k := range keys {
		filter := ""
		if !whole[k] {
			filter = strings.Join(runs[k], "|")
		}
		out, err := goTest(k.module, []string{k.pkg}, filter, true)
		if err != nil {
			fmt.Fprint(os.Stderr, tail(out, 60))
			return fmt.Errorf("baseline: %s tests fail before any mutation: fix them first", k.pkg)
		}
		for _, match := range runRE.FindAllStringSubmatch(out, -1) {
			if !strings.Contains(match[1], "/") {
				ran[k] = append(ran[k], match[1])
			}
		}
	}
	for _, m := range mutants {
		if m.Run == "" || (m.Postgres && !havePG) {
			continue
		}
		re := regexp.MustCompile(m.Run)
		found := false
		for _, p := range m.Packages {
			for _, name := range ran[pkgKey{m.Module, p}] {
				found = found || re.MatchString(name)
			}
		}
		if !found {
			return fmt.Errorf("%s: run filter %q matches no test in %s: update %s", m.ID, m.Run, strings.Join(m.Packages, " "), listPath)
		}
	}
	fmt.Printf("baseline: %d packages pass unmutated (%.0fs)\n", len(keys), time.Since(start).Seconds())
	return nil
}

var runRE = regexp.MustCompile(`(?m)^=== RUN\s+(\S+)`)

var failRE = regexp.MustCompile(`--- FAIL: (\S+)`)

func apply(m mutant, havePG bool) result {
	r := result{m: m}
	if m.Postgres && !havePG {
		r.status = "SKIPPED"
		r.detail = "needs FAPIGO_SQLSTORE_POSTGRES_DSN"
		return r
	}
	orig, err := os.ReadFile(m.File)
	if err != nil {
		r.status = "STALE"
		r.detail = err.Error()
		return r
	}
	if n := bytes.Count(orig, []byte(m.Old)); n != 1 {
		r.status = "STALE"
		r.detail = fmt.Sprintf("anchor for %s no longer matches %s (%d occurrences, want 1): update %s", m.ID, m.File, n, listPath)
		return r
	}
	mutated := bytes.Replace(orig, []byte(m.Old), []byte(m.New), 1)

	restore.Lock()
	restore.path, restore.data = m.File, orig
	restore.Unlock()
	defer func() {
		restore.Lock()
		defer restore.Unlock()
		if err := writeBack(m.File, orig); err != nil {
			fmt.Fprintf(os.Stderr, "mutation-check: RESTORE %s BY HAND: %v\n", m.File, err)
			os.Exit(2)
		}
		restore.path = ""
	}()
	if err := writeBack(m.File, mutated); err != nil {
		r.status = "STALE"
		r.detail = err.Error()
		return r
	}

	start := time.Now()
	out, err := goTest(m.Module, m.Packages, m.Run, false)
	r.took = time.Since(start)
	switch {
	case strings.Contains(out, "[build failed]") || strings.Contains(out, "[setup failed]"):
		r.status = "BUILD-FAILED"
		r.detail = "the mutant must compile: " + firstLine(out)
	case err == nil:
		r.status = "SURVIVED"
		r.detail = "no test failed: " + m.Why
	default:
		r.status = "KILLED"
		names := uniq(failRE.FindAllStringSubmatch(out, -1))
		if len(names) == 0 {
			r.detail = firstLine(out)
		} else {
			r.detail = strings.Join(names, ", ")
		}
	}
	return r
}

// writeBack replaces the contents of path, a source file that already
// exists, so its mode is kept (WriteFile's applies only to a new file).
func writeBack(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600) //nolint:gosec // path is a mutant's file, checked local to the repository by load
}

func goTest(module string, pkgs []string, filter string, verbose bool) (string, error) {
	args := []string{"test", "-count=1", "-vet=off", "-timeout=10m"}
	if verbose {
		args = append(args, "-v")
	}
	if filter != "" {
		args = append(args, "-run", filter)
	}
	args = append(args, pkgs...)
	cmd := exec.Command("go", args...)
	cmd.Dir = modules[module]
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// report prints the results as a markdown table, to stdout and to the
// job summary, and returns how many mutants weren't killed.
func report(results []result, took time.Duration) int {
	var b strings.Builder
	failed, skipped := 0, 0
	for _, r := range results {
		switch r.status {
		case "KILLED":
		case "SKIPPED":
			skipped++
		default:
			failed++
		}
	}
	fmt.Fprintf(&b, "## Mutation check\n\n%d mutants: %d killed, %d not killed, %d skipped (%.0fs).\n\n",
		len(results), len(results)-failed-skipped, failed, skipped, took.Seconds())
	b.WriteString("| Mutant | Result | File | Guards | Detail |\n|---|---|---|---|---|\n")
	for _, r := range results {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", r.m.ID, r.status, r.m.File, cell(r.m.Why), cell(r.detail))
	}
	fmt.Print("\n" + b.String())
	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // the runner's own job summary file
		if err == nil {
			_, _ = f.WriteString(b.String())
			_ = f.Close()
		}
	}
	return failed
}

func watchInterrupt() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		restore.Lock()
		if restore.path != "" {
			_ = writeBack(restore.path, restore.data)
			fmt.Fprintln(os.Stderr, "\nmutation-check: interrupted; restored", restore.path)
		}
		os.Exit(130)
	}()
}

func uniq(matches [][]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		// Report the top-level test; its subtests' names add nothing.
		name, _, _ := strings.Cut(m[1], "/")
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

func firstLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "ok ") {
			return l
		}
	}
	return ""
}

func tail(out string, n int) string {
	lines := strings.Split(out, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}
