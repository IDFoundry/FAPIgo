#!/usr/bin/env bash
# Checks that .github/workflows/fuzz.yml's matrix lists exactly the fuzz
# targets the module defines: every `func FuzzXxx(f *testing.F)` in a
# _test.go file outside examples/ (each example is its own module, which
# fuzz.yml doesn't build), as a pkg/name pair, and nothing else. A target
# missing from the matrix still runs its seed corpus under go test, but
# is never actually fuzzed, so the mismatch is easy to miss.
#
# Usage: check-fuzz-matrix.sh [repo-root] [workflow-file]
set -euo pipefail

root=${1:-.}
workflow=${2:-$root/.github/workflows/fuzz.yml}

code=$(mktemp)
matrix=$(mktemp)
trap 'rm -f "$code" "$matrix"' EXIT

# Targets defined in code, as "<pkg> <name>" with pkg in fuzz.yml's own
# form ("." or "./dir").
(cd "$root" && grep -rE --include='*_test.go' -o '^func Fuzz[A-Za-z0-9_]*\(f \*testing\.F\)' . ) |
	grep -v '^\./examples/' |
	sed -E 's#^(.*)/[^/]+_test\.go:func (Fuzz[A-Za-z0-9_]*)\(.*#\1 \2#' |
	sort -u >"$code"

# Targets in the matrix: each "- pkg: X" entry followed by "name: Y".
awk '
	/^[[:space:]]*- pkg:[[:space:]]*/ { sub(/^[[:space:]]*- pkg:[[:space:]]*/, ""); pkg = $0; next }
	/^[[:space:]]*name:[[:space:]]*Fuzz/ && pkg != "" { sub(/^[[:space:]]*name:[[:space:]]*/, ""); print pkg " " $0; pkg = "" }
' "$workflow" | sort -u >"$matrix"

missing=$(comm -23 "$code" "$matrix")
extra=$(comm -13 "$code" "$matrix")
dupes=$(awk '{print $2}' "$code" | sort | uniq -d)

status=0
if [[ -n "$missing" ]]; then
	echo "Fuzz targets missing from $workflow's matrix (pkg name):"
	echo "$missing" | sed 's/^/  /'
	status=1
fi
if [[ -n "$extra" ]]; then
	echo "Matrix entries in $workflow with no matching fuzz target (pkg name):"
	echo "$extra" | sed 's/^/  /'
	status=1
fi
if [[ -n "$dupes" ]]; then
	# go test -fuzz='^Name$' runs per package, but a name shared across
	# packages makes the cache keys and artifact names ambiguous.
	echo "Fuzz target names defined in more than one package:"
	echo "$dupes" | sed 's/^/  /'
	status=1
fi
if [[ "$status" -eq 0 ]]; then
	echo "fuzz.yml's matrix matches all $(wc -l <"$code" | tr -d ' ') fuzz targets."
fi
exit "$status"
