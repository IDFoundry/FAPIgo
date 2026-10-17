#!/usr/bin/env bash
# Runs one fuzz target for fuzz.yml: go test -fuzz for <fuzztime>.
#
# go test -fuzz sometimes fails right at -fuzztime with "context deadline
# exceeded" and no failing input: a harness quirk, not a finding. That
# outcome alone is reported as a warning and the job passes. Anything
# else that fails still fails, and a real finding always writes its
# input under <pkg>/testdata/fuzz/<target>/ (which fuzz.yml uploads), so
# a run that wrote one, panicked, or failed for any other reason is
# never mistaken for the quirk.
#
# Usage: fuzz-target.sh <pkg> <target> <fuzztime>
set -uo pipefail

pkg=$1
target=$2
fuzztime=$3
corpus="$pkg/testdata/fuzz/$target"

list_inputs() {
	if [[ -d "$corpus" ]]; then
		find "$corpus" -type f | sort
	fi
	return 0
}

log=$(mktemp)
trap 'rm -f "$log"' EXIT

before=$(list_inputs)
go test "$pkg" -run='^$' -fuzz="^${target}\$" -fuzztime="$fuzztime" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
after=$(list_inputs)

if [[ "$status" -eq 0 ]]; then
	exit 0
fi

if [[ "$before" = "$after" ]] &&
	grep -q 'context deadline exceeded' "$log" &&
	! grep -qE 'Failing input written|^panic:|fatal error:' "$log"; then
	echo "::warning title=$target::go test -fuzz stopped with \"context deadline exceeded\" at -fuzztime and wrote no failing input: the known go test -fuzz harness quirk, not a finding."
	exit 0
fi

exit "$status"
