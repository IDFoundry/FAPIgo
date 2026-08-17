#!/usr/bin/env bash
# Runs all four FAPI2 conformance suites this repo has driver support
# for — AS baseline, AS message-signing, RP baseline, RP
# message-signing — against a locally running OIDF conformance suite,
# and prints one combined summary at the end.
#
# Always runs all four, even if an earlier one comes back unclean —
# never stops early — so a bad result in one suite never hides results
# from the other three.
#
# Prerequisites (see conformance/server/scripts/README.md and
# conformance/client/scripts/README.md for the one-time setup each of
# these implies):
#   - The OIDF conformance suite itself running locally
#     (https://localhost.emobix.co.uk:8443 by default).
#   - CONFORMANCE_SUITE_CHECKOUT set to that suite's own git checkout
#     (this script runs its scripts/run-test-plan.py from there).
#   - conformance/server/oidf-config/{baseline,message-signing}-plan.json
#     already filled in (gitignored — carries private keys; see that
#     directory's README).
#   - Docker, for the conformance-as-baseline/-message-signing
#     containers (brought up automatically by this script).
#
# Usage:
#   export CONFORMANCE_SUITE_CHECKOUT=/path/to/conformance-suite
#   export SUITE_NETWORK=<network from `docker network ls`>   # only if not the default
#   ./conformance/scripts/run-all.sh
#
# A clean "UNEXPECTED RESULTS" on an AS suite doesn't necessarily mean
# an AS regression — check the module names in the linked log first.
# Two categories are already known, understood, and NOT (yet) added to
# expected-warnings-*.json because they're artifacts of
# unblock-implicit-callback.py standing in for a real browser, not of
# the AS: (1) par-ensure-reused-request-uri-prior-to-auth-completion-succeeds
# needs the same login page visited twice, once unauthenticated and
# once already authenticated - a generic empty-body POST can't
# reproduce that; (2) occasional, non-deterministic timing races on
# multi-client/multi-step modules (a stray token-endpoint 4xx, a
# module receiving another module's stray callback) when the poller
# happens to move faster than the suite's own internal state machine
# expects. Neither has ever been traced to a real protocol violation
# by cmd/conformance-as - see unblock-implicit-callback.py's own doc
# comment for the full detail.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SERVER_DIR="$REPO_ROOT/conformance/server"
POLLER="$SERVER_DIR/scripts/unblock-implicit-callback.py"
CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://localhost.emobix.co.uk:8443/}"

: "${CONFORMANCE_SUITE_CHECKOUT:?Set CONFORMANCE_SUITE_CHECKOUT to your local OIDF conformance-suite checkout — see conformance/server/scripts/README.md step 1}"
if [ ! -f "$CONFORMANCE_SUITE_CHECKOUT/scripts/run-test-plan.py" ]; then
	echo "error: $CONFORMANCE_SUITE_CHECKOUT/scripts/run-test-plan.py not found — is CONFORMANCE_SUITE_CHECKOUT correct?" >&2
	exit 1
fi

WORKDIR="$(mktemp -d)"
declare -a POLLER_PIDS=()
RESULTS_FILE="$WORKDIR/results.txt"
touch "$RESULTS_FILE"
OVERALL_CLEAN=true

# record_result NAME LINE — appends "NAME|LINE" to $RESULTS_FILE. Not an
# associative array (declare -A needs bash 4+; the stock /bin/bash on
# macOS is 3.2), so results are looked up by grepping this file instead.
record_result() {
	printf '%s|%s\n' "$1" "$2" >>"$RESULTS_FILE"
}

lookup_result() {
	grep -F "$1|" "$RESULTS_FILE" 2>/dev/null | tail -1 | cut -d'|' -f2- || true
}

cleanup() {
	for pid in "${POLLER_PIDS[@]:-}"; do
		kill "$pid" >/dev/null 2>&1 || true
	done
	# Deliberately not removing $WORKDIR: it holds every suite's full
	# run-test-plan.py/driver log, which is exactly what's needed to
	# diagnose an "UNEXPECTED RESULTS" line in the summary below. Left
	# under mktemp's own directory (normally /tmp), so it doesn't
	# accumulate in the repo and the OS reclaims it eventually.
}
trap cleanup EXIT

log() { echo "[run-all] $*"; }

check_suite_reachable() {
	if ! curl -sk --max-time 5 -f -o /dev/null "${CONFORMANCE_SERVER}api/runner/available"; then
		echo "error: conformance suite not reachable at $CONFORMANCE_SERVER — start it first (see conformance/server/scripts/README.md step 1)" >&2
		exit 1
	fi
}

# wait_as_ready HOST_PORT — the AS containers take a couple seconds to
# start after `docker compose up`; run-test-plan.py has no reason to
# retry a connection-refused module 1 request, so wait here instead.
wait_as_ready() {
	local port="$1"
	for _ in $(seq 1 30); do
		if curl -sk --max-time 2 -o /dev/null "https://127.0.0.1:$port/"; then
			return 0
		fi
		sleep 1
	done
	echo "warning: conformance-as on port $port did not respond within 30s" >&2
}

# run_as_plan NAME PLAN_VARIANT CONFIG_JSON EXPECTED_WARNINGS EXPECTED_SKIPS
run_as_plan() {
	local name="$1" variant="$2" config="$3" warnings="$4" skips="$5"
	local log_file="$WORKDIR/as-$name.log"

	if [ ! -f "$config" ]; then
		log "AS $name: SKIPPED — $config not found (see conformance/server/oidf-config/README.md)"
		record_result "AS $name" "SKIPPED (no plan config)"
		return
	fi

	log "AS $name: starting run-test-plan.py"
	(
		cd "$CONFORMANCE_SUITE_CHECKOUT"
		./scripts/run-test-plan.py \
			--expected-failures-file "$warnings" \
			--expected-skips-file "$skips" \
			"$variant" \
			"$config"
	) >"$log_file" 2>&1 &
	local runner_pid=$!

	local plan_id=""
	for _ in $(seq 1 30); do
		# `|| true` matters here under `set -eo pipefail`: grep finding
		# nothing (true on every iteration until run-test-plan.py has
		# logged its plan id) makes the whole pipeline "fail" even
		# though head/awk succeed, and a bare failing assignment like
		# this one kills the script outright, silently, with no error
		# message — this exact bug was found live, not theorized.
		plan_id="$(grep -oE 'Created test plan, new id: [A-Za-z0-9]+' "$log_file" 2>/dev/null | head -1 | awk '{print $NF}')" || true
		if [ -n "$plan_id" ]; then
			break
		fi
		sleep 1
	done

	if [ -n "$plan_id" ]; then
		log "AS $name: plan $plan_id — starting unblock poller"
		CONFORMANCE_SERVER="$CONFORMANCE_SERVER" python3 "$POLLER" "$plan_id" >"$WORKDIR/as-$name-poller.log" 2>&1 &
		POLLER_PIDS+=("$!")
	else
		log "AS $name: WARNING — could not find plan id in log within 30s, poller not started"
	fi

	wait "$runner_pid" && exit_code=0 || exit_code=$?

	local totals
	totals="$(grep 'Overall totals' "$log_file" | tail -1)" || true
	if [ "$exit_code" -eq 0 ] && [ -n "$totals" ]; then
		record_result "AS $name" "OK — ${totals#*Overall totals: }"
	else
		OVERALL_CLEAN=false
		if [ -n "$totals" ]; then
			record_result "AS $name" "UNEXPECTED RESULTS — ${totals#*Overall totals: } (see $log_file)"
		else
			record_result "AS $name" "DID NOT COMPLETE (see $log_file)"
		fi
	fi
}

# run_rp_plan NAME PROFILE_FLAG
run_rp_plan() {
	local name="$1" profile="$2"
	local log_file="$WORKDIR/rp-$name.log"

	log "RP $name: starting cmd/conformance-client"
	(cd "$REPO_ROOT" && go run ./cmd/conformance-client -suite="$CONFORMANCE_SERVER" -profile="$profile") >"$log_file" 2>&1 || true

	local total passed
	total="$(awk '/=== summary ===/{f=1;next} f && NF{c++} END{print c+0}' "$log_file")"
	passed="$(awk '/=== summary ===/{f=1;next} f && $3=="PASSED"{c++} END{print c+0}' "$log_file")"

	if [ -n "$total" ] && [ "$total" != "0" ] && [ "$passed" = "$total" ]; then
		record_result "RP $name" "OK — $passed/$total PASSED"
	else
		OVERALL_CLEAN=false
		record_result "RP $name" "UNEXPECTED RESULTS — $passed/$total PASSED (see $log_file)"
	fi
}

check_suite_reachable

log "bringing up conformance-as containers"
# If cmd/conformance-as (or anything it imports) changed since the last
# build and results here look stale/wrong, rebuild manually first with
# `docker compose build --no-cache` — see this directory's README for
# why plain --build has been observed to reuse a stale cached `go
# build` layer even when the source changed. Not the default here
# since it'd make every routine run take minutes even when nothing
# changed.
(cd "$SERVER_DIR" && docker compose up -d --build conformance-as-baseline conformance-as-message-signing) >"$WORKDIR/docker-compose.log" 2>&1
wait_as_ready 18443
wait_as_ready 18444

run_as_plan "baseline" \
	'fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi][openid=openid_connect]' \
	"$SERVER_DIR/oidf-config/baseline-plan.json" \
	"$SERVER_DIR/expected-warnings-baseline.json" \
	"$SERVER_DIR/expected-skips-baseline.json"

run_as_plan "message-signing" \
	'fapi2-message-signing-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi][openid=openid_connect][fapi_request_method=signed_non_repudiation][fapi_response_mode=jarm]' \
	"$SERVER_DIR/oidf-config/message-signing-plan.json" \
	"$SERVER_DIR/expected-warnings-message-signing.json" \
	"$SERVER_DIR/expected-skips-message-signing.json"

run_rp_plan "baseline" "baseline"
run_rp_plan "message-signing" "message-signing"

echo
echo "=== combined summary ==="
for suite in "AS baseline" "AS message-signing" "RP baseline" "RP message-signing"; do
	result="$(lookup_result "$suite")"
	printf '%-20s %s\n' "$suite" "${result:-DID NOT RUN}"
done
echo
echo "full logs: $WORKDIR"

if [ "$OVERALL_CLEAN" = true ]; then
	echo
	echo "All four suites completed with no unexpected results."
	exit 0
else
	echo
	echo "One or more suites had unexpected results — see the log paths above."
	exit 1
fi
