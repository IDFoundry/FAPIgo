#!/usr/bin/env bash
# Runs all eleven FAPI2 conformance suites this repo has driver support
# for — AS baseline, AS message-signing, AS ciba-mtls, AS ciba-ping, AS
# mtls, AS message-signing-mtls, AS client-auth-mtls, RP baseline, RP
# message-signing, RP ciba-mtls, RP client-auth-mtls — against a
# locally running OIDF conformance suite,
# prints one combined summary at the end, and (via generate-report.py)
# writes a fuller report.md alongside the raw per-suite logs — every
# non-PASSED module, with the "why this is expected, not a defect"
# reasoning pulled straight from expected-{warnings,skips}-*.json where
# one exists.
#
# AS/RP client-auth-mtls cover RFC 8705 §2 client authentication
# (client_auth_type=mtls) — orthogonal to AS/RP ciba-mtls's §3
# sender-constraining coverage below: both keep sender_constrain=dpop,
# so AS client-auth-mtls is the first plan to exercise a DPoP proof
# presented at an mTLS-alias URL at all (see ARCHITECTURE.md's
# conformance strategy section for the real server/token.go and
# server/par.go gap this surfaced and fixed). RP client-auth-mtls is
# cmd/conformance-client -profile=baseline -client-auth-mtls, not a
# separate container.
#
# AS ciba-mtls and RP ciba-mtls both need RFC 8705 mTLS sender-
# constraining (see ARCHITECTURE.md's Conformance strategy section for
# why FAPI-CIBA-ID1 requires it unconditionally on both sides) —
# AS ciba-mtls runs against a third conformance-as container
# (conformance-as-ciba-mtls, ../server/docker-compose.yml) on its own
# ports; RP ciba-mtls is cmd/conformance-client -profile=ciba -mtls,
# not a separate container at all.
#
# AS ciba-ping covers CIBA §10.2 ping delivery mode — the exact same
# conformance-as-ciba-mtls container and config file as AS ciba-mtls
# above (two extra clients registered
# storage.BackchannelTokenDeliveryModePing, see
# ../server/scripts/setup-config/main.go's setupCIBAPing), just a
# different suite plan alias/variant against it. No RP-side counterpart:
# cmd/conformance-client only ever plays a poll-mode CIBA client (see
# ../client/scripts/README.md).
#
# AS mtls/AS message-signing-mtls close the remaining §3 sender
# -constraining gap: unlike AS ciba-mtls (no PAR/authorize hop at all)
# and AS client-auth-mtls (mTLS is client *authentication* there, not
# token binding — sender_constrain stays dpop), these run the ordinary
# fapi2-security-profile-final/fapi2-message-signing-final plans with
# sender_constrain=mtls, so a plain client authenticating with
# private_key_jwt as usual receives and uses mTLS-bound access tokens
# through the real PAR/authorize/callback/token flow — the same
# server/token.go binding logic AS ciba-mtls exercises, but never
# through this code path before. Two more conformance-as containers
# (conformance-as-mtls, conformance-as-message-signing-mtls,
# ../server/docker-compose.yml), generated via
# ../server/scripts/setup-config/main.go's senderConstrainMTLS profile
# flag. No RP-side counterpart yet:
# cmd/conformance-client's own -mtls flag is currently hardcoded to
# -profile=ciba only (see its own flag help text) — extending it to
# -profile=baseline is a natural, separate follow-up.
#
# Runs cmd/conformance-as under its default -access-token-format=jwt
# only. An earlier version of this script looped the AS suites over
# both jwt and opaque (see conformance/server/docker-compose.yml's
# ACCESS_TOKEN_FORMAT, still there for a manual one-off run) — that was
# dropped once resource.AccessTokenResolver's contract was tightened so
# DPoP binding/expiry/revocation are enforced once, uniformly, in
# Verify() itself rather than by each implementation: the two
# access-token formats can no longer disagree on those checks by
# construction, so a full live-suite duplicate run stopped pulling its
# weight against the doubled runtime. OpaqueAccessTokens' own
# format-specific behavior (issuance, storage lookup) is still covered
# by unit/integration tests (server/token_test.go,
# resource/verify_test.go) and cmd/conformance-as's own smoke test
# under both formats — see ARCHITECTURE.md's conformance strategy
# section.
#
# Always runs every suite, even if an earlier one comes back unclean —
# never stops early — so a bad result in one suite never hides results
# from the others.
#
# Prerequisites (see conformance/server/scripts/README.md and
# conformance/client/scripts/README.md for the one-time setup each of
# these implies):
#   - The OIDF conformance suite itself running locally
#     (https://localhost.emobix.co.uk:8443 by default).
#   - CONFORMANCE_SUITE_CHECKOUT set to that suite's own git checkout
#     (this script runs its scripts/run-test-plan.py from there).
#   - conformance/server/oidf-config/{baseline,message-signing,ciba-mtls,client-auth-mtls}-plan.json
#     already filled in (gitignored — carries private keys; run
#     `go run ./conformance/server/scripts/setup-config` to generate
#     all four, or see that directory's README to do it by hand).
#   - Docker, for the conformance-as-baseline/-message-signing/-ciba-mtls/-client-auth-mtls
#     containers (brought up automatically by this script).
#
# Usage:
#   export CONFORMANCE_SUITE_CHECKOUT=/path/to/conformance-suite
#   export SUITE_NETWORK=<network from `docker network ls`>   # only if not the default
#   ./conformance/scripts/run-all.sh
#
# A clean "UNEXPECTED RESULTS" on an AS suite doesn't necessarily mean
# an AS regression — check the module names in the linked log first,
# and check for a "(N module auto-retried — known suite-browser flake"
# note next to that suite's result. One category of failure is already
# known, understood, and auto-retried rather than added to
# expected-warnings-*.json: an abandoned module's page can be left
# loaded in the suite's own HtmlUnit browser driver, whose JS keeps
# running in the background and eventually fires a stale implicit-
# submit callback that lands on whichever module currently owns the
# shared alias — see retry-flaky-modules.py's own doc comment for the
# full forensic detail (confirmed via direct MongoDB analysis, not
# guessed) on why this is entirely a suite-internal race, never traced
# to a real protocol violation by cmd/conformance-as. Every occurrence
# gets exactly one automatic, narrowly-targeted retry (see run_as_plan
# below); a genuine, unrelated failure sitting alongside a flaky one
# always leaves the run reported as UNEXPECTED RESULTS on purpose.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SERVER_DIR="$REPO_ROOT/conformance/server"
POLLER="$SERVER_DIR/scripts/unblock-implicit-callback.py"
RETRY_FLAKY="$SERVER_DIR/scripts/retry-flaky-modules.py"
CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://localhost.emobix.co.uk:8443/}"

: "${CONFORMANCE_SUITE_CHECKOUT:?Set CONFORMANCE_SUITE_CHECKOUT to your local OIDF conformance-suite checkout — see conformance/server/scripts/README.md step 1}"
if [[ ! -f "$CONFORMANCE_SUITE_CHECKOUT/scripts/run-test-plan.py" ]]; then
	echo "error: $CONFORMANCE_SUITE_CHECKOUT/scripts/run-test-plan.py not found — is CONFORMANCE_SUITE_CHECKOUT correct?" >&2
	exit 1
fi

WORKDIR="${WORKDIR:-$(mktemp -d)}"
mkdir -p "$WORKDIR"
declare -a POLLER_PIDS=()
RESULTS_FILE="$WORKDIR/results.txt"
touch "$RESULTS_FILE"
OVERALL_CLEAN=true

# record_result NAME LINE — appends "NAME|LINE" to $RESULTS_FILE. Not an
# associative array (declare -A needs bash 4+; the stock /bin/bash on
# macOS is 3.2), so results are looked up by grepping this file instead.
record_result() {
	local name="$1" line="$2"
	printf '%s|%s\n' "$name" "$line" >>"$RESULTS_FILE"
}

lookup_result() {
	local name="$1"
	grep -F "$name|" "$RESULTS_FILE" 2>/dev/null | tail -1 | cut -d'|' -f2- || true
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

# check_suite_reachable — polls rather than checking once: a suite
# that was *just* started (`docker compose up -d` returns long before
# Mongo + the Spring Boot app are actually healthy — 30-90s startup is
# normal) shouldn't be treated the same as one that was never started
# at all. ~2 minutes of budget, matching wait_as_ready's own pattern
# below. This matters for CI (where the suite is brought up
# immediately before this script runs) as much as it helps locally
# (no more guessing how long to wait after starting the suite by
# hand).
check_suite_reachable() {
	for _ in $(seq 1 120); do
		if curl -sk --max-time 5 -f -o /dev/null "${CONFORMANCE_SERVER}api/runner/available"; then
			return 0
		fi
		sleep 1
	done
	echo "error: conformance suite not reachable at $CONFORMANCE_SERVER after 2 minutes — start it first (see conformance/server/scripts/README.md step 1)" >&2
	exit 1
}

# wait_as_ready HOST_PORT — the AS containers take a couple seconds to
# start locally after `docker compose up`, but `--build` above can add
# a cold Go module/image build on top of that (observed on a fresh
# GitHub Actions runner: no cached layers, so the build alone eats
# past a 30s budget before the container has even started) —
# run-test-plan.py has no reason to retry a connection-refused module
# 1 request, so wait here instead, with the same ~2 minute budget as
# check_suite_reachable. A container that's genuinely never coming up
# is a hard failure, not a warning: proceeding anyway just produces
# three straight INTERRUPTED modules and an aborted run downstream,
# which is a much more confusing failure to debug than this exiting
# with a clear message.
wait_as_ready() {
	local port="$1"
	for _ in $(seq 1 120); do
		if curl -sk --max-time 2 -o /dev/null "https://127.0.0.1:$port/"; then
			return 0
		fi
		sleep 1
	done
	echo "error: conformance-as on port $port did not respond within 2 minutes" >&2
	# Dump container state/logs here rather than leaving this a bare
	# timeout: distinguishing "still building/starting" from "crashed
	# on startup" from "up but unreachable" needs exactly this, and by
	# the time anyone's looking at a failed CI run the containers are
	# long gone (torn down by the workflow's own cleanup step).
	(cd "$SERVER_DIR" && docker compose ps) >&2 || true
	(cd "$SERVER_DIR" && docker compose logs --tail=100 conformance-as-baseline conformance-as-message-signing conformance-as-ciba-mtls conformance-as-mtls conformance-as-message-signing-mtls conformance-as-client-auth-mtls) >&2 || true
	exit 1
}

# run_as_plan NAME PLAN_VARIANT CONFIG_JSON EXPECTED_WARNINGS EXPECTED_SKIPS
run_as_plan() {
	local name="$1" variant="$2" config="$3" warnings="$4" skips="$5"
	local log_file="$WORKDIR/as-$name.log"

	if [[ ! -f "$config" ]]; then
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
	for _ in $(seq 1 300); do
		# `|| true` matters here under `set -eo pipefail`: grep finding
		# nothing (true on every iteration until run-test-plan.py has
		# logged its plan id) makes the whole pipeline "fail" even
		# though head/awk succeed, and a bare failing assignment like
		# this one kills the script outright, silently, with no error
		# message — this exact bug was found live, not theorized.
		plan_id="$(grep -oE 'Created test plan, new id: [A-Za-z0-9]+' "$log_file" 2>/dev/null | head -1 | awk '{print $NF}')" || true
		if [[ -n "$plan_id" ]]; then
			break
		fi
		sleep 0.1
	done

	if [[ -n "$plan_id" ]]; then
		log "AS $name: plan $plan_id — starting unblock poller"
		CONFORMANCE_SERVER="$CONFORMANCE_SERVER" python3 "$POLLER" "$plan_id" >"$WORKDIR/as-$name-poller.log" 2>&1 &
		POLLER_PIDS+=("$!")
	else
		log "AS $name: WARNING — could not find plan id in log within 30s, poller not started"
	fi

	wait "$runner_pid" && exit_code=0 || exit_code=$?

	# On a non-clean run, dump every INTERRUPTED module's full condition
	# log from the suite's own API — run-test-plan.py's own log only
	# ever records a bare "moved to INTERRUPTED" (see the traceback a
	# few lines above this loop's own output), never which specific
	# condition actually failed, and the suite container is gone by the
	# time anyone looks at a failed CI run (torn down by the workflow's
	# own cleanup step). Best-effort: the suite is still up at this
	# point in the script (this plan's own containers aren't touched
	# until every plan has run), so this is the only place that can
	# still reach it.
	if [[ "$exit_code" -ne 0 ]]; then
		local module_id
		for module_id in $(grep -oE 'Created test module, new id: [A-Za-z0-9]+' "$log_file" | awk '{print $NF}'); do
			if grep -q "module id $module_id status changed to INTERRUPTED" "$log_file"; then
				curl -sk --max-time 10 "${CONFORMANCE_SERVER}api/log/$module_id" -o "$WORKDIR/as-$name-$module_id-log.json" || true
			fi
		done
	fi

	local totals retry_note=""
	totals="$(grep 'Overall totals' "$log_file" | tail -1)" || true

	# On a non-clean run, check whether every module run-test-plan.py
	# flagged is exactly the known suite-internal browser-JS flake (see
	# retry-flaky-modules.py's own doc comment) before ever touching the
	# reported verdict — a genuine, unrelated failure sitting alongside
	# a flaky one always leaves it alone. The poller started above is
	# still running at this point (it isn't killed until this whole
	# script exits, not per-suite), which is what lets a freshly
	# created retry instance get its own browser interaction driven
	# automatically, the same as every other module in the plan.
	if [[ "$exit_code" -ne 0 && -n "$plan_id" ]]; then
		local retry_log="$WORKDIR/as-$name-retry.log"
		python3 "$RETRY_FLAKY" "$plan_id" "$log_file" >"$retry_log" 2>&1 || true
		if grep -q 'RETRY_VERDICT: all_resolved' "$retry_log"; then
			exit_code=0
			local retried_count
			retried_count="$(grep -oE '[0-9]+ resolved' "$retry_log" | tail -1 | awk '{print $1}')" || true
			retry_note=" (${retried_count:-1} module auto-retried — known suite-browser flake, see $retry_log)"
		else
			retry_note=" (auto-retry did not fully resolve this — see $retry_log)"
		fi
	fi

	if [[ "$exit_code" -eq 0 && -n "$totals" ]]; then
		record_result "AS $name" "OK — ${totals#*Overall totals: }${retry_note}"
	else
		OVERALL_CLEAN=false
		if [[ -n "$totals" ]]; then
			record_result "AS $name" "UNEXPECTED RESULTS — ${totals#*Overall totals: }${retry_note} (see $log_file)"
		else
			record_result "AS $name" "DID NOT COMPLETE (see $log_file)"
		fi
	fi
}

# run_rp_plan NAME PROFILE_FLAG [EXTRA_ARGS...] — EXTRA_ARGS is for
# -mtls (RP ciba-mtls) or -client-auth-mtls (RP client-auth-mtls); the
# two baseline/message-signing callers pass none.
run_rp_plan() {
	local name="$1" profile="$2"
	shift 2
	local log_file="$WORKDIR/rp-$name.log"

	log "RP $name: starting cmd/conformance-client"
	(cd "$REPO_ROOT" && go run ./cmd/conformance-client -suite="$CONFORMANCE_SERVER" -profile="$profile" "$@") >"$log_file" 2>&1 || true

	local total passed
	total="$(awk '/=== summary ===/{f=1;next} f && NF{c++} END{print c+0}' "$log_file")"
	passed="$(awk '/=== summary ===/{f=1;next} f && $3=="PASSED"{c++} END{print c+0}' "$log_file")"

	if [[ -n "$total" && "$total" != "0" && "$passed" = "$total" ]]; then
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
(cd "$SERVER_DIR" && docker compose up -d --build conformance-as-baseline conformance-as-message-signing conformance-as-ciba-mtls conformance-as-mtls conformance-as-message-signing-mtls conformance-as-client-auth-mtls) >"$WORKDIR/docker-compose.log" 2>&1
wait_as_ready 18443
wait_as_ready 18444
wait_as_ready 18446
wait_as_ready 18447
wait_as_ready 18450
wait_as_ready 18451
wait_as_ready 18452
wait_as_ready 18453
wait_as_ready 18448
wait_as_ready 18449

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

# CIBA needs its own AS: cmd/conformance-as -ciba -mtls, a second
# process/container from conformance-as-baseline/-message-signing (see
# ../server/docker-compose.yml's own conformance-as-ciba-mtls service),
# since fapi-ciba-id1-test-plan requires MTLS-bound access tokens
# unconditionally (see ARCHITECTURE.md's Conformance strategy section
# for why) — the baseline/message-signing containers run DPoP-only.
run_as_plan "ciba-mtls" \
	'fapi-ciba-id1-test-plan[client_auth_type=private_key_jwt][ciba_mode=poll][fapi_ciba_profile=plain_fapi][client_registration=static_client]' \
	"$SERVER_DIR/oidf-config/ciba-mtls-plan.json" \
	"$SERVER_DIR/expected-warnings-ciba-mtls.json" \
	"$SERVER_DIR/expected-skips-ciba-mtls.json"

# AS ciba-ping: same conformance-as-ciba-mtls container as the ciba-mtls
# leg above (see ../server/scripts/setup-config/main.go's setupCIBAPing
# and ../server/oidf-config/README.md) — two extra clients registered
# storage.BackchannelTokenDeliveryModePing on that same running AS, under
# their own suite plan alias ("gofapi-ciba-ping") so this plan's
# notification endpoint doesn't collide with the poll-mode plan's own.
# ciba_mode=ping is the only variant difference from the ciba-mtls leg
# above; no separate docker-compose service or `docker compose up`/
# wait_as_ready entry is needed since it's the exact same container.
run_as_plan "ciba-ping" \
	'fapi-ciba-id1-test-plan[client_auth_type=private_key_jwt][ciba_mode=ping][fapi_ciba_profile=plain_fapi][client_registration=static_client]' \
	"$SERVER_DIR/oidf-config/ciba-ping-plan.json" \
	"$SERVER_DIR/expected-warnings-ciba-ping.json" \
	"$SERVER_DIR/expected-skips-ciba-ping.json"

# AS mtls: sender_constrain=mtls under the ordinary PAR/authorize/token
# flow (see this file's own header comment for why this is a real,
# previously-untested combination) — its own conformance-as-mtls
# container.
run_as_plan "mtls" \
	'fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=mtls][fapi_profile=plain_fapi][openid=openid_connect]' \
	"$SERVER_DIR/oidf-config/mtls-plan.json" \
	"$SERVER_DIR/expected-warnings-mtls.json" \
	"$SERVER_DIR/expected-skips-mtls.json"

# AS message-signing-mtls: AS mtls's own message-signing counterpart —
# confirms sender_constrain=mtls composes correctly with signed request
# objects/JARM too.
run_as_plan "message-signing-mtls" \
	'fapi2-message-signing-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=mtls][fapi_profile=plain_fapi][openid=openid_connect][fapi_request_method=signed_non_repudiation][fapi_response_mode=jarm]' \
	"$SERVER_DIR/oidf-config/message-signing-mtls-plan.json" \
	"$SERVER_DIR/expected-warnings-message-signing-mtls.json" \
	"$SERVER_DIR/expected-skips-message-signing-mtls.json"

# AS client-auth-mtls needs its own AS too (conformance-as-client-auth-mtls,
# ../server/docker-compose.yml) — same -mtls second listener
# infrastructure ciba-mtls uses, but sender_constrain stays "dpop" here:
# this plan is RFC 8705 §2 client authentication, not §3 sender-
# constraining, and the two are orthogonal (see ARCHITECTURE.md).
run_as_plan "client-auth-mtls" \
	'fapi2-security-profile-final-test-plan[client_auth_type=mtls][sender_constrain=dpop][fapi_profile=plain_fapi][openid=openid_connect]' \
	"$SERVER_DIR/oidf-config/client-auth-mtls-plan.json" \
	"$SERVER_DIR/expected-warnings-client-auth-mtls.json" \
	"$SERVER_DIR/expected-skips-client-auth-mtls.json"

run_rp_plan "baseline" "baseline"
run_rp_plan "message-signing" "message-signing"

# RP ciba-mtls: cmd/conformance-client -profile=ciba -mtls against the
# suite's own fapi-ciba-id1-client-test-plan — see
# ../client/scripts/README.md's own CIBA section for why -mtls (not
# DPoP) is what this driver runs here: the suite's own
# AbstractFAPICIBAClientTest.handleHttp hardcodes the token endpoint to
# require mTLS unconditionally, regardless of client_auth_type variant.
run_rp_plan "ciba-mtls" "ciba" -mtls

# RP client-auth-mtls: cmd/conformance-client -profile=baseline
# -client-auth-mtls, the RFC 8705 §2 counterpart to AS client-auth-mtls
# above — sender-constraining stays DPoP; only how this driver
# authenticates itself (client_id + certificate, no client_assertion)
# changes. See ../client/scripts/README.md's own client-authentication
# mTLS section.
run_rp_plan "client-auth-mtls" "baseline" -client-auth-mtls

python3 "$SCRIPT_DIR/generate-report.py" "$WORKDIR" "$REPO_ROOT" || echo "warning: report generation failed (see above)" >&2

echo
echo "=== combined summary ==="
for suite in "AS baseline" "AS message-signing" "AS ciba-mtls" "AS ciba-ping" "AS mtls" "AS message-signing-mtls" "AS client-auth-mtls" "RP baseline" "RP message-signing" "RP ciba-mtls" "RP client-auth-mtls"; do
	result="$(lookup_result "$suite")"
	printf '%-20s %s\n' "$suite" "${result:-DID NOT RUN}"
done
echo
echo "full logs: $WORKDIR"
echo "report: $WORKDIR/report.md"

if [[ "$OVERALL_CLEAN" = true ]]; then
	echo
	echo "All eleven suites completed with no unexpected results."
	exit 0
else
	echo
	echo "One or more suites had unexpected results — see the log paths above."
	exit 1
fi
