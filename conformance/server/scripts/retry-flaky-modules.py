#!/usr/bin/env python3
"""Detects and automatically retries known, non-deterministic flakes in
AS-side conformance runs, so a transient suite-internal race doesn't
need a full run-all.sh re-run (or, worse, get mistaken for an AS
regression) every time it happens.

Two distinct flakes are known so far, both confirmed to originate in
the suite itself, never in cmd/conformance-as:

1. Stale implicit-submit browser JS. Confirmed via direct MongoDB
   forensics against this session's own run history (see git log for
   the investigation): a module gets abandoned (times out, or is
   interrupted for some unrelated reason) while its page is still
   loaded in the suite's own HtmlUnit browser driver. That driver
   isn't torn down instantly, so its JS keeps running in the
   background — and the page's residual implicit-submit xhr.send()
   eventually fires anyway, sometimes hundreds of milliseconds to
   seconds later. Since every module in a plan shares one alias/
   callback route, that stale POST lands on whichever module currently
   owns the alias, however unrelated: "Got an HTTP request ... that
   wasn't expected" interrupts it, and then that module's own
   legitimate (but now-late) implicit-submit arrives right behind it,
   hitting an already-interrupted module: "Illegal test state change".
   Neither event originates in unblock-implicit-callback.py (confirmed:
   it always re-checks an instance's live status before ever touching
   its log, so it structurally cannot submit on behalf of an instance
   that's already gone).

2. Stale HTTP response delivered for the wrong request. Confirmed live
   against a captured as-<name>-<id>-log.json (see run-all.sh's own
   dump-on-INTERRUPTED diagnostic): a module's HTTP client received a
   /token-shaped error body — {"error":"invalid_grant",
   "error_description":"code is invalid, expired, or already used"} —
   as the answer to a request that was never a /token call in the
   first place (e.g. a GET to the resource endpoint), immediately
   followed by that same request's genuine, correct response arriving
   right behind it. FAPIgo's own error vocabulary confirms this
   couldn't be a real FAPIgo response to that request:
   "invalid_grant" only exists in server/errors.go as a /token grant
   error, never emitted by the resource endpoint. A full FAPIgo code
   review (server/, resource/, storage/ — every package-level and
   struct-level mutable value, plus `go test -race`) found no shared
   response state that could explain one request's bytes landing on a
   different one; this is a connection-reuse/response-matching
   artifact in the suite's own HTTP client, only observed so far on a
   GitHub Actions runner, never locally.

Every occurrence of either flake across this session's history has
passed cleanly on a full re-run.

This script parses run-test-plan.py's own verbose stdout (the log file
run-all.sh already captures) for modules it flagged with "Unexpected
failure:" whose status was INTERRUPTED, confirms each one's own event
log carries the exact signature of one of the two flakes above
(deliberately narrow — this only ever retries a module whose failure
looks EXACTLY like a known, understood race, never a module that
failed for any other reason), and for each confirmed match, creates a
fresh instance of that same module (POST /api/runner, the same call
run-test-plan.py itself makes) inside the same plan.

Relies entirely on unblock-implicit-callback.py already being alive
against this plan_id — a newly created instance shows up in the
plan's own modules[].instances list automatically (confirmed live),
which is exactly what that poller already watches, so it picks up and
drives the retry's own browser interaction the same way it does every
other module. This script only creates the retry and polls its
outcome; it does no browser-interaction work of its own.

Usage:
    retry-flaky-modules.py <planId> <run-test-plan.py log file>

Prints one final line — "RETRY_VERDICT: all_resolved", "partial", or
"none" — plus a human-readable summary. run-all.sh greps that line to
decide whether to upgrade an "UNEXPECTED RESULTS" verdict to OK.
"all_resolved" only fires when EVERY module run-test-plan.py flagged
unexpected was both status=INTERRUPTED and matched the exact flake
signature, and every one of their retries passed — a genuine, unrelated
failure sitting alongside a flaky one always leaves the verdict
unresolved, on purpose.
"""
import http.client
import json
import os
import re
import ssl
import sys
import time
from urllib.parse import quote, urlsplit

CONFORMANCE_SERVER = os.environ.get("CONFORMANCE_SERVER", "https://localhost.emobix.co.uk:8443/")
_parsed = urlsplit(CONFORMANCE_SERVER)
HOST = _parsed.hostname
PORT = _parsed.port or 8443
CTX = ssl._create_unverified_context()

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# run-test-plan.py prefixes every line with its own "YYYY-MM-DD
# HH:MM:SS " timestamp (its own logging setup, not something run-all.sh
# adds) - the prefix is optional here only so a caller feeding in a
# pre-stripped line still matches.
TEST_LINE_RE = re.compile(r"^(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} )?Test \[(\d+):(\d+)\] (\S+) (\S+) (\S+) - result (\S+)\.")
# Same optional timestamp prefix as TEST_LINE_RE, same reason - this
# exact line was still being matched with a bare `== "Unexpected
# failure:"` string comparison, which never once matched real
# run-test-plan.py output (every line it prints carries the prefix,
# with no exception for this one) - confirmed live: this made
# find_unexpected_interrupted_modules() return zero candidates for
# every real INTERRUPTED module, silently, since this check was added.
UNEXPECTED_FAILURE_LINE_RE = re.compile(r"^(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} )?Unexpected failure:\s*$")

RETRY_POLL_TIMEOUT_SECONDS = 60
RETRY_POLL_INTERVAL_SECONDS = 1


class KeepAliveClient:
    """Same minimal keep-alive HTTPS client as unblock-implicit-callback.py
    — small enough, and specific enough to this poll-heavy use, that
    sharing it via an import felt like more coupling than it's worth
    between two independently-runnable scripts."""

    def __init__(self):
        self.conn = None

    def _ensure(self):
        if self.conn is None:
            self.conn = http.client.HTTPSConnection(HOST, PORT, context=CTX, timeout=10)

    def get_json(self, path):
        for attempt in range(2):
            try:
                self._ensure()
                self.conn.request("GET", path)
                resp = self.conn.getresponse()
                body = resp.read()
                if resp.status != 200:
                    raise RuntimeError(f"GET {path} -> {resp.status}")
                return json.loads(body)
            except Exception:
                self.conn = None
                if attempt == 1:
                    raise

    def post(self, path):
        for attempt in range(2):
            try:
                self._ensure()
                self.conn.request("POST", path)
                resp = self.conn.getresponse()
                body = resp.read()
                return resp.status, body
            except Exception:
                self.conn = None
                if attempt == 1:
                    raise


def strip_ansi(s):
    return ANSI_RE.sub("", s)


def find_unexpected_modules(log_path):
    """Parses run-test-plan.py's own verbose stdout for EVERY module
    whose printed "Test [...]" line is immediately followed by its own
    "Unexpected failure:" marker — i.e. every module run-test-plan.py
    itself considers responsible for its non-zero exit code, regardless
    of status. Deliberately does not filter to INTERRUPTED here (that
    used to happen in this function, and was a real bug - see git
    history): both known flakes are specifically INTERRUPTED-state
    races (see has_flake_signature / has_token_response_mismatch_
    signature's own doc comments), so a FINISHED module is never retry-
    eligible - but it still needs to come back from this function so
    main() can count it as a genuine, unresolved failure. Filtering it
    out here made a real AS-baseline failure (a FINISHED module,
    unrelated to an INTERRUPTED flake that happened to occur in the
    same run and got auto-retried) invisible to this script's own
    verdict entirely, which let RETRY_VERDICT: all_resolved fire even
    though a genuine failure was still sitting right there - confirmed
    live against a real run."""
    modules = []
    last = None
    with open(log_path) as f:
        for raw in f:
            line = strip_ansi(raw).rstrip("\n")
            m = TEST_LINE_RE.match(line)
            if m:
                _plan_n, _mod_n, test_name, module_id, status, _result = m.groups()
                # The printed name carries the variant inline, e.g.
                # "...-happy-flow[fapi_request_method=unsigned][...]" -
                # strip it back to the bare test module name (this is
                # display-only here; find_module_variant() below looks
                # module_id up in the plan directly, so this doesn't
                # affect which module actually gets retried).
                test_name = test_name.split("[", 1)[0]
                last = (module_id, test_name, status)
                continue
            if UNEXPECTED_FAILURE_LINE_RE.match(line) and last is not None:
                modules.append(last)
                last = None
    return modules


def has_flake_signature(log):
    """log is the module's own /api/log/{id} entries. The exact,
    deliberately narrow fingerprint: an unexpected-HTTP-request
    interruption followed later by an illegal-state-change failure —
    see this file's own doc comment for why each half is what it is."""
    saw_unexpected_request = any(
        "that wasn't expected" in e.get("msg", "") for e in log
    )
    saw_illegal_state_change = any(
        e.get("msg", "").startswith("Illegal test state change") for e in log
    )
    return saw_unexpected_request and saw_illegal_state_change


def has_token_response_mismatch_signature(log):
    """log is the module's own /api/log/{id} entries. Fingerprint for
    the second known flake (see this file's own doc comment): an "HTTP
    response" entry whose body is a /token grant error
    (error=invalid_grant) delivered as the answer to the immediately
    preceding "HTTP request" entry when that request wasn't a /token
    call at all. FAPIgo never emits invalid_grant from any endpoint
    but /token (grep server/errors.go), so this pairing is only
    possible if the suite's own HTTP client matched a stale response to
    the wrong request — never a real FAPIgo response to the request it
    was actually paired with."""
    pending_request_uri = None
    for entry in log:
        msg = entry.get("msg")
        if msg == "HTTP request":
            pending_request_uri = entry.get("request_uri", "")
            continue
        if msg == "HTTP response" and pending_request_uri is not None:
            try:
                body = json.loads(entry.get("response_body") or "")
            except (TypeError, ValueError):
                body = {}
            if not pending_request_uri.rstrip("/").endswith("/token") and body.get("error") == "invalid_grant":
                return True
            pending_request_uri = None
    return False


def find_module_variant(plan, module_id):
    for module in plan.get("modules", []):
        for inst in module.get("instances", []):
            inst_id = inst[0] if isinstance(inst, list) else inst
            if inst_id == module_id:
                return module.get("testModule"), module.get("variant", {})
    return None, None


def main():
    if len(sys.argv) != 3:
        print("usage: retry-flaky-modules.py <planId> <run-test-plan.py log file>", file=sys.stderr)
        sys.exit(2)
    plan_id, log_path = sys.argv[1], sys.argv[2]

    modules = find_unexpected_modules(log_path)
    if not modules:
        print("retry-flaky-modules: no modules with an unexpected-failure marker found", flush=True)
        print("RETRY_VERDICT: none", flush=True)
        return

    candidates = [(mid, name) for mid, name, status in modules if status == "INTERRUPTED"]
    # Never retry-eligible (see find_unexpected_modules' own doc
    # comment on why this function stopped filtering these out) — each
    # one goes straight into non_matching so the final verdict can
    # never claim all_resolved while one of these is still unaccounted
    # for.
    non_matching = []
    for module_id, test_name, status in modules:
        if status != "INTERRUPTED":
            print(f"retry-flaky-modules: {test_name} {module_id} is {status} (not INTERRUPTED) — never retry-eligible, leaving as a real failure", flush=True)
            non_matching.append((module_id, test_name))

    if not candidates:
        print(f"retry-flaky-modules: 0 resolved, 0 still unresolved, {len(non_matching)} not a flake match", flush=True)
        print("RETRY_VERDICT: partial" if non_matching else "RETRY_VERDICT: none", flush=True)
        return

    client = KeepAliveClient()
    try:
        plan = client.get_json(f"/api/plan/{plan_id}")
    except Exception as e:
        print(f"retry-flaky-modules: failed to fetch plan {plan_id}: {e}", flush=True)
        non_matching.extend(candidates)
        print(f"retry-flaky-modules: 0 resolved, 0 still unresolved, {len(non_matching)} not a flake match", flush=True)
        print("RETRY_VERDICT: partial", flush=True)
        return

    retries = []  # (old_module_id, test_name, new_instance_id)
    for module_id, test_name in candidates:
        try:
            log = client.get_json(f"/api/log/{module_id}")
        except Exception as e:
            print(f"retry-flaky-modules: {test_name} {module_id}: could not fetch log: {e}", flush=True)
            non_matching.append((module_id, test_name))
            continue

        matched_flake = has_flake_signature(log) or has_token_response_mismatch_signature(log)
        if not matched_flake:
            print(f"retry-flaky-modules: {test_name} {module_id} is INTERRUPTED but doesn't match a known flake signature — leaving as a real failure", flush=True)
            non_matching.append((module_id, test_name))
            continue

        test_module, variant = find_module_variant(plan, module_id)
        if test_module is None:
            print(f"retry-flaky-modules: {test_name} {module_id}: couldn't find its module entry in plan {plan_id}", flush=True)
            non_matching.append((module_id, test_name))
            continue

        variant_qs = quote(json.dumps(variant))
        try:
            status, body = client.post(f"/api/runner?test={quote(test_module)}&plan={plan_id}&variant={variant_qs}")
            if status != 201:
                raise RuntimeError(f"POST /api/runner -> {status}: {body!r}")
            new_id = json.loads(body)["id"]
        except Exception as e:
            print(f"retry-flaky-modules: {test_name} {module_id}: failed to create retry: {e}", flush=True)
            non_matching.append((module_id, test_name))
            continue

        print(f"retry-flaky-modules: {test_name} {module_id} matches a known flake signature — retrying as {new_id}", flush=True)
        retries.append((module_id, test_name, new_id))

    resolved = []
    unresolved = []
    for old_id, test_name, new_id in retries:
        deadline = time.monotonic() + RETRY_POLL_TIMEOUT_SECONDS
        result = None
        while time.monotonic() < deadline:
            try:
                info = client.get_json(f"/api/info/{new_id}")
            except Exception:
                time.sleep(RETRY_POLL_INTERVAL_SECONDS)
                continue
            if info.get("status") in ("FINISHED", "INTERRUPTED"):
                result = info.get("result")
                break
            time.sleep(RETRY_POLL_INTERVAL_SECONDS)

        if result == "PASSED":
            print(f"retry-flaky-modules: {test_name} retry {new_id} -> PASSED", flush=True)
            resolved.append((old_id, test_name, new_id))
        else:
            print(f"retry-flaky-modules: {test_name} retry {new_id} -> {result or 'TIMED OUT waiting for it to finish'}", flush=True)
            unresolved.append((old_id, test_name, new_id))

    print(flush=True)
    print(f"retry-flaky-modules: {len(resolved)} resolved, {len(unresolved)} still unresolved, {len(non_matching)} not a flake match", flush=True)

    if non_matching or unresolved:
        print("RETRY_VERDICT: partial", flush=True)
    else:
        print("RETRY_VERDICT: all_resolved", flush=True)


if __name__ == "__main__":
    main()
