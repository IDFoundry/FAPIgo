#!/usr/bin/env python3
"""Creates and runs the OIDF conformance suite's own
"openid-federation-deployed-entity-test-plan" against a running
conformance-as-federation / conformance-federation-trust-anchor pair,
and reports a pass/fail verdict — the federation counterpart to the
suite's own scripts/run-test-plan.py that run-all.sh's run_as_plan uses
for every other leg.

Not built on run-test-plan.py itself: that script's whole design (a
config file carrying OAuth client secrets/keys, a browser-driven
consent flow, the JS-stall poller and flaky-module retry run-all.sh
also drives for every other leg) doesn't apply here at all. Every
module in this plan is a pure server-to-server check — fetch an Entity
Statement, verify its signature, walk a Trust Chain — with no user
interaction and no plan-config file of its own; it runs to completion
within a couple of seconds of being created. So this script talks to
the suite's REST API directly instead: POST /api/plan, POST /api/runner
per module, poll GET /api/info until FINISHED, and read GET /api/log
for anything that wasn't a plain SUCCESS.

Usage:
    run-federation-plan.py \
        --entity-identifier https://conformance-as-federation:8443 \
        --trust-anchor https://conformance-federation-trust-anchor:8443 \
        --trust-anchor-jwks '{"keys":[...]}' \
        --expected-warnings expected-warnings-federation.json \
        --expected-skips expected-skips-federation.json

Prints one line per module plus a final "Overall totals: X/Y passed"
line — run-all.sh's own run_federation_plan greps that line the exact
same way run_as_plan already does for run-test-plan.py's own output.
Exits 0 only if every module finished with zero unexpected
failures/warnings (an expected one, matched against the given
--expected-warnings file, doesn't count against this); exits 1
otherwise.
"""
import argparse
import fnmatch
import http.client
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

from _sslutil import local_only_ssl_context

CONFORMANCE_SERVER = os.environ.get("CONFORMANCE_SERVER", "https://localhost.emobix.co.uk:8443/")
_parsed = urlsplit(CONFORMANCE_SERVER)
HOST = _parsed.hostname
PORT = _parsed.port or 8443
CTX = local_only_ssl_context(HOST)

MODULE_POLL_TIMEOUT_SECONDS = 60
MODULE_POLL_INTERVAL_SECONDS = 0.5


class KeepAliveClient:
    """Same minimal keep-alive HTTPS client as retry-flaky-modules.py /
    unblock-implicit-callback.py — see either's own doc comment for why
    this isn't shared via an import between these independently-runnable
    scripts."""

    def __init__(self):
        self.conn = None

    def _ensure(self):
        if self.conn is None:
            self.conn = http.client.HTTPSConnection(HOST, PORT, context=CTX, timeout=15)

    def get_json(self, path):
        for attempt in range(2):
            try:
                self._ensure()
                self.conn.request("GET", path)
                resp = self.conn.getresponse()
                body = resp.read()
                if resp.status != 200:
                    raise RuntimeError(f"GET {path} -> {resp.status}: {body[:500]!r}")
                return json.loads(body)
            except Exception:
                self.conn = None
                if attempt == 1:
                    raise

    def post_json(self, path, payload=None):
        """POSTs `path`. `payload=None` sends no body at all — required
        for /api/runner?test=...&plan=...: the suite's own client
        (Connect.create_test_from_plan_with_variant in the suite's own
        scripts/conformance.py) sends that call with query params only,
        no `data=`, and a `{}` JSON body there gets rejected outright
        (confirmed live: HTTP 400 with an empty response body — found
        only by actually running this script against a live suite, not
        by inspecting the suite's REST API docs, which don't document
        this). /api/plan does need its config as a real JSON body, so
        that call still passes an explicit payload."""
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {} if payload is None else {"Content-Type": "application/json"}
        for attempt in range(2):
            try:
                self._ensure()
                self.conn.request("POST", path, body=body, headers=headers)
                resp = self.conn.getresponse()
                resp_body = resp.read()
                if resp.status not in (200, 201):
                    raise RuntimeError(f"POST {path} -> {resp.status}: {resp_body[:500]!r}")
                return json.loads(resp_body)
            except Exception:
                self.conn = None
                if attempt == 1:
                    raise


def load_expected(path):
    """Loads an expected-warnings/expected-skips JSON file — a list of
    {"test-name": <fnmatch pattern, matched against the module's own
    testModule name>, "condition": <the log entry's own "src">,
    "expected-result": "warning"|"failure"} objects. A deliberately
    smaller schema than the suite's own run-test-plan.py uses (no
    configuration-filename/variant matching: this plan has exactly one
    fixed configuration, so those fields would never vary) — see this
    script's own doc comment for why run-test-plan.py's machinery isn't
    reused here at all. Resolved before opening — mirrors
    generate-report.py's own handling of its CLI-supplied path
    arguments, since `path` here likewise comes straight from argparse
    (--expected-warnings/--expected-skips, both fixed paths under
    conformance/server/ in every real invocation, but this is
    general-purpose CLI-argument-handling hygiene, not a defense against
    a real external actor)."""
    resolved = Path(path).resolve()
    if not resolved.exists():
        return []
    with open(resolved) as f:
        return json.load(f)


def is_expected(entry_list, test_module, src, result):
    expected_result = "warning" if result == "WARNING" else "failure"
    for obj in entry_list:
        if not fnmatch.fnmatch(test_module, obj["test-name"]):
            continue
        if obj["condition"] != src:
            continue
        if obj["expected-result"] != expected_result:
            continue
        return True
    return False


def create_plan(client, entity_identifier, trust_anchor, trust_anchor_jwks):
    variant = json.dumps({"server_metadata": "discovery", "client_registration": "automatic"})
    config = {
        "federation": {
            "entity_identifier": entity_identifier,
            "de_trust_anchor": trust_anchor,
            "de_trust_anchor_jwks": trust_anchor_jwks,
        }
    }
    path = f"/api/plan?planName=openid-federation-deployed-entity-test-plan&variant={quote(variant)}"
    return client.post_json(path, config)


def run_module(client, plan_id, test_module):
    result = client.post_json(f"/api/runner?test={quote(test_module)}&plan={plan_id}")
    return result["id"]


def wait_for_finished(client, module_id):
    deadline = time.monotonic() + MODULE_POLL_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        info = client.get_json(f"/api/info/{module_id}")
        if info.get("status") == "FINISHED":
            return info
        time.sleep(MODULE_POLL_INTERVAL_SECONDS)
    raise RuntimeError(f"module {module_id} did not reach FINISHED within {MODULE_POLL_TIMEOUT_SECONDS}s")


def evaluate_module(client, test_module, module_id, expected_warnings):
    """Returns (clean: bool, summary: str)."""
    log = client.get_json(f"/api/log/{module_id}")
    unexpected = []
    expected_seen = []
    for entry in log:
        result = entry.get("result")
        if result not in ("FAILURE", "WARNING"):
            continue
        src = entry.get("src", "")
        if is_expected(expected_warnings, test_module, src, result):
            expected_seen.append((result, src))
        else:
            unexpected.append((result, src))

    if not unexpected:
        note = f" ({len(expected_seen)} expected: {', '.join(r for r, _ in expected_seen)})" if expected_seen else ""
        return True, f"OK{note}"

    details = "; ".join(f"{r}: {s}" for r, s in unexpected)
    return False, f"UNEXPECTED: {details}"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--entity-identifier", required=True)
    parser.add_argument("--trust-anchor", required=True)
    parser.add_argument("--trust-anchor-jwks", required=True, help="JSON JWK Set, as a string")
    parser.add_argument("--expected-warnings", required=True)
    parser.add_argument("--expected-skips", required=True)
    args = parser.parse_args()

    trust_anchor_jwks = json.loads(args.trust_anchor_jwks)
    expected_warnings = load_expected(args.expected_warnings)
    # args.expected_skips is accepted but never read: no module in this
    # plan is ever expected to SKIP, so there's nothing to match against
    # it — the flag stays required purely so run-all.sh's own
    # run_federation_plan can pass --expected-warnings/--expected-skips
    # uniformly, the same pair every other leg's config takes.

    client = KeepAliveClient()

    print(f"creating plan against entity_identifier={args.entity_identifier} trust_anchor={args.trust_anchor}", flush=True)
    plan = create_plan(client, args.entity_identifier, args.trust_anchor, trust_anchor_jwks)
    plan_id = plan["id"]
    modules = [m["testModule"] for m in plan["modules"]]
    print(f"plan {plan_id}: {len(modules)} modules: {', '.join(modules)}", flush=True)

    total = len(modules)
    passed = 0
    for test_module in modules:
        module_id = run_module(client, plan_id, test_module)
        try:
            wait_for_finished(client, module_id)
            clean, summary = evaluate_module(client, test_module, module_id, expected_warnings)
        except Exception as e:
            clean, summary = False, f"ERROR: {e}"
        if clean:
            passed += 1
        print(f"{test_module} ({module_id}): {summary}", flush=True)

    print(f"Overall totals: {passed}/{total} passed", flush=True)
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
