#!/usr/bin/env python3
"""Workaround for the suite's own scripted-browser (HtmlUnit) failing to
execute implicitCallback.html's JS, which normally auto-POSTs an empty
body to a per-visit "implicit submission" URL to let a stuck module
continue (see CreateRandomImplicitSubmitUrl.java / implicitCallback.html
in the conformance-suite source). HtmlUnit throws a syntax error trying
to parse the page's Bootstrap 5.3.3 bundle before it ever reaches that
submission script, so the module hangs forever waiting for a POST that
never arrives.

This is not an optional convenience — every suite version that supports
the fapi2-security-profile-final-test-plan this AS is tested against
also carries this bug. Confirmed by bisecting the suite's own git
history: release-v5.1.17 has the old, working Bootstrap 5.2.3 template
but predates the FAPI2-Security-Profile-Final test plan entirely (it
was added in the very next release, v5.1.18, which also bumped
Bootstrap to 5.3.3 in the same release). There is no version with both.
Run this alongside run-test-plan.py for any AS-side FAPI2 plan.

Run it alongside run-test-plan.py:

    ./scripts/run-test-plan.py '<plan>[...]' <config.json> &
    /path/to/unblock-implicit-callback.py <planId>

<planId> is printed by run-test-plan.py itself ("Created test plan, new
id: ..."), or read it from the suite's own plan-detail URL.

This script polls a plan's currently-known module instances (via
GET /api/plan/{planId}, whose "modules[].instances" list grows live as
run-test-plan.py creates each module) and, for each instance still
active (not yet FINISHED/INTERRUPTED), watches its log for two kinds of
stuck-waiting-for-a-human events and resolves each automatically:

  1. A "Created random implicit submission URL" entry: POSTs an empty
     body (mirroring implicitCallback.html's own `xhr.send(hash)`,
     where hash is empty for a plain query-param, non-fragment
     response) to it exactly once, immediately.

     IMPORTANT: every module in a plan without dynamic client
     registration shares one alias, and the suite reassigns the
     alias's fixed-path callback route
     (/test/a/<alias>/implicit/<random>) to whichever module currently
     owns the alias — NOT to whichever module originally generated
     that random path. A POST that arrives even a little late (after
     the module that generated it has already been abandoned — e.g.
     by run-test-plan.py's own timeout, or simply by the next module
     starting) gets delivered to a *different*, unrelated, later
     module instead, which correctly rejects it as unexpected and
     gets itself interrupted. Both a delayed submission AND a retried
     one hit this the same way, so this script (a) never retries a
     URL and (b) submits as fast as possible: a deliberate fixed delay
     was tried here (to sidestep a rarer issue below) and measurably
     made this cross-module misrouting worse, since most modules
     transition in well under a second once unblocked.

  2. A log entry carrying an "upload" placeholder id (negative-test
     modules that land on a local error page and ask a human to
     "upload a screenshot" — createBrowserInteractionPlaceholder() in
     the suite's own AbstractCondition.java): POSTs a minimal 1x1 PNG
     to POST /api/log/{testId}/images/{placeholder}. Confirmed live
     (ImageAPI.java + AbstractTestModule.waitForPlaceholders(), a
     background watcher every module with a placeholder runs, backing
     off from 1s up to 30s) that this alone is sufficient to move the
     module from WAITING to FINISHED with result=REVIEW — nothing
     else needs approving by hand for run-test-plan.py's own purposes,
     which only waits for status, not result. A human still needs to
     look at REVIEW results afterward; the blank placeholder image
     can't confirm the AS actually showed a proper error page.

Known residual limitation: a couple of modules with unusually complex
multi-visit semantics (e.g.
par-ensure-reused-request-uri-prior-to-auth-completion-succeeds, which
requires the SAME login page be visited twice — once unauthenticated,
once already authenticated) can still fail, since a generic
empty-body POST doesn't preserve the browser-session continuity those
specific tests depend on. This is a limitation of automating past the
suite's own broken browser, not of the AS under test — check the
failing module's own log for its actual assertion failure (or lack of
one) before assuming a real regression.

Usage: unblock-implicit-callback.py <planId> [<planId> ...]
"""
import os
import sys
import time
import http.client
import json
import ssl
from urllib.parse import urlsplit

CONFORMANCE_SERVER = os.environ.get("CONFORMANCE_SERVER", "https://localhost.emobix.co.uk:8443/")
_parsed = urlsplit(CONFORMANCE_SERVER)
HOST = _parsed.hostname
PORT = _parsed.port or 8443
CTX = ssl._create_unverified_context()

# A minimal valid 1x1 transparent PNG - content doesn't matter, the
# suite only validates it's a well-formed image under its size limit.
PLACEHOLDER_PNG = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAA"
    "AAYAAjCB0C8AAAAASUVORK5CYII="
)


class KeepAliveClient:
    """A minimal keep-alive HTTPS client. Connection reuse matters here:
    re-scanning dozens of already-finished module logs every poll cycle
    with a fresh TLS handshake per request was slow enough to delay
    submissions past a module's own short-lived window, which is
    exactly the misrouting failure mode described above."""

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

    def post(self, path, body, content_type="text/plain"):
        for attempt in range(2):
            try:
                self._ensure()
                self.conn.request("POST", path, body=body, headers={"Content-Type": content_type})
                resp = self.conn.getresponse()
                resp.read()
                return resp.status
            except Exception:
                self.conn = None
                if attempt == 1:
                    raise


def main():
    plan_ids = sys.argv[1:]
    if not plan_ids:
        print("usage: unblock-implicit-callback.py <planId> [<planId> ...]", file=sys.stderr)
        sys.exit(1)

    client = KeepAliveClient()
    submitted = set()   # implicit_submit fullUrl values already POSTed (one attempt each)
    uploaded = set()    # (instance_id, placeholder) pairs already filled (one attempt each)
    active = set()      # instance ids not yet confirmed terminal
    seen_ever = set()   # instance ids ever added, so we don't re-add a terminal one

    print(f"watching plans: {plan_ids} on {HOST}:{PORT}", flush=True)
    while True:
        for plan_id in plan_ids:
            try:
                plan = client.get_json(f"/api/plan/{plan_id}")
            except Exception as e:
                print(f"plan {plan_id}: fetch error: {e}", flush=True)
                continue
            for module in plan.get("modules", []):
                for instance_id in module.get("instances", []):
                    if instance_id not in seen_ever:
                        seen_ever.add(instance_id)
                        active.add(instance_id)

        for instance_id in list(active):
            try:
                info = client.get_json(f"/api/info/{instance_id}")
            except Exception:
                continue
            if info.get("status") in ("FINISHED", "INTERRUPTED"):
                active.discard(instance_id)
                continue

            try:
                log = client.get_json(f"/api/log/{instance_id}")
            except Exception:
                continue

            for entry in log:
                if entry.get("msg") == "Created random implicit submission URL":
                    full_url = entry.get("implicit_submit", {}).get("fullUrl")
                    if not full_url or full_url in submitted:
                        continue
                    submitted.add(full_url)
                    try:
                        status = client.post(urlsplit(full_url).path, b"")
                        print(f"unblocked {instance_id}: POST {full_url} -> {status}", flush=True)
                    except Exception as e:
                        print(f"unblock {instance_id} failed (not retrying): POST {full_url}: {e}", flush=True)

                placeholder = entry.get("upload")
                if placeholder:
                    key = (instance_id, placeholder)
                    if key in uploaded:
                        continue
                    uploaded.add(key)
                    try:
                        status = client.post(f"/api/log/{instance_id}/images/{placeholder}", PLACEHOLDER_PNG.encode())
                        print(f"filled placeholder {instance_id}/{placeholder} -> {status}", flush=True)
                    except Exception as e:
                        print(f"fill placeholder {instance_id}/{placeholder} failed (not retrying): {e}", flush=True)

        time.sleep(0.2)


if __name__ == "__main__":
    main()
