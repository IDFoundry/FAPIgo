#!/usr/bin/env python3
"""Workaround for the suite's own scripted-browser (HtmlUnit) usually
failing to execute implicitCallback.html's JS, which normally auto-POSTs
an empty body to a per-visit "implicit submission" URL to let a stuck
module continue (see CreateRandomImplicitSubmitUrl.java /
implicitCallback.html in the conformance-suite source). HtmlUnit throws
a syntax error parsing the page's Bootstrap 5.3.3 <script src> bundle -
but that failure is scoped to that one script tag, not the whole page:
the SEPARATE inline <script> block holding the real xhr.send() call
still executes independently, and sometimes wins on its own before this
poller ever gets there (confirmed live via the module's own log). So
this isn't "the module always hangs" - it's "the module hangs often
enough, unpredictably enough, that every AS-side plan run needs this
running regardless." When the browser's own JS does win the race,
submitting again anyway isn't just redundant: the suite's own
module-continuation logic isn't safe against being woken twice
concurrently, corrupting the flow into two racing token exchanges over
the same authorization code - see the "Incoming HTTP request to
{path}" check below, which exists specifically to detect and skip that
case.

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
     response) to it exactly once, one poll cycle after first seeing
     it (a fraction of a second at the default interval) - see the
     "already_submitted_by_browser" check below for why the delay is
     that short and no shorter.

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
     one hit this the same way, so this script never retries a URL,
     and only ever defers by one poll cycle - a flat one-second delay
     was tried here once and measurably made this cross-module
     misrouting worse, since most modules transition in well under a
     second once unblocked; a fraction-of-a-second deferral, scaled to
     the poll interval rather than a guessed constant, is far below
     that risk window while still usually being enough to let the
     browser's own JS (see immediately below) win first.

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

     Some modules create this placeholder speculatively, before the
     outcome is known — e.g. ensure-different-nonce-inside-and-outside
     -request-object logs its placeholder as soon as the redirect is
     built, even though the module can still go on to complete a fully
     valid, successful flow via a different path (using the request
     object's own correct nonce, per spec). AbstractTestModule's own
     fireTestFinishedInternal() only downgrades an otherwise-successful
     result to REVIEW if a placeholder was actually filled while the
     module was still undecided — so filling this unconditionally, the
     instant it's seen, forces a real PASS down to REVIEW. A one-cycle
     deferral (mirroring implicit-submit's) is NOT enough here: this
     log entry appears far earlier in wall-clock time (at redirect-
     build time) than implicit-submit's own entry (only after the
     callback), so confirmed live that the placeholder still got filled
     before implicit-submit's one-cycle deferral had even resolved.
     Instead this waits a flat PLACEHOLDER_GRACE_SECONDS from when the
     placeholder was first seen, then fills it only if the module is
     still active (not finished on its own in the meantime). This is
     safe to make generous: unlike implicit-submit's shared per-alias
     route, a placeholder fill is addressed by instance id directly, so
     there is no cross-module-misrouting risk in waiting longer — the
     only cost of a larger value is extra polling latency before a
     genuinely-review-needed module gets flagged, not an incorrect
     result. 5 seconds comfortably covers every legitimate
     self-finishing module observed live, including
     par-ensure-reused-request-uri-prior-to-auth-completion-succeeds,
     whose createPlaceholder() creates its placeholder unconditionally
     at test start — well before either of its two authorization-
     endpoint visits. That module was originally clocked taking
     anywhere from ~3s to ~31s to self-finish, which looked like
     inherent multi-visit timing variance and briefly drove this value
     up as high as 20s — but every one of those slow runs turned out to
     be masking a real go-fapi bug (the PAR request_uri was being
     invalidated on the mere GET to the authorization endpoint, not at
     actual authorization completion, so the module's second visit hit
     a 400 and the run only ever finished via this placeholder's
     eventual fill, never via a genuine callback). Once that storage-
     layer bug was fixed (single-use enforcement moved to
     CompleteAuthorization, gated on the underlying PAR reference — see
     storage/transaction.go), this module's real self-finish time
     dropped to ~130ms, in line with every other module here. 5s leaves
     ample margin above that for load variance without reintroducing
     the earlier multi-second-to-30-second latency that was never
     actually needed.

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
    pending = {}        # fullUrl -> instance_id, seen one cycle ago, not yet acted on
    uploaded = set()    # (instance_id, placeholder) pairs already filled (one attempt each)
    pending_placeholders = {}  # (instance_id, placeholder) -> monotonic time first seen
    active = set()      # instance ids not yet confirmed terminal
    seen_ever = set()   # instance ids ever added, so we don't re-add a terminal one

    # A placeholder can be created (and logged) well before the module's
    # own success path has a chance to run - anywhere from as soon as
    # the authorization redirect is built (e.g.
    # ensure-different-nonce-inside-and-outside-request-object) to
    # unconditionally at test start, before either authorization-
    # endpoint visit even happens (e.g. par-ensure-reused-request-uri
    # -prior-to-auth-completion-succeeds). A one-cycle deferral (mirroring
    # implicit-submit's) fires far too early for either: observed live
    # filling the placeholder BEFORE the module's own success path had
    # even been attempted, which is backwards - the module can never
    # take its "succeed normally" path if we've already forced it into
    # REVIEW first. Placeholders don't share a route across modules the
    # way implicit-submit does (they're addressed by instance id, not a
    # shared alias), so there's no cross-module-misrouting risk in
    # waiting longer here - long enough to comfortably cover the
    # slowest legitimate self-finishing module observed live (every one
    # completes within a few hundred milliseconds once genuinely
    # unblocked; see the doc comment at the top of this file for how a
    # much larger value was briefly needed here while a real go-fapi bug
    # was making one module falsely appear slow).
    PLACEHOLDER_GRACE_SECONDS = 5.0

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
                    if full_url not in pending:
                        # Defer to the next poll cycle instead of acting
                        # immediately: confirmed live, via a full log
                        # trace, that the check below still isn't enough
                        # on its own — the browser's own real xhr.send()
                        # (observed landing ~40-115ms after this log
                        # entry appears) can arrive in the gap between
                        # this poller fetching the log and posting,
                        # slipping past the check the same cycle it's
                        # first seen. One extra cycle (a fraction of a
                        # second here) gives that race a chance to
                        # resolve on its own before we decide, while
                        # staying far short of the multi-second lag that
                        # caused the cross-module alias-misrouting bug a
                        # deliberate flat delay was tried for once and
                        # reverted (see git history) — this is scaled to
                        # the poll interval, not a guessed constant.
                        pending[full_url] = instance_id
                        continue
                    del pending[full_url]
                    submitted.add(full_url)
                    request_path = urlsplit(full_url).path
                    # HtmlUnit's syntax error is scoped to the one
                    # <script src=bootstrap.min.js> tag - the SEPARATE
                    # inline <script> block holding implicitCallback.html's
                    # real xhr.send() logic still executes on its own,
                    # and sometimes wins this race before we even look.
                    # Submitting anyway when it already has is not just
                    # redundant: confirmed live that the suite's module-
                    # continuation logic isn't safe against being woken
                    # twice - it corrupts the flow into two concurrent
                    # token exchanges racing over the same authorization
                    # code, surfacing as a confusing "invalid_grant: code
                    # already used" on an otherwise-clean module. Since
                    # this same already-fetched `log` is what the browser's
                    # own request would also appear in, checking costs
                    # nothing extra.
                    already_submitted_by_browser = any(
                        e.get("msg") == f"Incoming HTTP request to {request_path}" for e in log
                    )
                    if already_submitted_by_browser:
                        print(f"skipped {instance_id}: browser's own JS already submitted {full_url}", flush=True)
                        continue
                    try:
                        status = client.post(request_path, b"")
                        print(f"unblocked {instance_id}: POST {full_url} -> {status}", flush=True)
                    except Exception as e:
                        print(f"unblock {instance_id} failed (not retrying): POST {full_url}: {e}", flush=True)

                placeholder = entry.get("upload")
                if placeholder:
                    key = (instance_id, placeholder)
                    if key in uploaded:
                        continue
                    if key not in pending_placeholders:
                        pending_placeholders[key] = time.monotonic()
                        continue

        now = time.monotonic()
        due = [key for key, first_seen in pending_placeholders.items() if now - first_seen >= PLACEHOLDER_GRACE_SECONDS]
        for key in due:
            fill_instance_id, placeholder = key
            del pending_placeholders[key]
            if fill_instance_id not in active:
                # Finished on its own during the grace period - this
                # placeholder was never actually needed. Leaving it
                # unfilled is correct: filling it now would still risk
                # (harmlessly, since the module's result is already
                # decided) but there's nothing to gain, and every trace
                # confirms a genuine success path finalizes long before
                # this grace period elapses.
                continue
            uploaded.add(key)
            try:
                status = client.post(f"/api/log/{fill_instance_id}/images/{placeholder}", PLACEHOLDER_PNG.encode())
                print(f"filled placeholder {fill_instance_id}/{placeholder} -> {status}", flush=True)
            except Exception as e:
                print(f"fill placeholder {fill_instance_id}/{placeholder} failed (not retrying): {e}", flush=True)

        time.sleep(0.2)


if __name__ == "__main__":
    main()
