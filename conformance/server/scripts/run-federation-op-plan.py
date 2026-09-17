#!/usr/bin/env python3
"""Runs the OIDF conformance suite's own
"openid-federation-entity-joined-to-test-federation-op-test-plan"
(client_registration=automatic, server_metadata=discovery)'s
openid-federation-automatic-client-registration-with-par module against
a running conformance-as-federation, and reports whether the automatic
registration this AS performs at its own PAR endpoint actually succeeds.

Only -with-par is attempted here — not the plan's other five
"positive" modules (-with-jar-and-get/-with-jar-and-post and each of
their own -and-trust-chain siblings). Those all deliver the
authorization request without PAR (JAR by value, GET or POST straight
to /authorize); this AS's own metadata advertises
require_pushed_authorization_requests=true (the FAPI 2.0 Security
Profile's own baseline, not a federation-specific choice), so it
correctly rejects every one of those with invalid_request regardless
of Trust Anchor setup. -with-par is the one module whose own request
shape this AS is actually willing to accept.

Bridges the one structural gap that's kept every module in this plan
from ever completing automatic registration against this AS, found by
tracing a live run all the way to the actual PAR call (see
project_openid_federation_status.md's own PR #317 note for the full
investigation): the suite plays the Relying Party and self-hosts a
fresh Trust Anchor for every single test instance — its own Entity
Identifier is a random path segment under the suite's own base URL,
generated anew each run — so no static -federation config file
(oidf-config/federation.config.json) can ever list it in advance.

The suite's own configure()+start() (which builds the Trust Anchor,
signs the request object, and calls this AS's own PAR endpoint) runs
in a background task dispatched immediately after module creation
returns — confirmed live to complete, end to end, within about a
second, leaving no reliable window to compute the module's own random
ID and register its Trust Anchor with this AS afterwards. So this
script sidesteps the race entirely with the suite's own "alias"
config field: supplying "alias" makes the suite build the test
instance's own base URL from that fixed string instead of a random
ID (TestRunner.createTest's own alias branch — "test/a/<alias>"
instead of "test/<random id>"), so this script generates its own
random alias, computes the resulting Trust Anchor Entity Identifier
deterministically (baseUrl + "/trust-anchor" — see
AbstractOpenIDFederationAutomaticClientRegistrationTest.configure() in
the suite's own source), and registers it with conformance-as-federation's
own POST /internal/federation/trust-anchors
(-federation-trust-anchor-admin, cmd/conformance-as/
federation_trust_anchor_admin.go) *before* the module is ever created
at all — no race to win.

This only proves automatic registration/PAR itself succeeds — it does
not drive the rest of the flow (consent, token exchange, id_token
validation), which needs the suite's own browser-driving machinery
(scripts/run-test-plan.py) this narrower script doesn't attempt to
reproduce. Not wired into run-all.sh: unlike run-federation-plan.py's
own five modules, a genuinely complete run of this one still needs that
missing browser-driving piece to reach a real PASSED verdict, so this
script's own "did PAR succeed" report is a diagnostic tool for now, not
a CI gate.

As of this writing, PAR itself still FAILs here — but for a cause
outside this AS's or this script's control, confirmed by tracing the
live error through this AS's own server logs (never returned to the
caller — see server/par.go's own "unknown client" wording, deliberate,
not a bug): the suite's own AddOpenIDRelyingPartyMetadataToEntityConfiguration
condition (which builds the RP's own openid_relying_party metadata for
every module in this plan) never sets a "token_endpoint_auth_method"
claim at all, for any configuration this script — or any config a
human could supply through the suite's own UI — can influence. This AS
requires one to be explicit (no implicit "client_secret_basic" default,
both FAPIgo's own "no implicit defaults" design and FAPI 2.0's own
prohibition on client_secret-based methods), so it correctly refuses
to auto-register a client that never declares one — the SSRF/TLS/Trust
Anchor plumbing above all completed successfully first, confirmed by
watching the AS's own error move from "target address is not allowed"
to a TLS certificate error to this exact, final, metadata-content
error, one real fix at a time. This is a gap in the suite's own test
module, not this AS: revisit once/if the suite ships a fix, or a
configuration surface for it.

Usage:
    run-federation-op-plan.py \
        --entity-identifier https://conformance-as-federation:8443 \
        --as-admin-url https://127.0.0.1:18456
"""
import argparse
import base64
import http.client
import json
import os
import secrets
import sys
import time
from urllib.parse import quote, urlsplit

from _sslutil import local_only_ssl_context

CONFORMANCE_SERVER = os.environ.get("CONFORMANCE_SERVER", "https://localhost.emobix.co.uk:8443/")
_suite = urlsplit(CONFORMANCE_SERVER)
SUITE_HOST = _suite.hostname
SUITE_PORT = _suite.port or 8443
SUITE_BASE = f"https://{SUITE_HOST}:{SUITE_PORT}"

MODULE_POLL_TIMEOUT_SECONDS = 30
MODULE_POLL_INTERVAL_SECONDS = 0.5


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def generate_ec_jwk(kid):
    """Generates one P-256 signing JWK (private, ES256) — this script's
    own throwaway RP/Trust Anchor keys, never persisted, matching
    run-federation-plan.py's own "confirmed working by hand before
    being scripted" standard for exactly this kind of one-off crypto
    plumbing."""
    from cryptography.hazmat.primitives.asymmetric import ec

    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.private_numbers()
    pub = nums.public_numbers
    return {
        "kty": "EC", "crv": "P-256",
        "x": b64u(pub.x.to_bytes(32, "big")),
        "y": b64u(pub.y.to_bytes(32, "big")),
        "d": b64u(nums.private_value.to_bytes(32, "big")),
        "kid": kid, "alg": "ES256", "use": "sig",
    }


def public_jwks(private_jwks):
    """Strips "d" from every key in a {"keys": [...]} JWK Set — the
    shape POST /internal/federation/trust-anchors expects (a Trust
    Anchor's own JWKS is verification-only material from a Resolver's
    own perspective; see federation.TrustAnchor's own doc comment)."""
    return {"keys": [{k: v for k, v in jwk.items() if k != "d"} for jwk in private_jwks["keys"]]}


class KeepAliveClient:
    """Same minimal keep-alive HTTPS client as run-federation-plan.py's
    own — see its own doc comment for why this isn't shared via an
    import between these independently-runnable scripts. Parametrized
    over host/port/ssl_context here, since this script talks to two
    different hosts (the suite, and conformance-as-federation's own
    admin port) rather than one."""

    def __init__(self, host, port, ctx):
        self.host, self.port, self.ctx = host, port, ctx
        self.conn = None

    def _ensure(self):
        if self.conn is None:
            self.conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=15)

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

    def post_json(self, path, payload=None, expect=(200, 201)):
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {} if payload is None else {"Content-Type": "application/json"}
        for attempt in range(2):
            try:
                self._ensure()
                self.conn.request("POST", path, body=body, headers=headers)
                resp = self.conn.getresponse()
                resp_body = resp.read()
                if resp.status not in expect:
                    raise RuntimeError(f"POST {path} -> {resp.status}: {resp_body[:500]!r}")
                return resp.status, (json.loads(resp_body) if resp_body else None)
            except Exception:
                self.conn = None
                if attempt == 1:
                    raise


def create_plan(suite, entity_identifier, rp_ec_jwks, rp_client_jwks, trust_anchor_jwks, alias):
    variant = json.dumps({"client_registration": "automatic", "server_metadata": "discovery"})
    config = {
        "alias": alias,
        "federation": {
            "entity_identifier": entity_identifier,
            "rp_ec_jwks": rp_ec_jwks,
            "rp_client_jwks": rp_client_jwks,
        },
        "federation_trust_anchor": {"trust_anchor_jwks": trust_anchor_jwks},
    }
    path = f"/api/plan?planName=openid-federation-entity-joined-to-test-federation-op-test-plan&variant={quote(variant)}"
    _, plan = suite.post_json(path, config, expect=(201,))
    return plan["id"]


def create_module(suite, plan_id, test_module):
    _, result = suite.post_json(f"/api/runner?test={quote(test_module)}&plan={plan_id}", expect=(201,))
    return result["id"]


def wait_for_par_outcome(suite, module_id):
    """Polls module_id's own log until either a CallPAREndpoint result
    appears or the module reaches a terminal status, whichever first —
    this script only cares about the PAR outcome, not the rest of the
    flow (see this file's own doc comment)."""
    deadline = time.monotonic() + MODULE_POLL_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        log = suite.get_json(f"/api/log/{module_id}")
        for entry in log:
            if entry.get("src") == "CallPAREndpoint" and "response_status_code" in entry:
                return entry
        info = suite.get_json(f"/api/info/{module_id}")
        if info.get("status") in ("FINISHED", "INTERRUPTED"):
            return None
        time.sleep(MODULE_POLL_INTERVAL_SECONDS)
    raise RuntimeError(f"module {module_id} produced no PAR result within {MODULE_POLL_TIMEOUT_SECONDS}s")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--entity-identifier", required=True, help="this AS's own Entity Identifier, e.g. https://conformance-as-federation:8443")
    parser.add_argument("--as-admin-url", required=True, help="this AS's own base URL as reachable from where this script runs, e.g. https://127.0.0.1:18456 (the docker-compose-exposed port, not the in-network hostname)")
    args = parser.parse_args()

    admin = urlsplit(args.as_admin_url)
    suite = KeepAliveClient(SUITE_HOST, SUITE_PORT, local_only_ssl_context(SUITE_HOST))
    as_admin = KeepAliveClient(admin.hostname, admin.port or 443, local_only_ssl_context(admin.hostname))

    rp_ec_jwks = {"keys": [generate_ec_jwk("rp-ec-key1")]}
    rp_client_jwks = {"keys": [generate_ec_jwk("rp-client-key1")]}
    trust_anchor_jwks = {"keys": [generate_ec_jwk("ta-key1")]}

    alias = "gofapi-op-plan-" + secrets.token_hex(8)

    # See this file's own doc comment for why alias, not the module's
    # own (unknown until after creation) random ID, is what makes this
    # entity_id computable — and therefore registerable — up front.
    trust_anchor_entity_id = f"{SUITE_BASE}/test/a/{alias}/trust-anchor"
    print(f"adding trust anchor {trust_anchor_entity_id} to {args.as_admin_url}", flush=True)
    as_admin.post_json(
        "/internal/federation/trust-anchors",
        {"entity_id": trust_anchor_entity_id, "jwks": public_jwks(trust_anchor_jwks)},
        expect=(204,),
    )

    print(f"creating plan against entity_identifier={args.entity_identifier}", flush=True)
    plan_id = create_plan(suite, args.entity_identifier, rp_ec_jwks, rp_client_jwks, trust_anchor_jwks, alias)

    test_module = "openid-federation-automatic-client-registration-with-par"
    module_id = create_module(suite, plan_id, test_module)

    par_result = wait_for_par_outcome(suite, module_id)
    if par_result is None:
        print(f"{test_module} ({module_id}): NO PAR CALL OBSERVED — see {SUITE_BASE}/test/{module_id}", flush=True)
        sys.exit(1)

    status = par_result["response_status_code"]
    print(f"{test_module} ({module_id}): PAR responded {status}", flush=True)
    if status.startswith("201"):
        print("PASS: automatic registration succeeded at PAR", flush=True)
        sys.exit(0)
    print(f"FAIL: {par_result.get('response_body', '')}", flush=True)
    sys.exit(1)


if __name__ == "__main__":
    main()
