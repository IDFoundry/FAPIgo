#!/usr/bin/env python3
"""Builds report.md from a completed conformance/scripts/run-all.sh run.

run-all.sh calls this once, after all eight suites have finished and
results.txt/the per-suite log files already exist — it doesn't run any
part of the suites itself, only reads what's already on disk:

  - results.txt (run-all.sh's own "NAME|LINE" record_result output)
  - as-{baseline,message-signing,ciba-mtls,client-auth-mtls}.log
    (run-test-plan.py's own verbose stdout, already captured by
    run-all.sh)
  - as-{baseline,message-signing,ciba-mtls,client-auth-mtls}-retry.log,
    if retry-flaky-modules.py ran (only exists when that suite came
    back non-clean)
  - rp-{baseline,message-signing,ciba-mtls}.log (cmd/conformance-client's
    own stdout) — client-auth-mtls has no RP-side counterpart (see
    run-all.sh's own comment on that leg)
  - conformance/server/expected-{warnings,skips}-{baseline,message
    -signing,ciba-mtls,client-auth-mtls}.json — the same files
    run-test-plan.py itself reads, so every WARNING/SKIPPED module's
    "why this is expected, not a defect" reasoning in the report is
    pulled from the one place that reasoning is already authoritatively
    written down, not re-explained/duplicated here.

Each suite section leads with a quick table of just its non-PASSED
modules (empty/omitted when everything passed) so a regression is
visible without scrolling, followed by a collapsed "All N modules run"
<details> block listing every module by name with its own status —
the full, audit-trail-grade record of what actually ran, not just how
many.

Usage:
    generate-report.py <workdir> <repo_root>

Writes <workdir>/report.md.
"""
import fnmatch
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# run-test-plan.py prefixes every line with its own "YYYY-MM-DD
# HH:MM:SS " timestamp - see retry-flaky-modules.py's identical regex
# for the same reason.
TEST_LINE_RE = re.compile(r"^(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} )?Test \[(\d+):(\d+)\] (\S+) (\S+) (\S+) - result (\S+)\.")

AS_SUITES = ["baseline", "message-signing", "ciba-mtls", "client-auth-mtls"]
RP_SUITES = ["baseline", "message-signing", "ciba-mtls", "client-auth-mtls"]

# Markdown separator row for a 2-column table (Module/Result).
TABLE_SEPARATOR_2COL = "|---|---|"


def strip_ansi(s):
    return ANSI_RE.sub("", s)


def git_info(repo_root):
    def run(*args):
        try:
            return subprocess.run(
                ["git", *args], cwd=repo_root, capture_output=True, text=True, check=True
            ).stdout.strip()
        except Exception:
            return None

    return run("rev-parse", "--short", "HEAD"), run("branch", "--show-current")


def load_results(workdir):
    results = {}
    results_file = workdir / "results.txt"
    if not results_file.exists():
        return results
    for line in results_file.read_text().splitlines():
        if "|" not in line:
            continue
        name, _, value = line.partition("|")
        results[name] = value  # last one wins, matching lookup_result's `tail -1`
    return results


def parse_as_log(log_path):
    """Returns a list of dicts: {plan_n, mod_n, test_name, module_id,
    status, result} for every module run-test-plan.py printed a Test
    [...] line for."""
    modules = []
    if not log_path.exists():
        return modules
    for raw in log_path.read_text().splitlines():
        line = strip_ansi(raw)
        m = TEST_LINE_RE.match(line)
        if not m:
            continue
        _, _, test_name, module_id, status, result = m.groups()
        # The printed name carries the variant inline, e.g.
        # "...-happy-flow[fapi_request_method=unsigned][...]" - strip
        # it back to the bare test module name so it matches
        # expected-{warnings,skips}-*.json's own "test-name" entries
        # (which never include a variant suffix; variant is matched
        # separately there, and this report doesn't need that
        # granularity).
        test_name = test_name.split("[", 1)[0]
        modules.append(
            {
                "test_name": test_name,
                "module_id": module_id,
                "status": status,
                "result": result,
            }
        )
    return modules


def load_expected(repo_root, kind, name):
    """kind is 'warnings' or 'skips'."""
    path = repo_root / "conformance" / "server" / f"expected-{kind}-{name}.json"
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def find_comment(expected_list, test_name):
    for entry in expected_list:
        if fnmatch.fnmatch(test_name, entry.get("test-name", "")):
            return entry.get("comment", "").strip()
    return None


def parse_retry_log(retry_log_path):
    """Returns {module_id: outcome_string} for whatever
    retry-flaky-modules.py reported, keyed by the *original* module id
    it was retrying on behalf of."""
    outcomes = {}
    if not retry_log_path.exists():
        return outcomes
    text = retry_log_path.read_text()
    for line in text.splitlines():
        m = re.search(r"^retry-flaky-modules: (\S+) (\S+) matches a known flake signature — retrying as (\S+)", line)
        if m:
            test_name, module_id, new_id = m.groups()
            outcomes[module_id] = {"test_name": test_name, "new_id": new_id, "result": "pending"}
    for line in text.splitlines():
        m = re.search(r"^retry-flaky-modules: (\S+) retry (\S+) -> (.+)$", line)
        if m:
            test_name, new_id, result = m.groups()
            for module_id, info in outcomes.items():
                if info["new_id"] == new_id:
                    info["result"] = result
    return outcomes


def parse_rp_log(log_path):
    """Returns a list of dicts: {test_name, result, detail} for every
    line in a cmd/conformance-client log's "=== summary ===" block —
    main.go prints one "<outcome> <test-name>" line per module there,
    where <outcome> is the suite's own graded result optionally
    followed by "[driver: ...]" context (see main.go's awaitVerdict).
    test_name never contains whitespace, so it's always the line's
    last token; everything before it is the outcome/detail field."""
    modules = []
    if not log_path.exists():
        return modules
    in_summary = False
    for line in log_path.read_text().splitlines():
        if "=== summary ===" in line:
            in_summary = True
            continue
        if not in_summary or not line.strip():
            continue
        # Strip the "YYYY/MM/DD HH:MM:SS " prefix Go's log package adds.
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        detail, _, test_name = parts[2].rpartition(" ")
        detail = detail.strip()
        result = detail.split()[0] if detail else ""
        modules.append({"test_name": test_name, "result": result, "detail": detail})
    return modules


def render_as_suite(md, name, workdir, repo_root, results):
    log_path = workdir / f"as-{name}.log"
    retry_log_path = workdir / f"as-{name}-retry.log"
    result_line = results.get(f"AS {name}", "DID NOT RUN")

    md.append(f"## AS {name}\n")
    md.append(f"**{result_line}**\n")

    modules = parse_as_log(log_path)
    if not modules:
        md.append(f"_No module detail available — see [{log_path.name}]({log_path.name})._\n")
        return

    retry_outcomes = parse_retry_log(retry_log_path)
    expected_warnings = load_expected(repo_root, "warnings", name)
    expected_skips = load_expected(repo_root, "skips", name)

    def why_for(m):
        if m["module_id"] in retry_outcomes:
            info = retry_outcomes[m["module_id"]]
            return f"auto-retried (known suite-browser flake) → {info['result']}"
        if m["result"] == "WARNING":
            return find_comment(expected_warnings, m["test_name"]) or "**no expected-warnings entry found**"
        if m["result"] in ("SKIPPED", "REVIEW"):
            return find_comment(expected_skips, m["test_name"]) or (
                "requires human review of an uploaded screenshot" if m["result"] == "REVIEW" else ""
            )
        if m["result"] == "FAILED":
            return "**not in any expected list — check the log**"
        return ""

    not_passed = [m for m in modules if m["result"] != "PASSED"]
    if not_passed:
        md.append("| Module | Status | Result | Why |")
        md.append("|---|---|---|---|")
        for m in not_passed:
            md.append(f"| `{m['test_name']}` | {m['status']} | {m['result']} | {why_for(m)} |")
        md.append("")
    else:
        md.append("Every module PASSED.\n")

    md.append(f"<details><summary>All {len(modules)} modules run</summary>\n")
    md.append("| Module | Status | Result | Why |")
    md.append("|---|---|---|---|")
    for m in modules:
        md.append(f"| `{m['test_name']}` | {m['status']} | {m['result']} | {why_for(m)} |")
    md.append("")
    md.append("</details>\n")

    md.append(f"Full log: [{log_path.name}]({log_path.name})\n")


def render_rp_suite(md, name, workdir, results):
    log_path = workdir / f"rp-{name}.log"
    result_line = results.get(f"RP {name}", "DID NOT RUN")
    md.append(f"## RP {name}\n")
    md.append(f"**{result_line}**\n")

    modules = parse_rp_log(log_path)
    if not modules:
        md.append(f"_No module detail available — see [{log_path.name}]({log_path.name})._\n")
        return

    not_passed = [m for m in modules if m["result"] != "PASSED"]
    if not_passed:
        md.append("| Module | Result |")
        md.append(TABLE_SEPARATOR_2COL)
        for m in not_passed:
            md.append(f"| `{m['test_name']}` | {m['detail']} |")
        md.append("")
    else:
        md.append("Every module PASSED.\n")

    md.append(f"<details><summary>All {len(modules)} modules run</summary>\n")
    md.append("| Module | Result |")
    md.append(TABLE_SEPARATOR_2COL)
    for m in modules:
        md.append(f"| `{m['test_name']}` | {m['detail']} |")
    md.append("")
    md.append("</details>\n")

    md.append(f"Full log: [{log_path.name}]({log_path.name})\n")


def main():
    if len(sys.argv) != 3:
        print("usage: generate-report.py <workdir> <repo_root>", file=sys.stderr)
        sys.exit(2)
    # Resolved to an absolute, canonical path and checked up front —
    # every read/write this script does (results.txt, the per-suite
    # logs, expected-{warnings,skips}-*.json, report.md itself) derives
    # from one of these two arguments, so this is the one place that
    # needs to fail clearly on a malformed one (e.g. a hallucinated or
    # mistyped path from an automated caller) instead of silently
    # reading or writing wherever it happens to resolve to.
    workdir = Path(sys.argv[1]).resolve()
    repo_root = Path(sys.argv[2]).resolve()
    if not workdir.is_dir():
        print(f"error: workdir {workdir} is not a directory", file=sys.stderr)
        sys.exit(2)
    if not (repo_root / "conformance" / "server").is_dir():
        print(f"error: repo_root {repo_root} does not look like a FAPIgo checkout (no conformance/server directory)", file=sys.stderr)
        sys.exit(2)

    commit, branch = git_info(repo_root)
    results = load_results(workdir)

    md = []
    md.append("# Conformance report\n")
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if commit:
        where = f"`{commit}`" + (f" on `{branch}`" if branch else "")
    else:
        where = "(commit unknown)"
    md.append(f"Generated {generated} by `conformance/scripts/run-all.sh`, FAPIgo at {where}.\n")

    md.append("## Summary\n")
    md.append("| Suite | Result |")
    md.append(TABLE_SEPARATOR_2COL)
    for label in ["AS baseline", "AS message-signing", "AS ciba-mtls", "AS client-auth-mtls", "RP baseline", "RP message-signing", "RP ciba-mtls", "RP client-auth-mtls"]:
        md.append(f"| {label} | {results.get(label, 'DID NOT RUN')} |")
    md.append("")

    for name in AS_SUITES:
        render_as_suite(md, name, workdir, repo_root, results)
    for name in RP_SUITES:
        render_rp_suite(md, name, workdir, results)

    report_path = workdir / "report.md"
    report_path.write_text("\n".join(md) + "\n")
    print(f"wrote {report_path}")


if __name__ == "__main__":
    main()
