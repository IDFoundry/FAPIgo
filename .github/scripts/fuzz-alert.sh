#!/usr/bin/env bash
# Reports a nightly fuzz.yml run on a GitHub issue labelled "fuzz", so a
# red run can't go unnoticed: nothing else alerts on it, and it never
# runs against a PR.
#
# On a failed run it opens an issue naming the failing targets, their
# job logs and how to reproduce each one, or comments on the open
# "fuzz" issue if there already is one. On a passing run it comments on
# and closes the open "fuzz" issue, if any. Any other result (a
# cancelled run) is left alone.
#
# Usage: fuzz-alert.sh <result>
#   <result> is needs.fuzz.result: success, failure, cancelled or skipped.
# Environment: GH_TOKEN and GH_REPO (for gh), RUN_ID, RUN_NUMBER,
# RUN_URL.
set -euo pipefail

result=$1
label=fuzz

open_issue() {
	gh issue list --label "$label" --state open --limit 1 --json number --jq '.[0].number // empty'
}

# failed_jobs prints one tab-separated "<pkg> <target> <conclusion> <url>"
# line per matrix job of this run that didn't pass. Matrix jobs are
# named "fuzz (<pkg>, <target>)".
failed_jobs() {
	# $m is a jq variable, not a shell one.
	# shellcheck disable=SC2016
	gh api --paginate "repos/$GH_REPO/actions/runs/$RUN_ID/jobs?per_page=100" \
		--jq '.jobs[]
			| select(.name | startswith("fuzz ("))
			| select(.conclusion != "success" and .conclusion != "skipped")
			| (.name | capture("^fuzz \\((?<pkg>[^,]+), (?<target>[^)]+)\\)$")) as $m
			| [$m.pkg, $m.target, .conclusion, .html_url] | @tsv'
}

failure_body() {
	local jobs=$1
	echo "Nightly fuzz run #$RUN_NUMBER failed: $RUN_URL"
	echo
	echo "| Package | Target | Result | Log |"
	echo "| --- | --- | --- | --- |"
	if [[ -z "$jobs" ]]; then
		echo "| ? | ? | failure | $RUN_URL (no failed matrix job found; see the run) |"
	fi
	local pkg target conclusion url
	while IFS=$'\t' read -r pkg target conclusion url; do
		[[ -n "$pkg" ]] || continue
		echo "| \`$pkg\` | \`$target\` | $conclusion | [job]($url) |"
	done <<<"$jobs"
	cat <<EOF

To reproduce, from the repository root, download a target's
\`fuzz-failure-<Target>\` artifact, which puts the failing input at
\`<pkg>/testdata/fuzz/<Target>/<file>\` (there is none if the job failed
without writing one), and replay it with
\`go test <pkg> -run '<Target>/<file>'\`, or every seed of the target
with \`-run '<Target>'\`:

\`\`\`sh
EOF
	while IFS=$'\t' read -r pkg target conclusion url; do
		[[ -n "$pkg" ]] || continue
		echo "gh run download $RUN_ID -n fuzz-failure-$target && go test $pkg -run '$target'"
	done <<<"$jobs"
	cat <<EOF
\`\`\`

Fix the bug and commit the input with the fix, where it stays as a
regression seed that every \`go test\` run replays. This issue closes
itself on the next nightly run that passes.
EOF
}

case "$result" in
failure)
	jobs=$(failed_jobs)
	body=$(mktemp)
	trap 'rm -f "$body"' EXIT
	failure_body "$jobs" >"$body"
	issue=$(open_issue)
	if [[ -n "$issue" ]]; then
		gh issue comment "$issue" --body-file "$body"
	else
		gh label create "$label" --color d93f0b \
			--description "Nightly fuzz run failures" --force
		gh issue create --title "Nightly fuzz failure" --label "$label" --body-file "$body"
	fi
	;;
success)
	issue=$(open_issue)
	if [[ -n "$issue" ]]; then
		gh issue close "$issue" --comment "Nightly fuzz run #$RUN_NUMBER passed: $RUN_URL"
	fi
	;;
*)
	echo "fuzz matrix result is \"$result\"; nothing to report."
	;;
esac
