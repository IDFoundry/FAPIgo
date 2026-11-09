#!/usr/bin/env bash
# Checks that every Postgres service image in .github/workflows/ (the
# sqlstore job in ci.yml, and mutation.yml) is exactly the image
# .github/postgres/Dockerfile pins (tag and digest). Dependabot can't
# update a workflow's service image but does update a Dockerfile's, so a
# Dependabot pull request moving the Dockerfile's digest fails this
# until the workflows are moved to match.
#
# Usage: check-postgres-pin.sh [repo-root]
set -euo pipefail

root=${1:-.}
dockerfile=$root/.github/postgres/Dockerfile

want=$(sed -nE 's/^FROM[[:space:]]+([^[:space:]]+).*/\1/p' "$dockerfile")
if [[ "$(printf '%s\n' "$want" | grep -c .)" -ne 1 || $want != postgres:*@sha256:* ]]; then
	echo "$dockerfile: want exactly one FROM postgres:<tag>@sha256:<digest> line" >&2
	exit 1
fi

status=0
seen=0
for workflow in "$root"/.github/workflows/*.yml; do
	found=$(sed -nE 's/^[[:space:]]*image:[[:space:]]*(postgres[:@][^[:space:]]*).*/\1/p' "$workflow")
	[[ -z $found ]] && continue
	while IFS= read -r got; do
		seen=$((seen + 1))
		if [[ $got != "$want" ]]; then
			echo "$workflow: Postgres service image $got doesn't match $dockerfile's $want; copy the Dockerfile's pin there" >&2
			status=1
		fi
	done <<<"$found"
done
if [[ $seen -eq 0 ]]; then
	echo "$root/.github/workflows: no Postgres service image found" >&2
	exit 1
fi
[[ $status -eq 0 ]] && echo "All $seen Postgres service images match $dockerfile: $want"
exit "$status"
