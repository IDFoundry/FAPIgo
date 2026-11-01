#!/usr/bin/env bash
# Checks that every Postgres service image in .github/workflows/ci.yml
# is exactly the image .github/postgres/Dockerfile pins (tag and digest).
# Dependabot can't update a workflow's service image but does update a
# Dockerfile's, so a Dependabot pull request moving the Dockerfile's
# digest fails this until ci.yml is moved to match.
#
# Usage: check-postgres-pin.sh [repo-root]
set -euo pipefail

root=${1:-.}
dockerfile=$root/.github/postgres/Dockerfile
workflow=$root/.github/workflows/ci.yml

want=$(sed -nE 's/^FROM[[:space:]]+([^[:space:]]+).*/\1/p' "$dockerfile")
if [ "$(printf '%s\n' "$want" | grep -c .)" -ne 1 ] || [[ $want != postgres:*@sha256:* ]]; then
	echo "$dockerfile: want exactly one FROM postgres:<tag>@sha256:<digest> line" >&2
	exit 1
fi

found=$(sed -nE 's/^[[:space:]]*image:[[:space:]]*(postgres[:@][^[:space:]]*).*/\1/p' "$workflow")
if [ -z "$found" ]; then
	echo "$workflow: no Postgres service image found" >&2
	exit 1
fi

status=0
while IFS= read -r got; do
	if [ "$got" != "$want" ]; then
		echo "$workflow: Postgres service image $got doesn't match $dockerfile's $want; copy the Dockerfile's pin to ci.yml" >&2
		status=1
	fi
done <<<"$found"
[ "$status" -eq 0 ] && echo "Postgres service image matches $dockerfile: $want"
exit "$status"
