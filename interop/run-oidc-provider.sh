#!/usr/bin/env bash
# Runs the oidc-provider interop suite: FAPIgo's client package
# (interop/fapigo-client) drives complete FAPI 2.0 flows against
# oidc-provider (interop/oidc-provider). Builds the driver, generates a
# fresh test CA, server and client certificates, writes the provider's
# client registrations and the driver's configuration, starts the
# provider, runs every leg, and always stops the provider and deletes
# the work directory.
#
# Needs Go (the version in interop/fapigo-client/go.mod), Node.js
# 22.12+, npm, curl and openssl. Ports default to 29443, 29444 (the
# provider's mTLS endpoint aliases) and 29446 (the driver's CIBA
# notification endpoint); override with INTEROP_OP_PORT,
# INTEROP_OP_MTLS_PORT and INTEROP_DRIVER_PORT.
# INTEROP_KEEP_WORK_DIR=1 keeps the work directory (configs, keys,
# provider log) for debugging.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
provider_dir="${repo_root}/interop/oidc-provider"
driver_dir="${repo_root}/interop/fapigo-client"

export INTEROP_OP_PORT="${INTEROP_OP_PORT:-29443}"
export INTEROP_OP_MTLS_PORT="${INTEROP_OP_MTLS_PORT:-29444}"
export INTEROP_DRIVER_PORT="${INTEROP_DRIVER_PORT:-29446}"

work_dir="$(mktemp -d)"
server_pid=""

cleanup() {
  local status=$?
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
  fi
  if [[ "${INTEROP_KEEP_WORK_DIR:-}" == "1" ]]; then
    echo "interop: work directory kept at ${work_dir}"
  else
    rm -rf "${work_dir}"
  fi
  exit "${status}"
}
trap cleanup EXIT

dump_log() {
  echo "----- oidc-provider.log -----"
  cat "${work_dir}/oidc-provider.log"
}

echo "interop: building interop/fapigo-client"
(cd "${driver_dir}" && go build -o "${work_dir}/fapigo-client" .)

echo "interop: installing the provider's pinned dependencies"
(cd "${provider_dir}" && npm ci --ignore-scripts --no-audit --no-fund)

echo "interop: generating a test CA, server and client certificates"
certs="${work_dir}/certs"
mkdir -p "${certs}"
openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 1 \
  -subj "/CN=FAPIgo interop test CA" \
  -keyout "${certs}/ca.key" -out "${certs}/ca.crt" 2>/dev/null
# One localhost certificate for the provider's listeners and the
# driver's CIBA notification endpoint.
openssl req -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -subj "/CN=localhost" \
  -keyout "${certs}/server.key" -out "${certs}/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "${certs}/server.ext"
openssl x509 -req -days 1 -in "${certs}/server.csr" \
  -CA "${certs}/ca.crt" -CAkey "${certs}/ca.key" -CAcreateserial \
  -extfile "${certs}/server.ext" -out "${certs}/server.crt" 2>/dev/null
# Self-signed client certificates: self_signed_tls_client_auth and
# certificate binding compare thumbprints, not chains.
for name in client-mtls client-ciba; do
  openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 1 \
    -subj "/CN=${name}" -addext "extendedKeyUsage=clientAuth" \
    -keyout "${certs}/${name}.key" -out "${certs}/${name}.crt" 2>/dev/null
done

node "${provider_dir}/setup.mjs" "${work_dir}"

echo "interop: starting oidc-provider"
# The provider sends CIBA pings to the driver's endpoint, whose
# certificate chains to the run's test CA.
NODE_EXTRA_CA_CERTS="${certs}/ca.crt" node "${provider_dir}/server.mjs" "${work_dir}" \
  >"${work_dir}/oidc-provider.log" 2>&1 &
server_pid="$!"

for port in "${INTEROP_OP_PORT}" "${INTEROP_OP_MTLS_PORT}"; do
  ready=""
  for _ in $(seq 1 50); do
    if curl -sf --cacert "${certs}/ca.crt" -o /dev/null "https://localhost:${port}/.well-known/openid-configuration"; then
      ready=1
      break
    fi
    sleep 0.2
  done
  if [[ -z "${ready}" ]]; then
    echo "interop: oidc-provider did not come up on port ${port}" >&2
    dump_log >&2
    exit 1
  fi
done

echo "interop: running the FAPIgo client legs"
if ! "${work_dir}/fapigo-client" -config "${work_dir}/driver.json"; then
  echo "interop: at least one leg failed; the oidc-provider log follows" >&2
  dump_log >&2
  exit 1
fi
