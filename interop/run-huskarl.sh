#!/usr/bin/env bash
# Runs the huskarl interop suite (interop/huskarl) against
# cmd/conformance-as: builds the binary and the harness, generates a
# fresh test CA, server and client certificates, writes the server
# configurations and client keys with interop/openid-client/setup.mjs
# (shared, so both suites drive identically configured servers), starts
# two conformance-as instances (FAPI 2.0 Security Profile with -mtls
# -ciba -client-credentials-grant, and Message Signing), runs every leg,
# and always stops the servers and deletes the work directory.
#
# Needs Go (the version in go.mod), Rust (cargo, 1.92+), Node.js 22.12+
# (setup.mjs only, no npm packages), curl and openssl. Ports default to
# 28443-28445; override with INTEROP_AS_PORT, INTEROP_AS_MTLS_PORT and
# INTEROP_AS_MS_PORT.
# INTEROP_KEEP_WORK_DIR=1 keeps the work directory (configs, keys,
# server logs) for debugging.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
harness="${repo_root}/interop/huskarl"
setup="${repo_root}/interop/openid-client/setup.mjs"

export INTEROP_AS_PORT="${INTEROP_AS_PORT:-28443}"
export INTEROP_AS_MTLS_PORT="${INTEROP_AS_MTLS_PORT:-28444}"
export INTEROP_AS_MS_PORT="${INTEROP_AS_MS_PORT:-28445}"
export INTEROP_HARNESS_PORT="${INTEROP_HARNESS_PORT:-28446}"

work_dir="$(mktemp -d)"
server_pids=()

cleanup() {
  local status=$?
  for pid in "${server_pids[@]+"${server_pids[@]}"}"; do
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  done
  if [[ "${INTEROP_KEEP_WORK_DIR:-}" == "1" ]]; then
    echo "interop: work directory kept at ${work_dir}"
  else
    rm -rf "${work_dir}"
  fi
  exit "${status}"
}
trap cleanup EXIT

dump_logs() {
  for log in "${work_dir}"/as-*.log; do
    echo "----- ${log##*/} -----"
    cat "${log}"
  done
}

echo "interop: building cmd/conformance-as"
(cd "${repo_root}" && go build -o "${work_dir}/conformance-as" ./cmd/conformance-as)

echo "interop: building the huskarl harness from its lockfile"
(cd "${harness}" && cargo build --locked)

echo "interop: generating a test CA, server and client certificates"
certs="${work_dir}/certs"
mkdir -p "${certs}"
openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
  -subj "/CN=FAPIgo interop test CA" \
  -keyout "${certs}/ca.key" -out "${certs}/ca.crt" 2>/dev/null
# RSA: conformance-as's TLS 1.2 cipher list is ECDHE_RSA only.
openssl req -nodes -newkey rsa:2048 -subj "/CN=localhost" \
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

node "${setup}" "${work_dir}"

echo "interop: starting conformance-as"
"${work_dir}/conformance-as" -config "${work_dir}/as-baseline.json" \
  -mtls -ciba -client-credentials-grant >"${work_dir}/as-baseline.log" 2>&1 &
server_pids+=("$!")
"${work_dir}/conformance-as" -config "${work_dir}/as-message-signing.json" \
  >"${work_dir}/as-message-signing.log" 2>&1 &
server_pids+=("$!")

for port in "${INTEROP_AS_PORT}" "${INTEROP_AS_MTLS_PORT}" "${INTEROP_AS_MS_PORT}"; do
  ready=""
  for _ in $(seq 1 50); do
    if curl -sf --cacert "${certs}/ca.crt" -o /dev/null "https://localhost:${port}/.well-known/openid-configuration"; then
      ready=1
      break
    fi
    sleep 0.2
  done
  if [[ -z "${ready}" ]]; then
    echo "interop: conformance-as did not come up on port ${port}" >&2
    dump_logs >&2
    exit 1
  fi
done

echo "interop: running the huskarl legs"
if ! (cd "${harness}" && cargo run --locked --quiet -- "${work_dir}"); then
  echo "interop: at least one leg failed; conformance-as logs follow" >&2
  dump_logs >&2
  exit 1
fi
