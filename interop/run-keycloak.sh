#!/usr/bin/env bash
# Runs the Keycloak interop suite: FAPIgo's client package
# (interop/fapigo-client) drives complete FAPI 2.0 flows against
# Keycloak (interop/keycloak). Builds the driver, generates a fresh test
# CA, server and client certificates, starts Keycloak in Docker (the
# image pinned in interop/keycloak/Dockerfile) over HTTPS with that CA,
# configures its realm and writes the driver's configuration
# (interop/keycloak/setup.mjs), starts the CIBA authentication-channel
# harness (interop/keycloak/harness.mjs), runs every leg, and always
# stops Keycloak and the harness and deletes the work directory.
#
# Needs Go (the version in interop/fapigo-client/go.mod), Docker,
# Node.js 22.12+ (no npm packages), curl and openssl. Ports default to
# 29543 (Keycloak), 29546 (the driver's CIBA notification endpoint) and
# 29547 (the harness); override with INTEROP_KC_PORT,
# INTEROP_DRIVER_PORT and INTEROP_HARNESS_PORT.
# INTEROP_KEEP_WORK_DIR=1 keeps the work directory (configs, keys,
# Keycloak's and the harness's logs) for debugging.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
keycloak_dir="${repo_root}/interop/keycloak"
driver_dir="${repo_root}/interop/fapigo-client"

export INTEROP_KC_PORT="${INTEROP_KC_PORT:-29543}"
export INTEROP_DRIVER_PORT="${INTEROP_DRIVER_PORT:-29546}"
export INTEROP_HARNESS_PORT="${INTEROP_HARNESS_PORT:-29547}"

# Keycloak calls back to the host (the harness, the driver's
# notification endpoint) as host.docker.internal. On Linux that name is
# the Docker bridge's gateway address, so those listeners bind to it;
# Docker Desktop forwards it to the host's loopback.
if [[ "$(uname -s)" == "Linux" ]]; then
  INTEROP_HOST_ADDR="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')"
else
  INTEROP_HOST_ADDR="127.0.0.1"
fi
export INTEROP_HOST_ADDR

image="$(awk '/^FROM /{print $2}' "${keycloak_dir}/Dockerfile")"
container="fapigo-interop-keycloak-$$"
work_dir="$(mktemp -d)"
harness_pid=""
container_started=""

cleanup() {
  local status=$?
  if [[ -n "${harness_pid}" ]]; then
    kill "${harness_pid}" 2>/dev/null || true
    wait "${harness_pid}" 2>/dev/null || true
  fi
  if [[ -n "${container_started}" ]]; then
    docker logs "${container}" >"${work_dir}/keycloak.log" 2>&1 || true
    docker rm -f "${container}" >/dev/null 2>&1 || true
  fi
  if [[ "${INTEROP_KEEP_WORK_DIR:-}" == "1" ]]; then
    echo "interop: work directory kept at ${work_dir}"
  else
    rm -rf "${work_dir}"
  fi
  exit "${status}"
}
trap cleanup EXIT

dump_logs() {
  echo "----- keycloak log -----"
  docker logs "${container}" 2>&1 | tail -n 200 || true
  echo "----- harness.log -----"
  cat "${work_dir}/harness.log" 2>/dev/null || true
}

echo "interop: building interop/fapigo-client"
(cd "${driver_dir}" && go build -o "${work_dir}/fapigo-client" .)

echo "interop: pulling ${image}"
docker pull --quiet "${image}" >/dev/null

echo "interop: generating a test CA, server and client certificates"
certs="${work_dir}/certs"
mkdir -p "${certs}"
openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 1 \
  -subj "/CN=FAPIgo interop test CA" \
  -keyout "${certs}/ca.key" -out "${certs}/ca.crt" 2>/dev/null
# One certificate for Keycloak's listener (reached as localhost) and
# the driver's CIBA notification endpoint (reached by Keycloak as
# host.docker.internal).
openssl req -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -subj "/CN=localhost" \
  -keyout "${certs}/server.key" -out "${certs}/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "${certs}/server.ext"
openssl x509 -req -days 1 -in "${certs}/server.csr" \
  -CA "${certs}/ca.crt" -CAkey "${certs}/ca.key" -CAcreateserial \
  -extfile "${certs}/server.ext" -out "${certs}/server.crt" 2>/dev/null
# Client certificates from the same CA: Keycloak's X.509 client
# authenticator is tls_client_auth (RFC 8705 §2.1), which needs a chain
# to a trusted CA, and its listener refuses a certificate it can't
# verify even where only the token binding uses it.
printf 'extendedKeyUsage=clientAuth\n' > "${certs}/client.ext"
for name in client-mtls client-ciba; do
  openssl req -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -subj "/CN=${name}" \
    -keyout "${certs}/${name}.key" -out "${certs}/${name}.csr" 2>/dev/null
  openssl x509 -req -days 1 -in "${certs}/${name}.csr" \
    -CA "${certs}/ca.crt" -CAkey "${certs}/ca.key" -CAcreateserial \
    -extfile "${certs}/client.ext" -out "${certs}/${name}.crt" 2>/dev/null
done

# What the container mounts: its listener's certificate and key and the
# CA, readable by the image's unprivileged user.
kc_certs="${work_dir}/keycloak-certs"
mkdir -p "${kc_certs}"
cp "${certs}/ca.crt" "${certs}/server.crt" "${certs}/server.key" "${kc_certs}/"
chmod 711 "${work_dir}"
chmod 755 "${kc_certs}"
chmod 644 "${kc_certs}"/*

KC_BOOTSTRAP_ADMIN_USERNAME="interop-admin"
KC_BOOTSTRAP_ADMIN_PASSWORD="$(openssl rand -hex 16)"
export KC_BOOTSTRAP_ADMIN_USERNAME KC_BOOTSTRAP_ADMIN_PASSWORD

echo "interop: starting Keycloak"
# start-dev: an in-memory database and no clustering, enough for a test.
# The trust store (the run's CA) verifies client certificates on the
# HTTPS listener (requested, not required) and the driver's notification
# endpoint's certificate for CIBA pings. The CIBA HTTP authentication
# channel posts each request to the harness.
docker run -d --name "${container}" \
  -p "127.0.0.1:${INTEROP_KC_PORT}:8443" \
  --add-host=host.docker.internal:host-gateway \
  -v "${kc_certs}:/etc/interop-certs:ro" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME -e KC_BOOTSTRAP_ADMIN_PASSWORD \
  "${image}" start-dev \
  --hostname="https://localhost:${INTEROP_KC_PORT}" \
  --https-port=8443 \
  --https-certificate-file=/etc/interop-certs/server.crt \
  --https-certificate-key-file=/etc/interop-certs/server.key \
  --https-client-auth=request \
  --truststore-paths=/etc/interop-certs/ca.crt \
  --spi-ciba-auth-channel--ciba-http-auth-channel--http-authentication-channel-uri="http://host.docker.internal:${INTEROP_HARNESS_PORT}/channel" \
  >/dev/null
container_started=1

ready=""
for _ in $(seq 1 120); do
  if curl -sf --cacert "${certs}/ca.crt" -o /dev/null "https://localhost:${INTEROP_KC_PORT}/realms/master/.well-known/openid-configuration"; then
    ready=1
    break
  fi
  sleep 1
done
if [[ -z "${ready}" ]]; then
  echo "interop: Keycloak did not come up on port ${INTEROP_KC_PORT}" >&2
  dump_logs >&2
  exit 1
fi

echo "interop: configuring the realm"
export NODE_EXTRA_CA_CERTS="${certs}/ca.crt"
if ! node "${keycloak_dir}/setup.mjs" "${work_dir}"; then
  dump_logs >&2
  exit 1
fi

echo "interop: starting the CIBA authentication-channel harness"
node "${keycloak_dir}/harness.mjs" >"${work_dir}/harness.log" 2>&1 &
harness_pid="$!"
ready=""
for _ in $(seq 1 50); do
  if grep -q 'listening' "${work_dir}/harness.log"; then
    ready=1
    break
  fi
  sleep 0.2
done
if [[ -z "${ready}" ]]; then
  echo "interop: the harness did not start" >&2
  dump_logs >&2
  exit 1
fi

echo "interop: running the FAPIgo client legs"
if ! "${work_dir}/fapigo-client" -config "${work_dir}/driver.json"; then
  echo "interop: at least one leg failed; Keycloak's and the harness's logs follow" >&2
  dump_logs >&2
  exit 1
fi
