#!/usr/bin/env bash
# Generates one throwaway self-signed cert/key pair for conformance-as to
# serve TLS with under docker-compose.
#
# No CA, no trust-store wiring: the OIDF conformance suite's outbound
# HTTP client (net.openid.conformance.condition.AbstractCondition
# .createHttpClient) installs a trust-all X509TrustManager and a
# NoopHostnameVerifier for every call it makes to the implementation
# under test, so a self-signed cert is sufficient by design, not as a
# shortcut. See conformance/server/scripts/README.md.
#
# The SAN list covers every hostname this binary might be reached as
# across the setups documented in that README (docker-compose service
# names, plus localhost/host.docker.internal for running conformance-as
# directly on the host).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p certs

openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout certs/server.key -out certs/server.crt -days 3650 \
  -subj "/CN=conformance-as" \
  -addext "subjectAltName=DNS:conformance-as-baseline,DNS:conformance-as-message-signing,DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1"

# openssl's default 0600 on the key is only readable by the host user
# that ran this script — but the container reads it as the distroless
# nonroot image's own fixed UID (65532), a different user entirely, via
# a bind mount (docker-compose.yml). Docker preserves host permission
# bits verbatim on Linux, so 0600 means "permission denied" in the
# container on a real Linux host — silently not enforced the same way
# under Docker Desktop's bind-mount handling on macOS, which is why
# this only ever surfaced on a Linux CI runner. Harmless to widen:
# this is an explicitly throwaway, non-secret self-signed dev key (see
# this file's header comment on why no real trust/CA is involved).
chmod 644 certs/server.key

echo "wrote conformance/server/certs/server.{crt,key} (gitignored — regenerate any time)"
