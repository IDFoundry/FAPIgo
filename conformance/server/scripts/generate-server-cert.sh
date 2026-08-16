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

echo "wrote conformance/server/certs/server.{crt,key} (gitignored — regenerate any time)"
