# Never built. interop/run-keycloak.sh runs this image with docker run,
# reading the reference from the FROM line below, so the pin lives in one
# place and Dependabot (the docker ecosystem in .github/dependabot.yml)
# can move it. A bump also updates the version in interop/README.md and
# the top-level README.
FROM quay.io/keycloak/keycloak:26.8.2@sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0
# The image runs Keycloak as an unprivileged user; naming it here only
# keeps this never-built file from defaulting to root.
USER 1000
