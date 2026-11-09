# Never built. ci.yml's sqlstore job and mutation.yml run this image as
# a service container, and Dependabot doesn't update a workflow's service
# images, but it does update a Dockerfile's (the docker ecosystem in
# .github/dependabot.yml). So the pin lives here too, and ci.yml's lint
# job (.github/scripts/check-postgres-pin.sh) fails until they all
# match: when Dependabot moves this digest, copy it to both workflows.
FROM postgres:17-alpine@sha256:266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b
# The image's server itself runs as postgres (its entrypoint drops root);
# naming it here only keeps this never-built file from defaulting to root.
USER postgres
