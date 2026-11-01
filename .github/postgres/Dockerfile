# Never built. ci.yml's sqlstore job runs this image as a service
# container, and Dependabot doesn't update a workflow's service images,
# but it does update a Dockerfile's (the docker ecosystem in
# .github/dependabot.yml). So the pin lives here too, and ci.yml's lint
# job (.github/scripts/check-postgres-pin.sh) fails until the two match:
# when Dependabot moves this digest, copy it to ci.yml.
FROM postgres:17-alpine@sha256:266d3c257594e195b309ae9d1805e54c788f1d7b375f56bf6c367aac6c917e7b
