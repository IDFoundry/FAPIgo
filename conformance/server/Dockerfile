# Builds cmd/conformance-as for the docker-compose setup in this
# directory. Build context is the repo root (../.. from here) since the
# binary needs the whole module.
FROM golang:1.25 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/conformance-as ./cmd/conformance-as

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/conformance-as /conformance-as
ENTRYPOINT ["/conformance-as"]
