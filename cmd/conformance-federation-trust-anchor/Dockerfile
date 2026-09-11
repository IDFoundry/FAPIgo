# Builds cmd/conformance-federation-trust-anchor. Build context is the
# repo root since the binary needs the whole module — see
# conformance/server/Dockerfile's identical pattern.
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/conformance-federation-trust-anchor ./cmd/conformance-federation-trust-anchor

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/conformance-federation-trust-anchor /conformance-federation-trust-anchor
ENTRYPOINT ["/conformance-federation-trust-anchor"]
