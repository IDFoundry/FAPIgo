# Builds cmd/conformance-federation-trust-anchor. Build context is the
# repo root since the binary needs the whole module — see
# conformance/server/Dockerfile's identical pattern.
FROM golang:1.26@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/conformance-federation-trust-anchor ./cmd/conformance-federation-trust-anchor

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/conformance-federation-trust-anchor /conformance-federation-trust-anchor
ENTRYPOINT ["/conformance-federation-trust-anchor"]
