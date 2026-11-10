# Builds cmd/conformance-federation-trust-anchor. Build context is the
# repo root since the binary needs the whole module — see
# conformance/server/Dockerfile's identical pattern.
FROM golang:1.27@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/conformance-federation-trust-anchor ./cmd/conformance-federation-trust-anchor

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/conformance-federation-trust-anchor /conformance-federation-trust-anchor
ENTRYPOINT ["/conformance-federation-trust-anchor"]
