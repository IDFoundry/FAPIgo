# Builds cmd/conformance-as for the docker-compose setup in this
# directory. Build context is the repo root (../.. from here) since the
# binary needs the whole module.
FROM golang:1.27@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/conformance-as ./cmd/conformance-as

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/conformance-as /conformance-as
ENTRYPOINT ["/conformance-as"]
