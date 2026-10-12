# Builds cmd/conformance-as for the docker-compose setup in this
# directory. Build context is the repo root (../.. from here) since the
# binary needs the whole module.
FROM golang:1.27@sha256:e432b43af23a9328d56a7c499be0476810aa344acbcf65fc7c455d4ff5a40602 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/conformance-as ./cmd/conformance-as

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/conformance-as /conformance-as
ENTRYPOINT ["/conformance-as"]
