# evaders/azuretls/Dockerfile — one-shot container for the azuretls-client TLS/JA3+H2 forger.
# Builds the Go binary and drives one Chrome-fingerprinted (TLS only) request at the live edge.

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY evaders/azuretls/ .
RUN go build -o /azuretls .

FROM alpine:3.20
COPY --from=build /azuretls /azuretls
ENTRYPOINT ["/azuretls"]
