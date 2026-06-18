# evaders/go-tls/Dockerfile — one-shot container for the forged-TLS (uTLS) evader.
# Builds the Go binary and drives one HTTP/2 Chrome-fingerprinted request at the live edge.

FROM golang:1.23-alpine AS build
WORKDIR /src
COPY evaders/go-tls/ .
RUN go build -o /go-tls ./cmd/go-tls

FROM alpine:3.20
COPY --from=build /go-tls /go-tls
ENTRYPOINT ["/go-tls"]
