# evaders/chain-mitm/Dockerfile — build the uTLS MITM front (forges a browser TLS+H2 handshake to the edge).
# A real browser proxies through it; the edge sees a forged network layer + a real JS runtime (the chain).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /front .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /front /front
EXPOSE 8444
USER nonroot:nonroot
ENTRYPOINT ["/front"]
