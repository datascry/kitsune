# evaders/os-spoof/Dockerfile — userspace-TCP SYN forger (Windows option order) + uTLS.
# Needs NET_RAW (AF_PACKET) + NET_ADMIN (drop kernel RSTs). Run on the kitsune network against the edge.
FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod ./
COPY *.go ./
RUN go mod tidy && go build -o /os-spoof .

FROM alpine:3.20
RUN apk add --no-cache iptables iputils libpcap
COPY --from=build /os-spoof /os-spoof
ENTRYPOINT ["/os-spoof"]
