# evaders/slow-http/Dockerfile — build the HTTP/1.1 slow-header (slowloris) hold evader.
# Compiles the raw slow-header client; run it on the kitsune network against the edge.
FROM golang:1.26-alpine
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN go build -o /slowhttp .
ENTRYPOINT ["/slowhttp"]
