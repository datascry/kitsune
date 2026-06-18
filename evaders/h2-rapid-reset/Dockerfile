# evaders/h2-rapid-reset/Dockerfile — build the HTTP/2 Rapid Reset (CVE-2023-44487) flood evader.
# Compiles the raw-framer attack client; run it on the kitsune network against the edge.
FROM golang:1.26-alpine
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN go build -o /h2rr .
ENTRYPOINT ["/h2rr"]
