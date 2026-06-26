# arena/Dockerfile — multi-stage build for the public arena challenge-gate.
# Builds the gate (which imports the local evaders/pow module via a replace) on golang:alpine; ships distroless.

FROM golang:1.26-alpine AS build
WORKDIR /src
# The arena module replaces github.com/datascry/kitsune/evaders/pow with ../evaders/pow, so both are copied.
COPY evaders/pow/ ./evaders/pow/
COPY arena/ ./arena/
WORKDIR /src/arena
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /arena-gate ./cmd/arena-gate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /arena-gate /arena-gate
EXPOSE 8095
USER nonroot:nonroot
ENTRYPOINT ["/arena-gate"]
