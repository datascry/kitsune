# evaders/pow/Dockerfile — the PoW arms-race testbed: the BLUE gate + the RED native solver in one image.
# Builds both binaries; CMD selects the gate (default) or the solver via the compose service command.

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY evaders/pow/ .
RUN go build -o /pow-gate ./cmd/pow-gate && go build -o /pow-solver ./cmd/pow-solver

FROM alpine:3.20
COPY --from=build /pow-gate /pow-gate
COPY --from=build /pow-solver /pow-solver
# Default to the gate; the solver service overrides the entrypoint.
ENTRYPOINT ["/pow-gate"]
