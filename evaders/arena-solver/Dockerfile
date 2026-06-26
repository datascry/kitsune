# evaders/arena-solver/Dockerfile — the browserless arena CAPTCHA solver (red side; owned gates only).
# Builds the static solver; run it one-shot against Kitsune's own edge/detector to beat every arena gate.

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY evaders/arena-solver/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /arena-solver .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /arena-solver /arena-solver
USER nonroot:nonroot
ENTRYPOINT ["/arena-solver"]
