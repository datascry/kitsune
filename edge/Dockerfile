# edge/Dockerfile — multi-stage build for the Kitsune edge service.
# Compiles a static binary on golang:alpine, ships it on a distroless-style scratch image.

FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /edge ./cmd/edge

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /edge /edge
EXPOSE 8081
USER nonroot:nonroot
ENTRYPOINT ["/edge"]
