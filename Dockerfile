FROM golang:1.27-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
RUN go test ./...
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /registryless ./cmd/registryless

FROM scratch
LABEL org.opencontainers.image.title="registryless" \
      org.opencontainers.image.source="https://github.com/codemowers/registryless" \
      codemowers.io/registryless.component="daemon"
COPY --from=build /registryless /registryless
ENTRYPOINT ["/registryless"]
