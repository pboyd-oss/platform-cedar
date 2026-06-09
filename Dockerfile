FROM harbor.tuxgrid.com/docker.io/golang:1.26-alpine AS builder
ARG PLATFORM_CA_B64=""
RUN [ -z "$PLATFORM_CA_B64" ] || (printf '%s' "$PLATFORM_CA_B64" | base64 -d > /usr/local/share/ca-certificates/platform-build.crt && update-ca-certificates 2>/dev/null)
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /cedar-sidecar ./cmd/cedar-sidecar

FROM scratch
COPY --from=builder /cedar-sidecar /cedar-sidecar
COPY schema/ /schema/
ENTRYPOINT ["/cedar-sidecar"]
