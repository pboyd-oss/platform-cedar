FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /cedar-sidecar ./cmd/cedar-sidecar

FROM scratch
COPY --from=builder /cedar-sidecar /cedar-sidecar
COPY policies/ /policies/
COPY schema/ /schema/
ENTRYPOINT ["/cedar-sidecar"]
