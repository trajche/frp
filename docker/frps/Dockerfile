# Build stage - build on target platform directly
FROM golang:1.24-bookworm AS builder

WORKDIR /src

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build frps binary for current platform
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /frps ./cmd/frps

# Runtime stage
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="frps" \
    org.opencontainers.image.description="frp server with ACME support" \
    org.opencontainers.image.source="https://github.com/trajche/frp" \
    org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /frps /usr/bin/frps

# Copy default config
COPY conf/frps.toml /etc/frp/frps.toml

# Create directory for ACME certificates
RUN mkdir -p /var/lib/frps/acme

# Expose common ports
EXPOSE 7000 7500 80 443

ENTRYPOINT ["/usr/bin/frps"]
CMD ["-c", "/etc/frp/frps.toml"]
