# frps Docker Image

Docker image for frp server with ACME/Let's Encrypt support.

## Quick Start

```bash
# Build and run with docker-compose
cd docker/frps
docker-compose up -d
```

## Build Manually

```bash
# From repository root
docker build -t trajche/frps:latest -f docker/frps/Dockerfile .

# Multi-architecture build
docker buildx build --platform linux/amd64,linux/arm64 \
  -t trajche/frps:latest -f docker/frps/Dockerfile --push .
```

## Run

```bash
docker run -d --name frps \
  -p 7000:7000 \
  -p 7500:7500 \
  -p 80:80 \
  -p 443:443 \
  -v $(pwd)/frps.toml:/etc/frp/frps.toml:ro \
  -v frps-acme:/var/lib/frps/acme \
  trajche/frps:latest
```

## Configuration

Edit `frps.toml` before starting. Key settings for ACME:

```toml
# Enable ACME feature
featureGates = { ACME = true }

acme.enable = true
acme.email = "your-email@example.com"
acme.acceptTOS = true
```

## Ports

| Port | Description |
|------|-------------|
| 7000 | frp bind port |
| 7500 | Dashboard |
| 80   | HTTP vhost (required for ACME) |
| 443  | HTTPS vhost |

## Volumes

| Path | Description |
|------|-------------|
| `/etc/frp/frps.toml` | Configuration file |
| `/var/lib/frps/acme` | ACME certificates (persist this!) |
