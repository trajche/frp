# ACME / Let's Encrypt Automatic TLS Certificates

*Alpha feature added in v0.62.0*

The ACME feature enables frp server to automatically obtain and manage TLS certificates from Let's Encrypt (or other ACME-compatible CAs). This allows HTTPS proxies and the dashboard to serve traffic with valid, automatically-renewed certificates without manual configuration.

> **Note**: ACME is an Alpha stage feature. Its configuration methods and functionality may be adjusted in subsequent versions. Test thoroughly before using in production environments.

## Requirements

- **Port 80 must be accessible**: HTTP-01 challenge requires the ACME CA to reach your server on port 80
- **Valid domain names**: Domains must resolve to your frp server's public IP
- **No wildcard certificates**: HTTP-01 challenge does not support wildcard certificates (`*.example.com`)

## Enabling ACME

Since ACME is currently an alpha feature, you need to enable it with feature gates:

```toml
# frps.toml
featureGates = { ACME = true }

acme.enable = true
acme.email = "admin@example.com"
acme.acceptTOS = true
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `acme.enable` | bool | `false` | Enable ACME certificate management |
| `acme.email` | string | required | Email for ACME account registration and expiry notifications |
| `acme.acceptTOS` | bool | `false` | Accept the CA's Terms of Service (required) |
| `acme.storagePath` | string | `~/.frp/acme` | Directory to store certificates and account data |
| `acme.caEndpoint` | string | Let's Encrypt Production | Custom ACME CA endpoint URL |
| `acme.enableForVhost` | bool | `true` | Auto-provision certificates for HTTPS vhost proxies |
| `acme.enableForDashboard` | bool | `false` | Enable ACME for the dashboard/web server |
| `acme.dashboardDomains` | []string | `[]` | Domains for dashboard certificate (required if `enableForDashboard` is true) |

## Basic Usage

### HTTPS Proxies

When ACME is enabled with `enableForVhost = true` (the default), certificates are automatically obtained for HTTPS proxy domains:

```toml
# frps.toml
bindAddr = "0.0.0.0"
bindPort = 7000
vhostHTTPPort = 80
vhostHTTPSPort = 443

featureGates = { ACME = true }

acme.enable = true
acme.email = "admin@example.com"
acme.acceptTOS = true
```

```toml
# frpc.toml
serverAddr = "your-server.com"
serverPort = 7000

[[proxies]]
name = "web"
type = "https"
customDomains = ["app.example.com"]
[proxies.plugin]
type = "https2http"
localAddr = "127.0.0.1:8080"
```

When a client connects to `https://app.example.com`, frp will:
1. Automatically obtain a certificate from Let's Encrypt
2. Serve the HTTPS traffic with the valid certificate
3. Automatically renew the certificate before expiry

### Dashboard with ACME

To enable ACME for the frps dashboard:

```toml
# frps.toml
webServer.addr = "0.0.0.0"
webServer.port = 7500
webServer.user = "admin"
webServer.password = "admin"

featureGates = { ACME = true }

acme.enable = true
acme.email = "admin@example.com"
acme.acceptTOS = true
acme.enableForDashboard = true
acme.dashboardDomains = ["dashboard.example.com"]
```

## Testing with Staging CA

For testing, use Let's Encrypt's staging environment to avoid rate limits:

```toml
acme.caEndpoint = "https://acme-staging-v02.api.letsencrypt.org/directory"
```

> **Note**: Staging certificates are not trusted by browsers. Switch to production (remove `caEndpoint` or set to empty string) once testing is complete.

## How It Works

1. **HTTP-01 Challenge**: When a certificate is needed, frp responds to ACME challenge requests at `/.well-known/acme-challenge/` on port 80
2. **On-Demand Issuance**: Certificates are obtained on the first TLS handshake for a domain, not at server startup
3. **Automatic Renewal**: Certificates are automatically renewed before expiry (typically 30 days before)
4. **Domain Tracking**: Domains are registered when proxies start and unregistered when they stop

## Storage

Certificates and account data are stored in the configured `storagePath` directory:

```
~/.frp/acme/
├── acme/                    # ACME account data
├── certificates/            # Obtained certificates
└── ocsp/                    # OCSP stapling data
```

Ensure this directory is:
- Writable by the frps process
- Backed up (contains your private keys)
- Persistent across restarts

## Limitations

- **No wildcard certificates**: HTTP-01 challenge cannot issue wildcard certificates. Use explicit domain names.
- **Port 80 required**: The HTTP-01 challenge requires port 80 to be accessible from the internet.
- **DNS must be configured**: Domain names must resolve to your frp server before certificate issuance.
- **Rate limits**: Let's Encrypt has [rate limits](https://letsencrypt.org/docs/rate-limits/). Use staging CA for testing.

## Troubleshooting

### Certificate not issued

1. Verify port 80 is accessible from the internet
2. Check that DNS resolves to your server's IP
3. Review frps logs for ACME-related errors
4. Test with staging CA first to avoid rate limits

### Challenge failed

```
acme: error: 403 :: urn:ietf:params:acme:error:unauthorized
```

This usually means the ACME CA couldn't reach your server on port 80. Ensure:
- No firewall blocking port 80
- `vhostHTTPPort = 80` is set
- Domain DNS points to your server

### Rate limited

```
acme: error: 429 :: urn:ietf:params:acme:error:rateLimited
```

You've hit Let's Encrypt rate limits. Wait and retry, or use staging CA for testing.

## Example Configurations

### Minimal HTTPS Proxy Setup

```toml
# frps.toml
bindPort = 7000
vhostHTTPPort = 80
vhostHTTPSPort = 443

featureGates = { ACME = true }

acme.enable = true
acme.email = "admin@example.com"
acme.acceptTOS = true
```

### Full Configuration

```toml
# frps.toml
bindAddr = "0.0.0.0"
bindPort = 7000
vhostHTTPPort = 80
vhostHTTPSPort = 443

webServer.addr = "0.0.0.0"
webServer.port = 7500
webServer.user = "admin"
webServer.password = "secure-password"

featureGates = { ACME = true }

acme.enable = true
acme.email = "admin@example.com"
acme.acceptTOS = true
acme.storagePath = "/var/lib/frps/acme"
acme.enableForVhost = true
acme.enableForDashboard = true
acme.dashboardDomains = ["frps-dashboard.example.com"]
```
