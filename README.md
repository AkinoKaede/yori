# yori - Your Outbound Relay Integrator

A relay proxy that dynamically fetches outbounds from multiple subscription sources, generates user credentials, and provides HTTP subscription endpoints.

## Features

- 🔄 **Multi-Subscription Support**: Fetch from multiple subscription sources (HTTP URLs or local files)
- 🎯 **Advanced Filtering**: Regex-based filtering, type filtering, exclusions with inversion support
- ✏️ **Flexible Rewriting**: Rename nodes with regex capture groups, remove emojis, rewrite multiplex/dialer/TLS configs
- 🔐 **Automatic TLS**: ACME support (Let's Encrypt, ZeroSSL) with DNS-01 challenge for wildcard certificates
- 📡 **HTTP Subscriptions**: Provide base64 and sing-box format subscriptions to downstream clients
- ♻️ **Hot Reload**: Automatic scheduled reload + manual reload via SIGHUP signal
- 🧭 **User-Based Routing**: Each outbound gets a unique user with credentials

## Architecture

```
┌─────────────────┐
│  Subscriptions  │
│  (HTTP/File)    │
└────────┬────────┘
         │ Fetch
         ▼
┌─────────────────┐
│Process Pipeline │
│ • Filter        │
│ • Rename        │
│ • Rewrite       │
└────────┬────────┘
         │ Merge
         ▼
┌─────────────────┐
│ User Generation │
└────────┬────────┘
         │
         ▼
┌──────────────────────────────┐     ┌──────────────┐
│          yori engine         │────▶│ HTTP Server  │
│ • inbound (hysteria2)        │     │ /sub/base64  │
│ • outbound manager + routing │     │ /sub/sing-box│
└──────────────────────────────┘     └──────────────┘
```

## Installation

### Build from Source

```bash
cd yori
make build
```

## Configuration

Create a `config.yaml` file (see [config.example.yaml](config.example.yaml) for full examples):

```yaml
subscriptions:
  - name: "provider-1"
    url: "https://example.com/sub?token=xxx"
    update_interval: "1h"
    process:
      - filter_type: ["shadowsocks", "vmess"]
      - remove_emoji: true

reload_interval: "30m"

http:
  listen: "0.0.0.0"
  port: 8080

hysteria2:
  listen: "::"
  ports: [443]
  up_mbps: 200
  down_mbps: 200
  
  public:
    server: "relay.example.com"
    ports: [443]
  
  tls:
    acme:
      domain: ["relay.example.com"]
      email: "admin@example.com"
  
  obfs:
    type: "salamander"
    password: "change-this"
```

### Configuration Sections

#### Subscriptions

Each subscription supports:

- **`url`**: HTTP(S) URL or `file://` path or relative path
- **`user_agent`**: Custom User-Agent header (optional)
- **`update_interval`**: How often to fetch updates (e.g., `30m`, `1h`, `24h`)
- **`process`**: Array of processing steps applied in order

#### Process Pipeline

Each process step can include:

- **`filter`**: Array of regex patterns to match node names/tags
- **`exclude`**: Array of regex patterns to exclude
- **`filter_type`**: Array of protocol types (`shadowsocks`, `vmess`, `trojan`, `hysteria2`, etc.)
- **`exclude_type`**: Array of protocol types to exclude
- **`invert`**: Invert the match result (boolean)
- **`remove`**: Remove matched nodes instead of processing (boolean)
- **`rename`**: Map of regex patterns to replacements (supports `$1`, `$2` capture groups)
- **`remove_emoji`**: Strip emoji characters (boolean)
- **`rewrite_multiplex`**: Rewrite multiplex configuration (object)
- **`rewrite_dialer_options`**: Rewrite dialer options (object)
- **`rewrite_packet_encoding`**: Rewrite packet encoding (string)
- **`rewrite_utls`**: Rewrite uTLS configuration (object)

#### TLS Configuration

**ACME (Automatic):**

```yaml
tls:
  acme:
    domain: ["example.com", "*.example.com"]
    email: "admin@example.com"
    provider: "letsencrypt"  # or "zerossl"
    data_directory: "./data/acme"
    
    # Optional: DNS-01 challenge
    dns01_challenge:
      provider: "cloudflare"  # or "alidns"
      api_token: "${CLOUDFLARE_API_TOKEN}"
```

**Manual Certificates:**

```yaml
tls:
  certificate_path: "/path/to/cert.pem"
  key_path: "/path/to/key.pem"
```

## Usage

### Start the Service

```bash
./yori -c config.yaml
```

### Reload Configuration

**Manual reload:**

```bash
# Find the process ID
pidof yori

# Send SIGHUP signal
kill -HUP <pid>
```

**Automatic reload:**

The service automatically reloads based on `reload_interval` and individual subscription `update_interval` settings.

### Systemd Service

Create `/etc/systemd/system/yori.service`:

```ini
[Unit]
Description=yori Service
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/yori -c /etc/yori/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now yori
sudo systemctl status yori
```

Reload configuration:

```bash
sudo systemctl reload yori
```

## Subscription Endpoints

### Base64 Format

```bash
curl http://your-server:8080/sub/base64
```

Returns base64-encoded `hysteria2://` share links:

```
hysteria2://user1:pass1@relay.example.com:443?sni=relay.example.com&alpn=h3&obfs=salamander&obfs-password=your-strong-obfs-password#outbound1
hysteria2://user2:pass2@relay.example.com:443?sni=relay.example.com&alpn=h3&obfs=salamander&obfs-password=your-strong-obfs-password#outbound2
```

Import this URL directly into compatible clients (ShadowRocket, Clash, etc.)

### sing-box Format

```bash
curl http://your-server:8080/sub/sing-box
```

Returns JSON configuration:

```json
{
  "outbounds": [
    {
      "type": "hysteria2",
      "tag": "outbound1",
      "server": "relay.example.com",
      "server_port": 443,
      "password": "generated-password",
      "tls": {
        "enabled": true,
        "server_name": "relay.example.com"
      },
      "obfs": {
        "type": "salamander",
        "password": "your-strong-obfs-password"
      }
    }
  ]
}
```

## User Generation

Each outbound from subscriptions generates one Hysteria2 user:

- **Username**: Outbound `tag` (after processing/renaming)
- **Password**: `SHA256(tag + salt)[:32]` - stable across reloads if tag unchanged
- **Routing**: Traffic from each user routes exclusively to their designated outbound

## Process Pipeline Examples

### Remove Expired Nodes

```yaml
process:
  - exclude: [".*(?i)(expired|过期).*"]
```

### Keep Only Specific Regions

```yaml
process:
  - filter: [".*(?i)(hong kong|japan|singapore).*"]
```

### Standardize Node Names

```yaml
process:
  - remove_emoji: true
    rename:
      "^🇺🇸\\s*(.*)$": "US-$1"
      "^🇯🇵\\s*(.*)$": "JP-$1"
      "^\\[Premium\\]\\s*(.*)$": "$1"
```

### Enable Multiplex for All Nodes

```yaml
process:
  - filter_type: ["shadowsocks", "vmess", "trojan"]
    rewrite_multiplex:
      enabled: true
      protocol: "smux"
      max_connections: 4
```

## Troubleshooting

### ACME Certificate Issues

**Port 80/443 unavailable:**

Use DNS-01 challenge:

```yaml
acme:
  dns01_challenge:
    provider: "cloudflare"
    api_token: "your-token"
```

**Check certificate status:**

```bash
ls -lah ./data/acme/
```

## License

This repository is licensed under [GNU General Public License v3.0 only](./LICENSE).

SPDX-License-Identifier: [GPL-3.0-or-later](https://spdx.org/licenses/GPL-3.0-only.html)

## Credits

- [sing-box](https://github.com/SagerNet/sing-box) - Universal proxy platform
- [serenity](https://github.com/SagerNet/serenity) - Subscription service inspiration
- [Hysteria2](https://v2.hysteria.network/) - Modern proxy protocol

## Contributing

Pull requests welcome! Please ensure:

1. Code follows existing style
2. All tests pass
3. Documentation updated
4. GPL-3.0 license header on new files

## Support

- Issues: [GitHub Issues](https://github.com/AkinoKaede/yori/issues)
- Discussions: [GitHub Discussions](https://github.com/AkinoKaede/yori/discussions)
