# SecID-Server-API

Self-hosted SecID resolver — run your own API server locally, in Docker, or on internal infrastructure.

**For the hosted public service, see [SecID-Service](https://github.com/CloudSecurityAlliance/SecID-Service)** (Cloudflare Worker, live at [secid.cloudsecurityalliance.org](https://secid.cloudsecurityalliance.org/)).

## Why Self-Host?

- **Private data** — add internal advisories, controls, or capabilities that can't be public
- **Latency** — serve from your own infrastructure, no external dependency
- **Air-gapped** — works without internet after initial registry sync
- **Federation** — register your resolver in the SecID ecosystem so others can discover it
- **Customization** — extend the resolver, add auth, integrate with internal systems

## Two Implementations

| Implementation | Language | Best for |
|---------------|----------|----------|
| **Python** | Python 3.10+ | Quick start, reference implementation, easy to extend |
| **TypeScript** | Node.js 22+ | Closest to production SecID-Service, higher throughput |

Both serve the same API, pass the same test suite, and support the same storage backends.

## Quick Start (Python)

```bash
# Clone this repo and the registry
git clone https://github.com/CloudSecurityAlliance/SecID-Server-API.git
git clone https://github.com/CloudSecurityAlliance/SecID.git

# Install and run
cd SecID-Server-API/python
pip install -r requirements.txt
python secid_server.py --registry ../../SecID/registry

# Test it
curl "http://localhost:8000/api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228"
```

## Quick Start (Docker)

```bash
git clone https://github.com/CloudSecurityAlliance/SecID.git

docker run -p 8000:8000 \
  -v ./SecID/registry:/data/registry \
  ghcr.io/cloudsecurityalliance/secid-server-api
```

## Storage Backends

Registry data is read-only at runtime. Load it once, serve from cache. The entire registry is ~5-10MB — fits in any backend trivially.

| Backend | Config | Best for |
|---------|--------|----------|
| **In-memory** | Default | Development, single container |
| **Redis / Valkey** | `--storage redis --redis-url redis://...` | Multi-container, shared cache |
| **Memcached** | `--storage memcached --memcached-url ...` | If you already run memcached |
| **SQLite** | `--storage sqlite --sqlite-path ./secid.db` | Single-node production, no external deps |

## Loading Strategies

| Strategy | Flag | Behavior |
|----------|------|----------|
| **Lazy** (default) | `--load lazy` | First request per key reads JSON, caches it. Instant startup. |
| **Bulk** | `--load bulk` | Startup: load all entries into cache. Predictable latency. |
| **Update** | `--load update` | After `git pull`: reload only changed files since last sync. |

Update loading uses git to detect changes:

```bash
# Pull latest registry data
cd /path/to/SecID && git pull

# Tell the server to reload changes
curl -X POST http://localhost:8000/admin/reload
```

Or run with `--watch` to auto-detect file changes.

## API Compatibility

Same API as the public service at secid.cloudsecurityalliance.org:

```
GET /api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228
```

Same response format, same status values (`found`, `corrected`, `related`, `not_found`, `error`). Any SecID client (SDK, plugin, MCP) works with any SecID server.

### MCP Endpoint

```
/mcp
```

Point any MCP client at your self-hosted server. Same three tools: `resolve`, `lookup`, `describe`.

## Private Registry Data

Merge public + private registry data:

```bash
python secid_server.py \
  --registry /data/public/SecID/registry \
  --registry /data/private/internal-registry
```

Private entries override public ones for the same namespace. Your internal advisories, controls, and capabilities supplement the public registry.

## Syncing Registry Data

The registry is a git repo. Git solves the sync problem:

```bash
# Initial clone
git clone https://github.com/CloudSecurityAlliance/SecID.git

# Update
cd SecID && git pull

# What changed?
git log --oneline --stat HEAD~5..HEAD -- registry/
```

No changelog file needed — `git log` and `git diff` tell you exactly what changed, when, and why.

## All SecID Repos

| Repo | What it is |
|------|-----------|
| **[SecID](https://github.com/CloudSecurityAlliance/SecID)** | Specification + registry data |
| **[SecID-Service](https://github.com/CloudSecurityAlliance/SecID-Service)** | Cloudflare-hosted production service |
| **[SecID-Server-API](https://github.com/CloudSecurityAlliance/SecID-Server-API)** (this repo) | Self-hosted resolver (Python, TypeScript, Docker) |
| **[SecID-Client-SDK](https://github.com/CloudSecurityAlliance/SecID-Client-SDK)** | Client libraries (Python, TypeScript, Go) |

## License

[CC0 1.0 Universal](LICENSE) — Public Domain Dedication
