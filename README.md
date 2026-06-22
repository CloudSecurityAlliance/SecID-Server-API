# SecID-Server-API

Self-hosted SecID resolver — run your own API server locally, in Docker, or on internal infrastructure.

**For the hosted public service, see [SecID-Service](https://github.com/CloudSecurityAlliance/SecID-Service)** (Cloudflare Worker, live at [secid.cloudsecurityalliance.org](https://secid.cloudsecurityalliance.org/)).

## Why Self-Host?

- **Private data** — add internal advisories, controls, or capabilities that can't be public
- **Latency** — serve from your own infrastructure, no external dependency
- **Air-gapped** — works without internet after initial registry sync
- **Federation** — register your resolver in the SecID ecosystem so others can discover it
- **Customization** — extend the resolver, add auth, integrate with internal systems

## Implementations

| Implementation | Status | Language | Best for |
|---------------|--------|----------|----------|
| **Python** | Active | Python 3.10+ | **Reference implementation** — shows all the moving parts (REST API + MCP + pluggable storage). Optimized for clarity and ease of extension; read the code to understand SecID server-side. |
| **TypeScript** | Planned | Node.js 22+ | Production-grade throughput; closest shape to SecID-Service's Cloudflare Worker. |
| **Go** | Planned | Go 1.22+ | Production-grade throughput; single static binary for deployment. |

All implementations serve the same REST API, pass the same conformance suite, and support the same storage backends. The Python implementation additionally exposes an optional MCP endpoint — see below.

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

# Tell the server to reload changes. /admin/reload is gated by a dedicated
# reload token — set SECID_RELOAD_TOKEN (or --reload-token) when starting the
# server, then send it in the X-Reload-Token header. With no token configured
# the endpoint is disabled (returns 401).
curl -X POST http://localhost:8000/admin/reload -H "X-Reload-Token: $SECID_RELOAD_TOKEN"
```

Or run with `--watch` to auto-detect file changes.

## Security & Exposure Defaults

This reference server is **safe-by-default**:

- **Binds to loopback (`127.0.0.1`) by default.** To serve other hosts, pass `--host 0.0.0.0` explicitly — and only behind a trusted network or reverse proxy. Front it with TLS so the reload token isn't sent in cleartext.
- **`/admin/reload` is disabled unless you set a reload token** (`SECID_RELOAD_TOKEN` / `--reload-token`, sent as the `X-Reload-Token` header), compared in constant time. The token is scoped to reload only — give any future admin endpoint its own token rather than widening this one. The read path (`/api/v1/resolve`, `/api/v1/types`, `/mcp`) is anonymous by design.
- **CORS is off by default.** No `Access-Control-Allow-Origin` header is sent unless you allowlist origins with `--cors-origin <origin>` (repeatable) or `SECID_CORS_ORIGINS` (comma-separated).
- **Untrusted input is length-capped** before it reaches registry regexes (a ReDoS bound; real SecIDs are well under it).

> **Upgrading from an earlier build?** The old defaults were `--host 0.0.0.0` and an unauthenticated `/admin/reload`. After this change you must (a) pass `--host 0.0.0.0` to keep listening on all interfaces, (b) set a reload token to use `/admin/reload` at all, and (c) pass `--cors-origin` if browser clients call the API cross-origin.

## API Compatibility

Same API as the public service at secid.cloudsecurityalliance.org:

```
GET /api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228
```

Same response format, same status values (`found`, `corrected`, `related`, `not_found`, `error`). Any SecID client (SDK, plugin, MCP) works with any SecID server.

Resolution results may include optional format metadata fields: `parsability`, `schema`, `parsing_instructions`, `auth`, and `content_type`. Use `?parsability=structured` to filter for machine-readable sources. See the [SecID API Response Format](https://github.com/CloudSecurityAlliance/SecID/blob/main/docs/reference/API-RESPONSE-FORMAT.md) for details.

### MCP Endpoint (optional)

```
/mcp
```

Point any MCP client at your self-hosted server. Same three tools as SecID-Service: `resolve`, `lookup`, `describe`.

MCP support requires the `mcp` Python package:

```bash
pip install mcp
```

Without it, the server starts normally and serves the REST API; the `/mcp` endpoint is logged as "disabled" at startup. This keeps the MCP dependency optional for users who only need the REST API.

The Python implementation is currently the only one with MCP support — TS/Go implementations (when built) will serve REST only. The canonical production MCP surface remains [SecID-Service](https://secid.cloudsecurityalliance.org/mcp).

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
