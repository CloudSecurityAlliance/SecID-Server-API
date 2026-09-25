# SecID-Server-API

Self-hosted SecID resolver — run your own API server locally or on internal infrastructure.

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
| **TypeScript** | Planned (not started) | Node.js 22+ | Production-grade throughput; closest shape to SecID-Service's Cloudflare Worker. |
| **Go** | Planned (not started) | Go 1.22+ | Production-grade throughput; single static binary for deployment. |
| **Docker image** | Planned (not started) | — | No Dockerfile or published image yet; see [docker/README.md](docker/README.md). |

Only the Python implementation exists today. Its resolution logic is a port of the live service ([SecID-Service](https://github.com/CloudSecurityAlliance/SecID-Service)) and is tested against the real registry and the shared fixtures in [SecID-Client-SDK](https://github.com/CloudSecurityAlliance/SecID-Client-SDK) — see [Testing](#testing). Future implementations are expected to pass the same tests. The Python implementation also exposes an optional MCP endpoint — see below.

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
| **Lazy** (default) | `--load lazy` | Instant startup. The first query that touches a type reads that type's JSON files once and caches them. |
| **Bulk** | `--load bulk` | Startup: load every namespace into the store and the resolver's index. Predictable latency. |

Both modes give identical answers. After the registry changes on disk, reload it without restarting:

```bash
# Pull latest registry data
cd /path/to/SecID && git pull

# Tell the server to reload changes. /admin/reload is gated by a dedicated
# reload token — set SECID_RELOAD_TOKEN (or --reload-token) when starting the
# server, then send it in the X-Reload-Token header. With no token configured
# the endpoint is disabled (returns 401).
curl -X POST http://localhost:8000/admin/reload -H "X-Reload-Token: $SECID_RELOAD_TOKEN"
```

The reload diffs each registry directory against the git commit it was last loaded at, and applies additions, modifications, deletions, and renames. If a registry directory is not a git checkout, or git is unavailable, it does a full reload instead (which also drops namespaces whose files were deleted). There is no file watcher; trigger the reload after each `git pull`.

## Security & Exposure Defaults

This reference server is **safe-by-default**:

- **Binds to loopback (`127.0.0.1`) by default.** To serve other hosts, pass `--host 0.0.0.0` explicitly — and only behind a trusted network or reverse proxy. Front it with TLS so the reload token isn't sent in cleartext.
- **`/admin/reload` is disabled unless you set a reload token** (`SECID_RELOAD_TOKEN` / `--reload-token`, sent as the `X-Reload-Token` header), compared in constant time. The token is scoped to reload only — give any future admin endpoint its own token rather than widening this one. The read path (`/api/v1/resolve`, `/api/v1/types`, `/mcp`) is anonymous by design.
- **CORS is off by default.** No `Access-Control-Allow-Origin` header is sent unless you allowlist origins with `--cors-origin <origin>` (repeatable) or `SECID_CORS_ORIGINS` (comma-separated).
- **Untrusted input is length-capped** before it reaches registry regexes (a ReDoS bound; real SecIDs are well under it).
- **MCP output labels registry text as untrusted.** On `/mcp`, contributor-written fields are control-stripped and moved under `registry_text_untrusted`, as on the live service. When bound to loopback, the MCP transport also rejects requests whose `Host` is not localhost (DNS-rebinding protection).

> **Upgrading from an earlier build?** The old defaults were `--host 0.0.0.0` and an unauthenticated `/admin/reload`. After this change you must (a) pass `--host 0.0.0.0` to keep listening on all interfaces, (b) set a reload token to use `/admin/reload` at all, and (c) pass `--cors-origin` if browser clients call the API cross-origin.

## API Compatibility

The resolve endpoint matches the public service at secid.cloudsecurityalliance.org:

```
GET /api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228
```

It returns the same response envelope (`secid_query`, `status`, `results`, `message`) and the same status values (`found`, `corrected`, `related`, `not_found`, `error`), so a SecID client (SDK, plugin, MCP) pointed at this server gets answers in the same shape. For a registry loaded from the same commit, the results are the same as the live service's. Known differences:

- **URL templates must be absolute `http(s)` URLs**, and substituted identifier values are percent-encoded where they would otherwise change the URL's structure (`?`, `#`, spaces). Characters that identifiers use in paths (`:`, `/`, `.`) are kept.
- **`not_found` guidance** points to the [SecID issue tracker](https://github.com/CloudSecurityAlliance/SecID/issues). The live service's `submit_feedback` MCP tool is not provided.
- **Listing filters** (`?subtype=`, `?country=`) are not implemented. The self-hosted server has a `?parsability=structured|scraped` filter instead.
- **`GET /api/v1/types`** returns the 10 types and their descriptions, but not subtype declarations or counts.
- **`GET /api/v1/registry.json`** (full registry download) is not implemented. Use the git checkout directly.

Resolution results may include optional format metadata fields: `parsability`, `schema`, `parsing_instructions`, `auth`, and `content_type`. Use `?parsability=structured` to filter for machine-readable sources. See the [SecID API Response Format](https://github.com/CloudSecurityAlliance/SecID/blob/main/docs/reference/API-RESPONSE-FORMAT.md) for details.

### MCP Endpoint (optional)

```
/mcp
```

Point any MCP client at your self-hosted server. It serves the same three tools as SecID-Service, `resolve`, `lookup`, and `describe`, with the same names. The `submit_feedback` tool is not provided.

MCP support requires the `mcp` Python package, version 1.8 or later (both the 1.x and 2.x SDKs work):

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

Private entries override public ones for the same namespace: a later `--registry` directory wins over an earlier one, in both load modes and regardless of which query arrives first. Your internal advisories, controls, and capabilities supplement the public registry.

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

## Testing

```bash
cd python
pip install -r requirements.txt pytest httpx    # add `mcp` to also run the /mcp tests
pytest -v -rs
```

- `test_smoke.py` covers imports, the app factory, the HTTP endpoints, and synthetic registries (overlay precedence, reload, URL hardening).
- `test_real_registry.py` runs the resolver against the **real** registry in both load modes. It uses the shared fixtures and the resolver conformance suite from SecID-Client-SDK, targeted cases whose expectations are taken from the live service, and every structured example in the registry. By default it expects sibling checkouts (`../../SecID/registry`, `../../SecID-Client-SDK`). Set `SECID_REGISTRY_DIR` / `SECID_CLIENT_SDK_DIR` to override. It skips with a message if either checkout is missing.

CI runs both files against the current `main` of SecID and SecID-Client-SDK.

To check a running server, including the live service, use the conformance harness in SecID-Client-SDK:

```bash
python ../SecID-Client-SDK/tests/conformance-harness/python/run.py --target http://localhost:8000
```

## All SecID Repos

| Repo | What it is |
|------|-----------|
| **[SecID](https://github.com/CloudSecurityAlliance/SecID)** | Specification + registry data |
| **[SecID-Service](https://github.com/CloudSecurityAlliance/SecID-Service)** | Cloudflare-hosted production service |
| **[SecID-Server-API](https://github.com/CloudSecurityAlliance/SecID-Server-API)** (this repo) | Self-hosted resolver (Python; TypeScript, Go and Docker planned) |
| **[SecID-Client-SDK](https://github.com/CloudSecurityAlliance/SecID-Client-SDK)** | Client libraries (Python, TypeScript, Go) |

## License

[Apache License 2.0](LICENSE) — Copyright 2026 Cloud Security Alliance.

The SecID registry data this server loads is published separately under CC0 in the [SecID](https://github.com/CloudSecurityAlliance/SecID) repository.
