# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Self-hosted SecID resolver — run your own API server for resolving security knowledge identifiers. Part of the [SecID ecosystem](https://github.com/CloudSecurityAlliance/SecID).

Three implementations planned: **Python (the reference implementation)**, plus TypeScript and Go (both planned). Each serves the same REST API as the production service at [secid.cloudsecurityalliance.org](https://secid.cloudsecurityalliance.org/).

The Python implementation also exposes an **optional MCP endpoint** at `/mcp` (requires `pip install mcp`). It's the reference implementation specifically because it demonstrates every server-side feature: REST API, MCP endpoint, pluggable storage backends, lazy/bulk loading, registry overlays. TS/Go implementations will be production-throughput-focused and serve REST only — the canonical MCP surface remains SecID-Service.

## Repository Structure

```
SecID-Server-API/
├── python/                  # Python reference implementation
│   ├── secid_server.py      # FastAPI factory + CLI (/api/v1/resolve + optional /mcp)
│   ├── resolver.py          # Core resolution logic
│   ├── registry_loader.py   # Load strategies (bulk, lazy, update)
│   ├── storage.py           # Storage backends (memory, Redis, memcached, SQLite)
│   ├── test_smoke.py        # Smoke + factory + HTTP endpoint tests
│   └── requirements.txt
├── typescript/              # TypeScript implementation (planned)
├── go/                      # Go implementation (planned)
├── docker/                  # Dockerfile and compose (planned)
├── tests/                   # Shared conformance suite — fixtures live in SecID-Client-SDK
├── .github/workflows/       # CI: runs pytest on the Python matrix
├── README.md
└── CLAUDE.md
```

## Development Commands

```bash
# Run the Python server (default: lazy load, in-memory store)
cd python && pip install -r requirements.txt
python secid_server.py --registry /path/to/SecID/registry

# Run with bulk load
python secid_server.py --registry /path/to/SecID/registry --load bulk

# Run with Redis
python secid_server.py --registry /path/to/SecID/registry --storage redis --redis-url redis://localhost:6379

# Test a resolve
curl "http://localhost:8000/api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228"

# Health check
curl http://localhost:8000/health
```

## Key Design Decisions

- **Factory pattern**: `secid_server.create_app(config)` returns a configured FastAPI app with no module-level side effects. Tests use it via `fastapi.testclient.TestClient`; ASGI deployments use it to construct apps from environment variables. The CLI in `main()` is a thin wrapper that builds a `ServerConfig` from argparse and calls the factory.
- **Pluggable storage**: All backends implement `get(key) → str | None` and `set(key, value)`. Registry data is read-only at runtime.
- **Same API**: `/api/v1/resolve` returns the same envelope as SecID-Service. Any SecID client works with any server.
- **Optional MCP**: `/mcp` mounted only if `pip install mcp` was run. Gracefully no-ops otherwise. The Python implementation is positioned as the reference that demonstrates MCP integration; the TS/Go ports (when built) will be REST-only since the canonical MCP surface is SecID-Service.
- **Multiple registries**: `--registry` can be specified multiple times. Later directories overlay earlier ones (private data supplements public).
- **Loading strategies**: Lazy (default, instant startup), bulk (load all at startup), update (reload changed files after git pull).
- **Format metadata on results**: Resolution results include optional `parsability` (`structured`/`scraped`), `schema` (SecID reference), `parsing_instructions` (SecID reference), `auth` (free text), and `content_type` (MIME type) fields. These describe what data format you get at each URL. The `?parsability=structured` query parameter filters for machine-readable sources only.

## Multi-Repo Architecture

| Repo | Purpose |
|------|---------|
| **[SecID](https://github.com/CloudSecurityAlliance/SecID)** | Specification + registry data (source of truth) |
| **[SecID-Service](https://github.com/CloudSecurityAlliance/SecID-Service)** | Cloudflare-hosted production service |
| **[SecID-Server-API](https://github.com/CloudSecurityAlliance/SecID-Server-API)** (this repo) | Self-hosted resolver |
| **[SecID-Client-SDK](https://github.com/CloudSecurityAlliance/SecID-Client-SDK)** | Client libraries (Python, TypeScript, Go) |
