# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Self-hosted SecID resolver — run your own API server for resolving security knowledge identifiers. Part of the [SecID ecosystem](https://github.com/CloudSecurityAlliance/SecID).

Three implementations planned: **Python (the reference implementation, the only one that exists)**, plus TypeScript and Go (not started). Each is meant to serve the same REST API as the production service at [secid.cloudsecurityalliance.org](https://secid.cloudsecurityalliance.org/). There is no Dockerfile or container image yet.

`python/resolver.py` is a **port of SecID-Service** (`src/parser.ts`, `resolver.ts`, `kv-resolve.ts`, `identity.ts`). The live service is the reference for correct behaviour: port logic from it rather than inventing it, and add a case to `TARGETED_CASES` in `python/test_real_registry.py` with the expectation taken from the live resolver.

The Python implementation also exposes an **optional MCP endpoint** at `/mcp` (requires `pip install mcp`). It's the reference implementation specifically because it demonstrates every server-side feature: REST API, MCP endpoint, pluggable storage backends, lazy/bulk loading, registry overlays. TS/Go implementations will be production-throughput-focused and serve REST only — the canonical MCP surface remains SecID-Service.

## Repository Structure

```
SecID-Server-API/
├── python/                  # Python reference implementation
│   ├── secid_server.py      # FastAPI factory + CLI (/api/v1/resolve + optional /mcp)
│   ├── resolver.py          # Core resolution logic (port of SecID-Service)
│   ├── registry_loader.py   # Loading: bulk, per-namespace, reload after git pull
│   ├── storage.py           # Storage backends (memory, Redis, memcached, SQLite)
│   ├── sanitize.py          # MCP output envelope (port of SecID-Service sanitize.ts)
│   ├── test_smoke.py        # Factory, HTTP endpoints, synthetic registries
│   ├── test_real_registry.py # Real registry + SecID-Client-SDK fixtures, both load modes
│   └── requirements.txt
├── typescript/              # TypeScript implementation (planned, README only)
├── docker/                  # Dockerfile and compose (planned, README only)
├── tests/                   # Pointer to the shared conformance suite in SecID-Client-SDK
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

# Reload after `git pull` in the registry (requires a reload token)
SECID_RELOAD_TOKEN=... python secid_server.py --registry /path/to/SecID/registry
curl -X POST http://localhost:8000/admin/reload -H "X-Reload-Token: $SECID_RELOAD_TOKEN"

# Tests (real-registry tests need ../../SecID and ../../SecID-Client-SDK, or
# SECID_REGISTRY_DIR / SECID_CLIENT_SDK_DIR)
pip install pytest httpx mcp
pytest -v -rs
```

## Key Design Decisions

- **Factory pattern**: `secid_server.create_app(config)` returns a configured FastAPI app with no module-level side effects. Tests use it via `fastapi.testclient.TestClient`; ASGI deployments use it to construct apps from environment variables. The CLI in `main()` is a thin wrapper that builds a `ServerConfig` from argparse and calls the factory.
- **Pluggable storage**: All backends implement `get(key) → str | None` and `set(key, value)`. Registry data is read-only at runtime.
- **Same API**: `/api/v1/resolve` returns the same envelope and status values as SecID-Service. The README lists the known differences (URL hardening, no listing filters, no registry download, no `submit_feedback`).
- **Optional MCP**: `/mcp` is served only if `pip install mcp` was run (the 1.x `FastMCP` and 2.x `MCPServer` SDKs both work). It no-ops otherwise. Tools are named `resolve`, `lookup`, and `describe`, like the live service, and their output goes through `sanitize.py`. The Python implementation is positioned as the reference that demonstrates MCP integration; the TS/Go ports (when built) will be REST-only since the canonical MCP surface is SecID-Service.
- **Multiple registries**: `--registry` can be specified multiple times. Later directories override earlier ones by namespace (`registry_loader.load_namespaces`). Every load path uses that one rule.
- **Loading strategies**: Lazy (default; a type's files are read on first use and cached in a per-type index) or bulk (everything at startup). `POST /admin/reload` diffs against the commit last loaded and handles deletes and renames.
- **Format metadata on results**: Resolution results include optional `parsability` (`structured`/`scraped`), `schema` (SecID reference), `parsing_instructions` (SecID reference), `auth` (free text), and `content_type` (MIME type) fields. These describe what data format you get at each URL. The `?parsability=structured` query parameter filters for machine-readable sources only.

## Multi-Repo Architecture

| Repo | Purpose |
|------|---------|
| **[SecID](https://github.com/CloudSecurityAlliance/SecID)** | Specification + registry data (source of truth) |
| **[SecID-Service](https://github.com/CloudSecurityAlliance/SecID-Service)** | Cloudflare-hosted production service |
| **[SecID-Server-API](https://github.com/CloudSecurityAlliance/SecID-Server-API)** (this repo) | Self-hosted resolver |
| **[SecID-Client-SDK](https://github.com/CloudSecurityAlliance/SecID-Client-SDK)** | Client libraries (Python, TypeScript, Go) |
