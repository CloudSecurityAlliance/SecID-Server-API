# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Self-hosted SecID resolver — run your own API server for resolving security knowledge identifiers. Part of the [SecID ecosystem](https://github.com/CloudSecurityAlliance/SecID).

Two implementations (Python reference + TypeScript) serve the same API as the production service at [secid.cloudsecurityalliance.org](https://secid.cloudsecurityalliance.org/).

## Repository Structure

```
SecID-Server-API/
├── python/                  # Python reference implementation
│   ├── secid_server.py      # FastAPI server (/api/v1/resolve + /mcp)
│   ├── resolver.py          # Core resolution logic
│   ├── registry_loader.py   # Load strategies (bulk, lazy, update)
│   ├── storage.py           # Storage backends (memory, Redis, memcached, SQLite)
│   └── requirements.txt
├── typescript/              # TypeScript implementation (planned)
├── docker/                  # Dockerfile and compose (planned)
├── tests/                   # Shared test suite — any server should pass these (planned)
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

- **Pluggable storage**: All backends implement `get(key) → str | None` and `set(key, value)`. Registry data is read-only at runtime.
- **Same API**: `/api/v1/resolve` returns the same envelope as SecID-Service. Any SecID client works with any server.
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
