# AGENTS.md

This file provides vendor-neutral guidance to AI coding agents when working with code in this repository. `CLAUDE.md` (`@AGENTS.md`) and `GEMINI.md` (`@./AGENTS.md`) point here so all agents read the same canonical instructions.

## Project Overview

Self-hosted SecID resolver — run your own API server for resolving security knowledge identifiers. Part of the [SecID ecosystem](https://github.com/CloudSecurityAlliance/SecID).

Three implementations planned: **Python (the reference implementation, the only one that exists)**, plus TypeScript and Go (not started). Each is meant to serve the same REST API as the production service at [secid.cloudsecurityalliance.org](https://secid.cloudsecurityalliance.org/). There is no Dockerfile or container image yet.

`python/resolver.py` is a **port of SecID-Service** (`src/parser.ts`, `resolver.ts`, `kv-resolve.ts`, `identity.ts`). The live service is the reference for correct behaviour: port logic from it rather than inventing it, and add a case to `TARGETED_CASES` in `python/test_real_registry.py` with the expectation taken from the live resolver.

The Python implementation also exposes an **optional MCP endpoint** at `/mcp` (requires `pip install mcp`). It's the reference implementation specifically because it demonstrates every server-side feature: REST API, MCP endpoint, pluggable storage backends, lazy/bulk loading, registry overlays. TS/Go implementations will be production-throughput-focused and serve REST only — the canonical MCP surface remains SecID-Service.

## Repository Structure & Module Organization

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
├── go/                      # Go implementation (planned, README only)
├── docker/                  # Dockerfile and compose (planned, README only)
├── tests/                   # Pointer to the shared conformance suite in SecID-Client-SDK
├── .github/workflows/       # CI: runs pytest on the Python matrix
├── README.md
└── AGENTS.md
```

- `python/` is the active reference implementation (`secid_server.py` factory + CLI, `resolver.py` port of SecID-Service, `registry_loader.py`, `storage.py`, `sanitize.py` MCP output envelope). Tests: `test_smoke.py`, `test_real_registry.py`.
- `typescript/` and `go/` are placeholders for the planned production-throughput implementations.
- `tests/` points at the shared conformance suite, which lives in `SecID-Client-SDK`.
- `docker/` documents planned containerization (no Dockerfile or image yet).
- `.github/workflows/test.yml` runs the Python test suite (smoke + real-registry) on every PR.
- Repository root docs describe self-hosting, storage modes, and compatibility with the hosted service.

## Build, Test, and Development Commands

Run from repository root unless noted.

```bash
# Install server dependencies and run the Python server (default: lazy load, in-memory store)
cd python && pip install -r requirements.txt
python secid_server.py --registry ../../SecID/registry

# Run with bulk load (preload registry at startup)
python secid_server.py --registry ../../SecID/registry --load bulk

# Run with Redis
python secid_server.py --registry ../../SecID/registry --storage redis --redis-url redis://localhost:6379

# Smoke test resolution
curl "http://localhost:8000/api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228"

# Health check
curl http://localhost:8000/health

# Reload after `git pull` in the registry (start the server with SECID_RELOAD_TOKEN
# or --reload-token set; without a token the endpoint returns 401)
export SECID_RELOAD_TOKEN=...
python secid_server.py --registry ../../SecID/registry
curl -X POST http://localhost:8000/admin/reload -H "X-Reload-Token: $SECID_RELOAD_TOKEN"

# Tests (real-registry tests need ../../SecID and ../../SecID-Client-SDK, or
# SECID_REGISTRY_DIR / SECID_CLIENT_SDK_DIR)
pip install pytest httpx "mcp>=1.23.0,<3.0.0"
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

## Coding Style & Naming Conventions

- Python code should stay straightforward and stdlib-first where practical.
- Use explicit names for resolver and storage behaviors (`lazy` vs `bulk`, backend flags).
- Keep API response shape compatible with `SecID-Service` (`found`, `corrected`, `related`, `not_found`, `error`).

## Testing Guidelines

- `python/test_smoke.py` covers imports, the factory, basic HTTP endpoints, and type-list invariants. Run with `pytest test_smoke.py -v` from `python/`.
- For new HTTP endpoints, add a test using `fastapi.testclient.TestClient` against `create_app(ServerConfig(...))`. See the existing endpoint tests for the pattern.
- `python/test_real_registry.py` runs the resolver against the real registry (`SECID_REGISTRY_DIR`, default `../../SecID/registry`) plus the shared fixtures in `SecID-Client-SDK` (`SECID_CLIENT_SDK_DIR`, default `../../SecID-Client-SDK`), in both lazy and bulk load modes. It skips with a message if either checkout is missing. Expectations come from the live resolver.
- For resolver logic changes, compare outputs against the hosted service for representative SecIDs, and add the case to `TARGETED_CASES` in `test_real_registry.py`.
- The shared fixtures (`SecID-Client-SDK/tests/fixtures.json`) and resolver conformance suite (`SecID-Client-SDK/tests/conformance/`) are run by `test_real_registry.py`. To check a running server, use `SecID-Client-SDK/tests/conformance-harness/python/run.py --target http://localhost:8000`.

## Commit & Pull Request Guidelines

- Use imperative commit subjects and keep commits focused by subsystem.
- In PRs, include backend used (`memory`, `redis`, etc.), load mode, and smoke-test commands/results.
- Call out any compatibility-impacting behavior changes against `SecID-Service`.

## Security & Configuration Tips

- Treat private registry overlays as sensitive and keep them out of version control.
- Do not commit runtime secrets, backend credentials, or internal hostnames.

## Multi-Repo Architecture

| Repo | Purpose |
|------|---------|
| **[SecID](https://github.com/CloudSecurityAlliance/SecID)** | Specification + registry data (source of truth) |
| **[SecID-Service](https://github.com/CloudSecurityAlliance/SecID-Service)** | Cloudflare-hosted production service |
| **[SecID-Server-API](https://github.com/CloudSecurityAlliance/SecID-Server-API)** (this repo) | Self-hosted resolver |
| **[SecID-Client-SDK](https://github.com/CloudSecurityAlliance/SecID-Client-SDK)** | Client libraries (Python, TypeScript, Go) |
