# SecID-Server-API — Goals

What `SecID-Server-API` achieves as the self-hosted reference server for [SecID](https://github.com/CloudSecurityAlliance/SecID) (SecID 3.0 — *"Can I run it myself?"*), and how we measure success.

## Vision / North Star

Provide a clear, safe-by-default, self-hostable SecID server that organizations and AI builders can run locally, in private clouds, or in air-gapped environments — with full resolution parity with [`SecID-Service`](https://github.com/CloudSecurityAlliance/SecID-Service) and seamless support for private registry overlays (`--registry public --registry private`).

## CSA Goals (Organization)

- **Objective:** Maintain a second independent, spec-conformant reference implementation of the SecID resolver and MCP server to validate specification portability and catch edge cases across runtimes.
  - **Success metrics:**
    - 100% pass rate across `python/test_smoke.py` and `python/test_real_registry.py` on Python 3.10–3.13 in CI (`.github/workflows/test.yml`).
    - 100% pass rate against the shared [`SecID-Client-SDK`](https://github.com/CloudSecurityAlliance/SecID-Client-SDK) client fixtures (`tests/fixtures.json`) and resolver conformance suite (`tests/conformance/fixtures.json`) in both `lazy` and `bulk` load modes.

## Community & Ecosystem Goals

- **Objective:** Enable enterprise and air-gapped deployments with private registry overlays and pluggable storage backends.
  - **Success metrics:**
    - Deterministic overlay precedence (`--registry` later directories override earlier ones by namespace in both `lazy` and `bulk` modes) verified by automated tests across `memory`, `sqlite`, `redis`, and `memcached` storage adapters (`python/storage.py`).
    - Zero-downtime incremental registry reload (`POST /admin/reload` using `git diff` in `python/registry_loader.py`) correctly handles additions, modifications, deletions, and in-place namespace renames.
- **Objective:** Guarantee a safe-by-default security posture for self-hosted operators and MCP clients.
  - **Success metrics:**
    - 100% enforcement of safe defaults: loopback bind (`127.0.0.1`), constant-time token check on `/admin/reload` (`401` when unset), opt-in CORS (`--cors-origin`), absolute `http(s)` URL template validation with identifier metacharacter escaping, `mcp>=1.23.0,<3.0.0` DNS-rebinding protection, and recursive MCP output sanitization (`python/sanitize.py`).

## Shared Goals

- **Objective:** Keep `SecID-Server-API`, `SecID-Service`, `SecID`, and `SecID-Client-SDK` aligned on types, resolution statuses (`found`, `corrected`, `related`, `not_found`, `error`), version disambiguation, and format metadata (`parsability`, `content_type`, `schema`, `parsing_instructions`, `auth`).
  - **Success metrics:** Zero unmitigated resolution parity gaps between `python/resolver.py` and `SecID-Service/src/resolver.ts`.

## Notes

- **How to participate:** Run `pytest -v -rs` from `python/` and compare resolver changes against the live service and `TARGETED_CASES` in `python/test_real_registry.py`. See [`AGENTS.md`](AGENTS.md) for development guidelines.
- **Related documents:** [`BUSINESS-CASE.md`](BUSINESS-CASE.md), [`README.md`](README.md), [`AGENTS.md`](AGENTS.md).
- **Review triggers:** Revisit goals when external demand justifies starting the planned TypeScript, Go, or Docker distributions (`typescript/`, `docker/`).
