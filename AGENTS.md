# Repository Guidelines

## Project Structure & Module Organization
- `python/` is the active reference implementation (`secid_server.py` factory + CLI, `resolver.py` port of SecID-Service, `registry_loader.py`, `storage.py`, `sanitize.py` MCP output envelope). Tests: `test_smoke.py`, `test_real_registry.py`.
- `typescript/` and `go/` are placeholders for the planned production-throughput implementations.
- `tests/` points at the shared conformance suite, which lives in `SecID-Client-SDK`.
- `docker/` documents planned containerization (no Dockerfile or image yet).
- `.github/workflows/test.yml` runs the Python test suite (smoke + real-registry) on every PR.
- Repository root docs describe self-hosting, storage modes, and compatibility with the hosted service.

## Build, Test, and Development Commands
Run from repository root unless noted.

- `cd python && pip install -r requirements.txt`: install server dependencies.
- `cd python && python secid_server.py --registry ../../SecID/registry`: start local server.
- `cd python && python secid_server.py --registry ../../SecID/registry --load bulk`: preload registry at startup.
- `curl "http://localhost:8000/api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228"`: smoke test resolution.
- `curl -X POST http://localhost:8000/admin/reload -H "X-Reload-Token: $SECID_RELOAD_TOKEN"`: reload after registry updates (start the server with `SECID_RELOAD_TOKEN` or `--reload-token` set; without a token the endpoint returns 401).

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
