# Repository Guidelines

## Project Structure & Module Organization
- `python/` is the active reference implementation (`secid_server.py` factory + CLI, resolver, loader, storage). Includes `test_smoke.py`.
- `typescript/` and `go/` are placeholders for the planned production-throughput implementations.
- `tests/` documents the planned shared conformance suite (fixtures live in `SecID-Client-SDK`).
- `docker/` documents planned containerization.
- `.github/workflows/test.yml` runs the Python smoke suite on every PR.
- Repository root docs describe self-hosting, storage modes, and compatibility with the hosted service.

## Build, Test, and Development Commands
Run from repository root unless noted.

- `cd python && pip install -r requirements.txt`: install server dependencies.
- `cd python && python secid_server.py --registry ../../SecID/registry`: start local server.
- `cd python && python secid_server.py --registry ../../SecID/registry --load bulk`: preload registry at startup.
- `curl "http://localhost:8000/api/v1/resolve?secid=secid:advisory/mitre.org/cve%23CVE-2021-44228"`: smoke test resolution.
- `curl -X POST http://localhost:8000/admin/reload`: reload after registry updates.

## Coding Style & Naming Conventions
- Python code should stay straightforward and stdlib-first where practical.
- Use explicit names for resolver and storage behaviors (`lazy` vs `bulk`, backend flags).
- Keep API response shape compatible with `SecID-Service` (`found`, `corrected`, `related`, `not_found`, `error`).

## Testing Guidelines
- `python/test_smoke.py` covers imports, the factory, basic HTTP endpoints, and type-list invariants. Run with `pytest test_smoke.py -v` from `python/`.
- For new HTTP endpoints, add a test using `fastapi.testclient.TestClient` against `create_app(ServerConfig(...))`. See the existing endpoint tests for the pattern.
- For resolver logic changes, compare outputs against the hosted service for representative SecIDs.
- Conformance against the canonical SecID-Service is the broader goal — the shared fixture suite lives in `SecID-Client-SDK/tests/fixtures.json` and is being grown into a multi-implementation conformance gate.

## Commit & Pull Request Guidelines
- Use imperative commit subjects and keep commits focused by subsystem.
- In PRs, include backend used (`memory`, `redis`, etc.), load mode, and smoke-test commands/results.
- Call out any compatibility-impacting behavior changes against `SecID-Service`.

## Security & Configuration Tips
- Treat private registry overlays as sensitive and keep them out of version control.
- Do not commit runtime secrets, backend credentials, or internal hostnames.
