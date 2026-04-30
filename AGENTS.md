# Repository Guidelines

## Project Structure & Module Organization
- `python/` is the active server implementation (`secid_server.py`, resolver, loader, storage).
- `tests/` and `docker/` currently document planned shared test/deployment flows.
- `typescript/` is a placeholder for the planned Node implementation.
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
- This repo does not yet ship a full automated suite; rely on reproducible smoke tests per change.
- Validate `/health`, `/api/v1/resolve`, and `/admin/reload` when touching server internals.
- For resolver logic changes, compare outputs against the hosted service for representative SecIDs.

## Commit & Pull Request Guidelines
- Use imperative commit subjects and keep commits focused by subsystem.
- In PRs, include backend used (`memory`, `redis`, etc.), load mode, and smoke-test commands/results.
- Call out any compatibility-impacting behavior changes against `SecID-Service`.

## Security & Configuration Tips
- Treat private registry overlays as sensitive and keep them out of version control.
- Do not commit runtime secrets, backend credentials, or internal hostnames.
