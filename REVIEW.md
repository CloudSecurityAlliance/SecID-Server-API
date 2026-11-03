@AGENTS.md

# Code Review Rules — CloudSecurityAlliance/SecID-Server-API

Review instructions for Claude Code Review, GitHub Copilot Code Review, and human/agent reviewers. OpenAI Codex (`codex review` / `codex exec`) reads the matching [`## Code Review Rules`](AGENTS.md#code-review-rules) section in [`AGENTS.md`](AGENTS.md).

Check every PR in `SecID-Server-API` against these rules:

## 1. Authority, Provenance, and CI Guardrails

- **Agent attribution:** Agent-authored commits must end with `AI-Agent: <Name>`, and agent PR descriptions/comments must start with `*Agent: <Name> (SecID governing agent)*` (or the contributing agent's role).
- **Governance and gate changes:** Every change to `.github/workflows/test.yml`, `AGENTS.md`, or `REVIEW.md` unconditionally requires an independent cross-vendor review and decision record, and must never weaken the `ci-passed` status gate (`test-python`). Widening agent authority requires Kurt's approval first.
- **Secrets and configuration:** Never commit runtime secrets, reload tokens (`SECID_RELOAD_TOKEN`), Redis/memcached credentials, or private registry overlays.

## 2. MCP Output Sanitization and Untrusted Input Handling (`python/sanitize.py`)

- **Recursive MCP output sanitization:** Every MCP tool (`resolve`, `lookup`, `describe` in `python/secid_server.py`) returning registry-derived data must pass its output through `sanitize_response_for_mcp()`. Verify that changes to response shapes or `python/sanitize.py`:
  - Recursively traverse nested dicts and lists (`sanitize_dict()` / `sanitize_value()`) so `UNTRUSTED_TEXT_KEYS` (`description`, `notes`, `note`, `official_name`, `common_name`, `auth`, `contacts`, `contact`, `scope`, `policy`, `disclosure_policy`, `version_disambiguation`, `unversioned_behavior`, `parsing_instructions`) at any depth are relocated into `registry_text_untrusted` with `registry_text_untrusted._warning`.
  - Strip C0/C1 control, zero-width, and bidi-override characters (`CONTROL_RE`) and recursively cap strings, lists, and nested dicts via `cap_string()` / `cap_value()` (`MAX_FIELD_CHARS = 4000`, `MAX_ARRAY_ITEMS = 64`), in lockstep with `SecID-Service/src/sanitize.ts`.

## 3. Endpoint Security, `/admin/reload` Auth, and URL Hardening (`python/secid_server.py`, `python/resolver.py`)

- **`POST /admin/reload` authentication:** Must fail closed (`401 Unauthorized`) whenever `reload_token` is unset/empty or does not match `X-Reload-Token`, using constant-time comparison (`hmac.compare_digest`), and serialize registry reloads under lock so concurrent reloads cannot corrupt state.
- **URL hardening and input bounds:** Preserve `http://` / `https://` URL scheme validation on resolved URLs and query length limits on `secid` inputs across REST (`/api/v1/resolve`) and MCP (`/mcp`).

## 4. Resolver Parity and Dual-Mode Testing (`python/resolver.py`, `python/registry_loader.py`)

- **Parity with `SecID-Service`:** Keep `TYPE_REGISTRY`, SecID parser behavior, format metadata (`parsability`, `schema`, `parsing_instructions`, `auth`, `content_type`, `?parsability=structured`), and resolution statuses (`found`, `corrected`, `related`, `not_found`, `error`) aligned with `SecID-Service`.
- **Test coverage (`python/test_smoke.py`, `python/test_real_registry.py`):** Every change to resolution, loading, storage backends, or MCP tools must include pytest coverage and pass in both `lazy` and `bulk` load modes.
