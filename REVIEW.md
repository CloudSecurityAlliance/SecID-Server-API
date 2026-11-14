@AGENTS.md

# Code Review Rules — CloudSecurityAlliance/SecID-Server-API

Review instructions for Claude Code Review, GitHub Copilot Code Review, and human/agent reviewers. OpenAI Codex (`codex review` / `codex exec`) reads the matching [`## Code Review Rules`](AGENTS.md#code-review-rules) section in [`AGENTS.md`](AGENTS.md).

Check every PR in `SecID-Server-API` against these rules:

## 1. Authority, Provenance, and CI Guardrails

- **Agent attribution:** Agent-authored commits must end with `AI-Agent: <Name>`, and agent PR descriptions/comments must start with `*Agent: <Name> (SecID governing agent)*` (or the contributing agent's role).
- **Governance and gate changes:** Every change to `.github/workflows/test.yml`, `AGENTS.md`, or `REVIEW.md` unconditionally requires an independent cross-vendor review and decision record, and must never weaken the `ci-passed` status gate (`test-python`). Widening agent authority requires Kurt's approval first.
- **Secrets and configuration:** Never commit runtime secrets, reload tokens (`SECID_RELOAD_TOKEN`), Redis/memcached credentials, or private registry overlays.

## 2. MCP Output Sanitization and Untrusted Input Handling (`python/sanitize.py`)

- **Schema allow-list MCP output sanitization:** Every MCP tool (`resolve`, `lookup`, `describe` in `python/secid_server.py`) must pass its output through `sanitize_response_for_mcp()`, and `/mcp` JSON responses through `sanitize_jsonrpc_for_mcp()` (`_SanitizeMcpResponses`). Verify that changes to response shapes or `python/sanitize.py`:
  - Keep it a **schema allow-list**: a field stays in place only where the response schema declares it and only if its value has the declared type and grammar (enumerations, dates, codes, http(s) URLs with a host, identifiers, SecIDs, anchored patterns). `secid` is trusted only as a result's own field, `pattern` only under `data.patterns[]`. Everything else moves into `registry_text_untrusted` with `_warning`. A widened schema, grammar or vocabulary needs a reason the value cannot carry prose, and the same change in `SecID-Service/src/sanitize.ts`.
  - Move a response `message` into the envelope behind `MESSAGE_POINTER` (`service_message` only for constant text written in this repo).
  - Strip Cc (except TAB/LF/CR), Cf and Default_Ignorable_Code_Point characters (`STRIP_RANGES`, frozen code points, written as `\U` escapes so the source stays ASCII) from every string and key in one bounded pass; cap strings (code points) and lists (`MAX_FIELD_CHARS = 4000`, `MAX_ARRAY_ITEMS = 64`), in lockstep with `SecID-Service/src/sanitize.ts`.
  - Keep `python/fixtures/mcp-sanitize-fixtures.json` byte-identical to SecID-Service's `test/fixtures/` copy (including its `vocabularies`), and `test_mcp_sanitize.py` green; its location table and validators are deliberately independent copies.

## 3. Endpoint Security, `/admin/reload` Auth, and URL Hardening (`python/secid_server.py`, `python/resolver.py`)

- **`POST /admin/reload` authentication:** Must fail closed (`401 Unauthorized`) whenever `reload_token` is unset/empty or does not match `X-Reload-Token`, using constant-time comparison (`hmac.compare_digest`), and serialize registry reloads under lock so concurrent reloads cannot corrupt state.
- **URL hardening and input bounds:** Preserve `http://` / `https://` URL scheme validation on resolved URLs and query length limits on `secid` inputs across REST (`/api/v1/resolve`) and MCP (`/mcp`).

## 4. Resolver Parity and Dual-Mode Testing (`python/resolver.py`, `python/registry_loader.py`)

- **Parity with `SecID-Service`:** Keep `TYPE_REGISTRY`, SecID parser behavior, format metadata (`parsability`, `schema`, `parsing_instructions`, `auth`, `content_type`, `?parsability=structured`), and resolution statuses (`found`, `corrected`, `related`, `not_found`, `error`) aligned with `SecID-Service`.
- **Test coverage (`python/test_smoke.py`, `python/test_real_registry.py`):** Every change to resolution, loading, storage backends, or MCP tools must include pytest coverage and pass in both `lazy` and `bulk` load modes.
