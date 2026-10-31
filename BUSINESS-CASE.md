# SecID-Server-API — Business Case

## Executive summary

`SecID-Server-API` is the self-hosted reference server for [SecID](https://github.com/CloudSecurityAlliance/SecID) (SecID 3.0 — *"Can I run it myself?"*). It allows organizations, researchers, and AI builders to run a full SecID REST API (`/api/v1/resolve`, `/api/v1/types`) and optional Model Context Protocol endpoint (`/mcp`: `resolve`, `lookup`, `describe`) locally, on internal networks, or in air-gapped environments — with pluggable storage backends (`memory`, `redis`, `memcached`, `sqlite`), lazy or bulk loading, incremental `git diff` reloads (`/admin/reload`), and **private registry overlays** (`--registry public --registry private`) that merge internal advisories, controls, and policies seamlessly over the public CSA registry.

## Business benefit categories

- **Enterprise & Air-Gapped Adoption (SecID 3.0)** — Unlocks SecID adoption for enterprises, regulated industries, and government/defense environments that cannot send internal security queries to a public cloud API or need to resolve internal/proprietary identifiers alongside public ones.
- **Specification Verification & Reference Architecture** — Serves as the second independent server implementation alongside [`SecID-Service`](https://github.com/CloudSecurityAlliance/SecID-Service) (Cloudflare Workers / TypeScript), proving that SecID's resolution algorithm, version disambiguation, and MCP output sanitization are portable across languages and storage engines.
- **Brand & Market Position** — Demonstrates CSA's commitment to open, vendor-neutral, self-hostable security infrastructure (Apache-2.0 software + CC0 registry data) with zero vendor lock-in.

Not directly applicable:

- **Direct Revenue** — Released under Apache-2.0 as an open-source reference server.

## Stakeholder value propositions

### CSA Value Proposition
- **CSA engineering and specification authors** get a clean, readable Python reference implementation (`python/resolver.py`, `python/registry_loader.py`, `python/storage.py`, `python/sanitize.py`) tested against the entire live registry and [`SecID-Client-SDK`](https://github.com/CloudSecurityAlliance/SecID-Client-SDK) conformance fixtures (`python/test_real_registry.py`), catching specification ambiguities and cross-implementation bugs (such as recursive MCP sanitization in `#19` / `SecID-Service#47`).
- **Low operational cost:** CSA does not host `SecID-Server-API` as a separate paid cloud service; it runs in GitHub Actions CI (`Python 3.10–3.13` + CodeQL) and is deployed by users on their own infrastructure.

### Community Value Proposition
- **Enterprise security teams** can overlay private namespaces (`secid:control/internal.example.com/...`, internal vulnerability advisories, proprietary policies) on top of the 2,138+ public SecID namespaces using `--registry /path/to/public --registry /path/to/private`, with deterministic last-wins precedence.
- **Air-gapped and low-latency environments** can run the resolver locally against an in-memory, SQLite, Redis, or Memcached store with zero external network calls after cloning the registry.

### Shared Value Creation
- **Cross-implementation security & parity:** Improvements discovered in `SecID-Server-API` (e.g., recursive MCP untrusted-text relocation in `python/sanitize.py`) and in `SecID-Service` (e.g., `@version` validation, tight vs open child pattern separation, single-percent-decode fallback) reinforce each other through shared conformance testing.

## AI Enablement

1. **Who becomes more AI-capable because CSA ships this?**
   - **Enterprise AI agents and internal security copilots** running inside private VPCs or air-gapped environments can connect to a local `/mcp` server (`resolve`, `lookup`, `describe`) that resolves both public security standards and internal company controls/advisories.
   - **Security tool builders** get a clean FastAPI factory (`create_app(ServerConfig(...))`) they can embed directly into Python security pipelines.
2. **Mechanism:**
   - **Both novel-surface creation and friction removal.** Multi-registry overlay resolution (`--registry public --registry private`) over MCP and REST creates a unified knowledge surface across public and private security identifiers, while zero-config lazy loading (`--load lazy`) removes deployment friction.
3. **Counterfactual:**
   - **"Enterprises build incompatible internal lookup tools or skip SecID for private data."** Without an official self-hosted server supporting private registry overlays and identical REST/MCP contracts, organizations cannot use a single identifier grammar across public and private security knowledge.

## Resources, risks, and operational burden assessment

### Operational burden

*(Note: `SecID-Server-API` is a self-hosted software distribution repository; CSA's hosted production runtime is documented in [`CloudSecurityAlliance/SecID-Service`](https://github.com/CloudSecurityAlliance/SecID-Service)'s `OPERATIONAL-RESOURCES.md` and `BACKUP-RESOURCES.md`.)*

- **Technical operations:** GitHub Actions CI (`.github/workflows/test.yml` running `pytest` across Python 3.10–3.13 against `SecID` and `SecID-Client-SDK`, plus CodeQL). No CSA-operated runtime servers.
- **Human / agent operations:** Governed autonomously by the SecID governing agent ([`CSA-Internal-Governance/SecID`](https://github.com/CSA-Internal-Governance/SecID)) with mandatory two-agent cross-vendor code review (`AGENTS.md`).
- **Total ongoing FTE:** < 0.03 human FTE.
- **Automation / minimization strategy:**
  - `python/test_real_registry.py` automatically tests structured examples in `CloudSecurityAlliance/SecID` (skipping `version_required` sources that require an explicit `@version` on unversioned source lookups) and all applicable server-resolution fixtures in `CloudSecurityAlliance/SecID-Client-SDK` (`tests/conformance/fixtures.json` plus the real-namespace resolution cases in `tests/fixtures.json`, excluding client-side transport/mock-only fixtures) in both `lazy` and `bulk` load modes.
- **Burden-exceeds-value / sunset trigger:** Keep the Python implementation as the canonical reference server and defer the planned TypeScript, Go, or Docker distributions until concrete external demand warrants the additional maintenance surface. Reconsider maintaining the separate Python port if keeping parity with `SecID-Service` exceeds 4 hours/month of engineering effort or if packaging `SecID-Service`'s TypeScript resolver directly in a self-hosted container replaces the need for a separate language port.

### Risks and mitigations

- **Behavioral drift from `SecID-Service` →** Mitigated by `python/test_real_registry.py` (`TARGETED_CASES`, shared `SecID-Client-SDK` fixtures, and full-registry example sweep) running in CI on every PR.
- **Insecure self-hosted deployment exposure →** Mitigated by safe-by-default server settings (`python/secid_server.py`): binds to `127.0.0.1` by default, disables `/admin/reload` (`401`) unless `SECID_RELOAD_TOKEN` is configured and matched in constant time, disables CORS unless `--cors-origin` is explicitly provided, requires `mcp>=1.23.0,<3.0.0` for loopback DNS-rebinding protection (`GHSA-9h52-p55h-vw2f`), and pins registry type paths to the fixed 10-type constant (`SECID_TYPES`).
- **Prompt injection via third-party or overlay registry text on `/mcp` →** Mitigated by recursive MCP output sanitization (`python/sanitize.py`), relocating untrusted text fields into `registry_text_untrusted` and stripping C0/C1/zero-width/bidi control characters.

## Success metrics

Tracked in [`GOALS.md`](GOALS.md):
- **Resolver parity:** 100% pass rate on `python/test_smoke.py` and `python/test_real_registry.py` (198 tests across Python 3.10–3.13 in both `lazy` and `bulk` modes).
- **Safe-by-default posture:** 100% enforcement of loopback default binding, token-gated `/admin/reload`, URL template scheme/metacharacter hardening, and recursive `/mcp` output sanitization.
