#!/usr/bin/env python3
"""SecID Server — self-hosted resolver with pluggable storage.

Two ways to use this module:

  1. CLI:    python secid_server.py --registry /path/to/SecID/registry [...]
  2. Library: from secid_server import create_app, ServerConfig
             config = ServerConfig(registry_dirs=["./registry"])
             app = create_app(config)

The factory function lets tests build a fully-configured app without
running the CLI bootstrap, and lets ASGI deployments (uvicorn, gunicorn)
construct the app from environment variables instead of argparse.

Serves:
  GET /api/v1/resolve?secid=...   — REST API (same as secid.cloudsecurityalliance.org)
  GET /health                      — health check
  POST /admin/reload               — reload registry data after git pull
  /mcp                             — MCP endpoint (when `mcp` package is installed)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Optional

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from storage import create_store
from registry_loader import bulk_load, SECID_TYPES
from resolver import resolve

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class ServerConfig:
    """Configuration for the SecID server. Pass to create_app().

    Attributes:
        registry_dirs: List of paths to registry directories. Later
            directories override earlier ones for the same namespace+type
            (overlay support).
        storage_type: One of "memory", "redis", "memcached", "sqlite".
        storage_kwargs: Backend-specific kwargs forwarded to create_store().
            For redis/memcached: {"url": "..."}. For sqlite: {"path": "..."}.
        load_mode: "lazy" (load on first request, default) or "bulk"
            (load everything at startup).
    """

    registry_dirs: list[str]
    storage_type: str = "memory"
    storage_kwargs: dict = field(default_factory=dict)
    load_mode: str = "lazy"


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(config: ServerConfig) -> FastAPI:
    """Create a configured SecID server FastAPI app.

    Used by the CLI (see main()) and by tests (via fastapi.testclient.TestClient).
    Has no module-level side effects, so importing this file is safe.
    """
    store = create_store(config.storage_type, **config.storage_kwargs)

    if config.load_mode == "bulk":
        count = bulk_load(store, config.registry_dirs)
        logger.info(f"Bulk loaded {count} namespaces into {config.storage_type} store")
    else:
        logger.info(f"Lazy loading from {config.registry_dirs} with {config.storage_type} store")

    app = FastAPI(
        title="SecID Server",
        description="Self-hosted SecID resolver",
        version="0.1.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    @app.get("/api/v1/resolve")
    async def api_resolve(
        secid: str = Query(..., description="SecID string to resolve"),
        parsability: Optional[str] = Query(
            None,
            description="Filter results by parsability: 'structured' or 'scraped'",
        ),
    ):
        """Resolve a SecID string to URLs and registry data."""
        result = resolve(store, secid, registry_dirs=config.registry_dirs)
        if parsability and "results" in result:
            result["results"] = [
                r for r in result["results"]
                if "url" not in r or r.get("parsability") == parsability
            ]
        return JSONResponse(content=result)

    @app.post("/admin/reload")
    async def admin_reload():
        """Reload registry data (after git pull)."""
        from registry_loader import update_load
        count = update_load(store, config.registry_dirs)
        return {"reloaded": count}

    @app.get("/health")
    async def health():
        """Health check — returns store type and current key count."""
        key_count = len(store.keys())
        return {"status": "ok", "store": config.storage_type, "keys": key_count}

    _try_mount_mcp(app, store, config)
    return app


def _try_mount_mcp(app: FastAPI, store, config: ServerConfig) -> None:
    """Mount /mcp endpoint if the `mcp` package is available.

    Same three tools as SecID-Service (resolve, lookup, describe). Optional
    dependency so users who only need the REST API don't have to install MCP.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        logger.info("MCP SDK not installed — /mcp endpoint disabled. Install with: pip install mcp")
        return

    mcp = FastMCP(
        "SecID",
        instructions=(
            "Self-hosted SecID resolver. Resolve, look up, and describe "
            "security knowledge identifiers."
        ),
    )

    @mcp.tool()
    def mcp_resolve(secid: str) -> str:
        """Resolve a SecID string to URLs and registry data.

        Examples:
          secid:advisory/mitre.org/cve#CVE-2021-44228  → CVE record URL
          secid:weakness/mitre.org/cwe#CWE-79          → CWE definition URL
          secid:ttp/mitre.org/attack#T1059.003          → ATT&CK technique URL
          secid:methodology/first.org/cvss@4.0          → CVSS v4.0 specification
        """
        return json.dumps(resolve(store, secid, registry_dirs=config.registry_dirs), indent=2)

    @mcp.tool()
    def mcp_lookup(type: str, identifier: str) -> str:
        """Look up a security identifier by type and identifier string.

        Args:
            type: Security knowledge type (advisory, capability, control, disclosure,
                  entity, methodology, reference, regulation, ttp, weakness)
            identifier: The identifier to search for (e.g., CVE-2021-44228, CWE-79)
        """
        secid = f"secid:{type}/{identifier}"
        return json.dumps(resolve(store, secid, registry_dirs=config.registry_dirs), indent=2)

    @mcp.tool()
    def mcp_describe(secid: str) -> str:
        """Describe a SecID type, namespace, or source.

        Examples:
          secid:advisory                    → list all advisory namespaces
          secid:advisory/mitre.org          → describe MITRE's advisory sources
          secid:methodology                 → list all methodology namespaces
        """
        hash_idx = secid.find("#")
        if hash_idx != -1:
            secid = secid[:hash_idx]
        return json.dumps(resolve(store, secid, registry_dirs=config.registry_dirs), indent=2)

    app.mount("/mcp", mcp.streamable_http_app())
    logger.info("MCP endpoint available at /mcp")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SecID Self-Hosted Server")
    parser.add_argument(
        "--registry", action="append", default=[],
        help="Path to registry directory (can specify multiple for overlay). Default: ./registry",
    )
    parser.add_argument("--storage", default="memory", choices=["memory", "redis", "memcached", "sqlite"])
    parser.add_argument("--redis-url", default="redis://localhost:6379")
    parser.add_argument("--memcached-url", default="localhost:11211")
    parser.add_argument("--sqlite-path", default=":memory:")
    parser.add_argument("--load", default="lazy", choices=["lazy", "bulk"])
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser.parse_args(argv)


def _resolve_registry_dirs(provided: list[str]) -> list[str]:
    """If no --registry was passed, search common host-local locations.

    Returns the list to use (provided as-is if non-empty, or a single
    auto-discovered path, or empty list if nothing found).
    """
    if provided:
        return provided
    for candidate in [
        "./registry",
        "../SecID/registry",
        os.path.expanduser("~/GitHub/CloudSecurityAlliance/SecID/registry"),
    ]:
        if os.path.isdir(candidate):
            return [candidate]
    return []


def _build_storage_kwargs(args: argparse.Namespace) -> dict:
    if args.storage == "redis":
        return {"url": args.redis_url}
    if args.storage == "memcached":
        return {"url": args.memcached_url}
    if args.storage == "sqlite":
        return {"path": args.sqlite_path}
    return {}


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point. Returns exit code."""
    args = _parse_args(argv)

    registry_dirs = _resolve_registry_dirs(args.registry)
    if not registry_dirs:
        print(
            "Error: No registry directory found. Use --registry /path/to/SecID/registry",
            file=sys.stderr,
        )
        return 1

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    config = ServerConfig(
        registry_dirs=registry_dirs,
        storage_type=args.storage,
        storage_kwargs=_build_storage_kwargs(args),
        load_mode=args.load,
    )

    app = create_app(config)

    import uvicorn
    logger.info(f"Starting SecID server on {args.host}:{args.port}")
    logger.info(f"Registry: {registry_dirs}")
    logger.info(f"Storage: {args.storage}, Loading: {args.load}")
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
