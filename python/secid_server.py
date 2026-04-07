#!/usr/bin/env python3
"""SecID Server — self-hosted resolver with pluggable storage.

Usage:
  python secid_server.py --registry /path/to/SecID/registry
  python secid_server.py --registry /data/public/registry --registry /data/private/registry
  python secid_server.py --storage redis --redis-url redis://localhost:6379
  python secid_server.py --load bulk    # pre-load all entries at startup
  python secid_server.py --load lazy    # load on first request (default)

Serves:
  GET /api/v1/resolve?secid=...   — REST API (same as secid.cloudsecurityalliance.org)
  /mcp                             — MCP endpoint (same three tools)
"""

import argparse
import json
import logging
import os
import sys

from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from storage import create_store
from registry_loader import bulk_load, SECID_TYPES
from resolver import resolve

# --- CLI arguments ---

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

args, _ = parser.parse_known_args()

# Default registry path
if not args.registry:
    # Try common locations
    for candidate in ["./registry", "../SecID/registry", os.path.expanduser("~/GitHub/CloudSecurityAlliance/SecID/registry")]:
        if os.path.isdir(candidate):
            args.registry = [candidate]
            break
    if not args.registry:
        print("Error: No registry directory found. Use --registry /path/to/SecID/registry", file=sys.stderr)
        sys.exit(1)

logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# --- Storage + loading ---

storage_kwargs = {}
if args.storage == "redis":
    storage_kwargs["url"] = args.redis_url
elif args.storage == "memcached":
    storage_kwargs["url"] = args.memcached_url
elif args.storage == "sqlite":
    storage_kwargs["path"] = args.sqlite_path

store = create_store(args.storage, **storage_kwargs)

if args.load == "bulk":
    count = bulk_load(store, args.registry)
    logger.info(f"Bulk loaded {count} namespaces into {args.storage} store")
else:
    logger.info(f"Lazy loading from {args.registry} with {args.storage} store")

# --- FastAPI app ---

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
async def api_resolve(secid: str = Query(..., description="SecID string to resolve")):
    """Resolve a SecID string to URLs and registry data."""
    result = resolve(store, secid, registry_dirs=args.registry)
    return JSONResponse(content=result)


@app.post("/admin/reload")
async def admin_reload():
    """Reload registry data (after git pull)."""
    from registry_loader import update_load
    count = update_load(store, args.registry)
    return {"reloaded": count}


@app.get("/health")
async def health():
    """Health check."""
    key_count = len(store.keys())
    return {"status": "ok", "store": args.storage, "keys": key_count}


# --- MCP Server (same three tools as SecID-Service) ---

try:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(
        "SecID",
        instructions="Self-hosted SecID resolver. Resolve, look up, and describe security knowledge identifiers.",
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
        return json.dumps(resolve(store, secid, registry_dirs=args.registry), indent=2)

    @mcp.tool()
    def mcp_lookup(type: str, identifier: str) -> str:
        """Look up a security identifier by type and identifier string.

        Args:
            type: Security knowledge type (advisory, capability, control, disclosure,
                  entity, methodology, reference, regulation, ttp, weakness)
            identifier: The identifier to search for (e.g., CVE-2021-44228, CWE-79)
        """
        secid = f"secid:{type}/{identifier}"
        return json.dumps(resolve(store, secid, registry_dirs=args.registry), indent=2)

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
        return json.dumps(resolve(store, secid, registry_dirs=args.registry), indent=2)

    # Mount MCP at /mcp
    app.mount("/mcp", mcp.streamable_http_app())
    logger.info("MCP endpoint available at /mcp")

except ImportError:
    logger.info("MCP SDK not installed — /mcp endpoint disabled. Install with: pip install mcp")


if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting SecID server on {args.host}:{args.port}")
    logger.info(f"Registry: {args.registry}")
    logger.info(f"Storage: {args.storage}, Loading: {args.load}")
    uvicorn.run(app, host=args.host, port=args.port)
