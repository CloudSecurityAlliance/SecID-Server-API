"""Load SecID registry JSON files into a storage backend.

Supports three loading strategies:
- bulk: load all entries at startup
- lazy: load on first request (handled by resolver, not here)
- update: reload only files changed since last sync
"""

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from storage import Store

logger = logging.getLogger(__name__)

SECID_TYPES = [
    "advisory", "capability", "control", "disclosure", "entity",
    "methodology", "reference", "regulation", "ttp", "weakness",
]


def find_registry_json_files(registry_dirs: list[str]) -> list[Path]:
    """Find all .json registry files across one or more registry directories.

    Later directories override earlier ones for the same namespace+type
    (enables private registry overlays).
    """
    files: dict[str, Path] = {}  # key → path (later wins)
    for registry_dir in registry_dirs:
        root = Path(registry_dir)
        if not root.is_dir():
            logger.warning(f"Registry directory not found: {registry_dir}")
            continue
        for json_file in sorted(root.rglob("*.json")):
            rel = json_file.relative_to(root)
            # Skip type-level JSON (e.g., advisory.json, methodology.json)
            # Skip templates and deferred
            if "_" in json_file.stem or str(rel).count("/") < 2:
                continue
            files[str(rel)] = json_file
    return list(files.values())


def build_namespace_key(data: dict) -> Optional[str]:
    """Build the KV key for a namespace entry: secid:{type}/{namespace}"""
    ns_type = data.get("type")
    namespace = data.get("namespace")
    if not ns_type or not namespace:
        return None
    return f"secid:{ns_type}/{namespace}"


def build_type_index(store: Store, registry_dirs: list[str]) -> None:
    """Build type-level index entries (secid:{type} → list of namespaces).

    Also builds the global index (secid:* → all namespaces across all types).
    """
    type_namespaces: dict[str, list[dict]] = {t: [] for t in SECID_TYPES}

    for key in store.keys():
        if not key.startswith("secid:"):
            continue
        parts = key[len("secid:"):].split("/", 1)
        if len(parts) != 2:
            continue
        secid_type, namespace = parts
        if secid_type not in SECID_TYPES:
            continue

        raw = store.get(key)
        if not raw:
            continue
        data = json.loads(raw)
        type_namespaces[secid_type].append({
            "namespace": namespace,
            "official_name": data.get("official_name", ""),
            "common_name": data.get("common_name"),
            "source_count": len(data.get("match_nodes", [])),
        })

    # Write type indexes
    for secid_type, namespaces in type_namespaces.items():
        # Load type-level JSON if it exists
        type_json = None
        for registry_dir in registry_dirs:
            type_file = Path(registry_dir) / f"{secid_type}.json"
            if type_file.exists():
                type_json = json.loads(type_file.read_text())
                break

        index = {
            "secid": f"secid:{secid_type}",
            "type": secid_type,
            "description": type_json.get("description", "") if type_json else "",
            "purpose": type_json.get("purpose", "") if type_json else "",
            "namespace_count": len(namespaces),
            "namespaces": sorted(namespaces, key=lambda n: n["namespace"]),
        }
        store.set(f"secid:{secid_type}", json.dumps(index))

    # Global index
    all_namespaces = []
    for secid_type, namespaces in type_namespaces.items():
        for ns in namespaces:
            all_namespaces.append({
                "type": secid_type,
                **ns,
            })
    global_index = {
        "total_namespaces": len(all_namespaces),
        "types": {t: len(ns) for t, ns in type_namespaces.items()},
        "child_index": sorted(all_namespaces, key=lambda n: (n["type"], n["namespace"])),
    }
    store.set("secid:*", json.dumps(global_index))

    total = sum(len(ns) for ns in type_namespaces.values())
    logger.info(f"Built type indexes: {total} namespaces across {len(SECID_TYPES)} types")


def bulk_load(store: Store, registry_dirs: list[str]) -> int:
    """Load all registry JSON files into the store. Returns count loaded."""
    files = find_registry_json_files(registry_dirs)
    loaded = 0

    for json_file in files:
        try:
            data = json.loads(json_file.read_text())
            key = build_namespace_key(data)
            if key:
                store.set(key, json.dumps(data))
                loaded += 1
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Skipping {json_file}: {e}")

    build_type_index(store, registry_dirs)
    logger.info(f"Bulk loaded {loaded} namespaces from {len(registry_dirs)} registry dir(s)")
    return loaded


def load_single(store: Store, registry_dirs: list[str], secid_type: str, namespace: str) -> Optional[dict]:
    """Lazy load a single namespace entry. Returns the data or None."""
    # Convert namespace to filesystem path: redhat.com → com/redhat.json
    parts = namespace.split("/", 1)
    domain = parts[0]
    subpath = parts[1] if len(parts) > 1 else None

    domain_parts = domain.split(".")
    domain_parts.reverse()
    fs_path = "/".join(domain_parts)
    if subpath:
        fs_path += "/" + subpath
    fs_path += ".json"

    for registry_dir in reversed(registry_dirs):  # later dirs take priority
        full_path = Path(registry_dir) / secid_type / fs_path
        if full_path.exists():
            try:
                data = json.loads(full_path.read_text())
                key = build_namespace_key(data)
                if key:
                    store.set(key, json.dumps(data))
                    return data
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Error loading {full_path}: {e}")
    return None


def update_load(store: Store, registry_dirs: list[str], since_commit: Optional[str] = None) -> int:
    """Reload only files changed since a given commit. Returns count updated.

    If since_commit is None, tries to use a stored marker.
    Falls back to bulk load if git is unavailable.
    """
    for registry_dir in registry_dirs:
        repo_root = Path(registry_dir).parent  # registry/ is inside the repo
        if not (repo_root / ".git").exists():
            logger.info(f"No git repo at {repo_root}, falling back to bulk load")
            return bulk_load(store, registry_dirs)

    updated = 0
    for registry_dir in registry_dirs:
        repo_root = Path(registry_dir).parent
        try:
            if since_commit:
                result = subprocess.run(
                    ["git", "diff", "--name-status", since_commit, "HEAD", "--", "registry/"],
                    capture_output=True, text=True, cwd=repo_root,
                )
            else:
                # Default: last 24 hours of changes
                result = subprocess.run(
                    ["git", "log", "--name-status", "--since=24 hours ago", "--pretty=format:", "--", "registry/"],
                    capture_output=True, text=True, cwd=repo_root,
                )

            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split("\t", 1)
                if len(parts) != 2:
                    continue
                status, filepath = parts

                if not filepath.endswith(".json") or "_" in Path(filepath).stem:
                    continue

                full_path = repo_root / filepath
                if status in ("A", "M"):  # added or modified
                    if full_path.exists():
                        try:
                            data = json.loads(full_path.read_text())
                            key = build_namespace_key(data)
                            if key:
                                store.set(key, json.dumps(data))
                                updated += 1
                                logger.info(f"Updated: {key}")
                        except (json.JSONDecodeError, KeyError) as e:
                            logger.warning(f"Error loading {filepath}: {e}")
                elif status == "D":  # deleted
                    # Try to figure out the key from the path
                    logger.info(f"Deleted: {filepath}")
                    updated += 1

        except FileNotFoundError:
            logger.warning("git not found, falling back to bulk load")
            return bulk_load(store, registry_dirs)

    if updated > 0:
        build_type_index(store, registry_dirs)
    logger.info(f"Update loaded {updated} changed files")
    return updated
