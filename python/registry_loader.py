"""Load SecID registry JSON files into a storage backend.

Loading strategies:
- bulk: load all entries at startup
- lazy: load on first request (the resolver builds a per-type index on first use)
- update: after `git pull`, reload only namespaces changed since the last load
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


def _reject_unsafe_segment(value: Optional[str]) -> bool:
    """Return True if a namespace/subpath segment is unsafe to join into a path.

    Rejects parent-dir traversal ('..'), absolute paths, backslashes, and NUL.
    Namespace/subpath segments are derived from the untrusted query string, and
    pathlib's '/' join does NOT collapse '..', so a crafted namespace could
    otherwise escape the registry tree (arbitrary .json read / existence oracle).
    """
    if not value:
        return False
    if "\x00" in value or "\\" in value:
        return True
    if value.startswith("/"):
        return True
    return any(part == ".." for part in value.split("/"))


def _contained_path(registry_dir: str, full_path: Path) -> Optional[Path]:
    """Return full_path iff it resolves inside registry_dir, else None.

    Resolves symlinks and collapses '..' on both sides, then confirms the
    target stays within the registry root. Fails closed (None) on escape or
    any resolution error, so callers treat it as 'file not present'.
    """
    try:
        base = Path(registry_dir).resolve()
        target = full_path.resolve()
        target.relative_to(base)  # raises ValueError if outside base
    except (ValueError, OSError):
        return None
    return target


def _is_namespace_file(rel: Path) -> bool:
    """True for registry/<type>/**/<name>.json namespace files.

    Excludes type-level files (registry/<type>.json, one path part) and anything
    under or named with a leading underscore (_template.json, _deferred/).
    """
    if rel.suffix != ".json" or len(rel.parts) < 3:
        return False
    return not any(part.startswith("_") for part in rel.parts)


def load_namespaces(registry_dirs: list[str], secid_type: str) -> dict[str, dict]:
    """Read every namespace file of one type, keyed by its `namespace` field.

    Precedence is deterministic: registry_dirs are applied in order and a later
    directory overrides an earlier one for the same namespace (a private overlay
    listed after the public registry wins). Every loader uses this rule -
    bulk_load, the resolver's per-type index, load_single, and update_load - so
    which copy you get never depends on query order.

    The `namespace` field inside the file is canonical, not the path: reversing
    'uk/gov/legislation.json' is ambiguous, the field is not.
    """
    found: dict[str, dict] = {}
    for registry_dir in registry_dirs:
        root = Path(registry_dir)
        type_dir = root / secid_type
        if not type_dir.is_dir():
            continue
        for json_file in sorted(type_dir.rglob("*.json")):
            if not _is_namespace_file(json_file.relative_to(root)):
                continue
            try:
                data = json.loads(json_file.read_text())
            except (OSError, ValueError) as e:
                logger.warning(f"Skipping {json_file}: {e}")
                continue
            namespace = data.get("namespace") if isinstance(data, dict) else None
            if not namespace:
                logger.warning(f"Skipping {json_file}: no namespace field")
                continue
            if data.get("type") != secid_type:
                logger.warning(
                    f"Skipping {json_file}: type {data.get('type')!r} does not match "
                    f"directory {secid_type!r}"
                )
                continue
            found[namespace] = data
    return found


def find_registry_json_files(registry_dirs: list[str]) -> list[Path]:
    """Find all namespace .json files across one or more registry directories.

    Later directories override earlier ones for the same relative path.
    Prefer load_namespaces(), which applies precedence by namespace.
    """
    files: dict[str, Path] = {}  # key -> path (later wins)
    for registry_dir in registry_dirs:
        root = Path(registry_dir)
        if not root.is_dir():
            logger.warning(f"Registry directory not found: {registry_dir}")
            continue
        for json_file in sorted(root.rglob("*.json")):
            rel = json_file.relative_to(root)
            if _is_namespace_file(rel):
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
            type_file = _contained_path(registry_dir, Path(registry_dir) / f"{secid_type}.json")
            if type_file and type_file.exists():
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
    """Load all registry JSON files into the store. Returns count loaded.

    Keys already in the store that the registry no longer produces are evicted,
    so a bulk load after files were deleted leaves no stale namespaces behind.
    """
    for registry_dir in registry_dirs:
        if not Path(registry_dir).is_dir():
            logger.warning(f"Registry directory not found: {registry_dir}")

    expected: set[str] = set()
    for secid_type in SECID_TYPES:
        for namespace, data in load_namespaces(registry_dirs, secid_type).items():
            key = f"secid:{secid_type}/{namespace}"
            store.set(key, json.dumps(data))
            expected.add(key)

    for key in _namespace_keys(store):
        if key not in expected:
            store.delete(key)

    build_type_index(store, registry_dirs)
    logger.info(f"Bulk loaded {len(expected)} namespaces from {len(registry_dirs)} registry dir(s)")
    return len(expected)


def _namespace_keys(store: Store) -> list[str]:
    """Store keys of the form secid:<type>/<namespace>."""
    out = []
    for key in store.keys():
        if not key.startswith("secid:"):
            continue
        secid_type, sep, _ = key[len("secid:"):].partition("/")
        if sep and secid_type in SECID_TYPES:
            out.append(key)
    return out


def load_single(store: Store, registry_dirs: list[str], secid_type: str, namespace: str) -> Optional[dict]:
    """Lazy load a single namespace entry. Returns the data or None."""
    # Reject hostile namespaces before they reach the filesystem join.
    if _reject_unsafe_segment(namespace):
        logger.warning(f"Rejected unsafe namespace: {namespace!r}")
        return None

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
        # Defense in depth: confirm the joined path stays inside the registry
        # tree even if a hostile segment slipped past the check above.
        # OSError covers hostile-but-safe input such as a segment longer than
        # the filesystem's name limit ("File name too long"): that is simply
        # "not in the registry", never a 500.
        try:
            full_path = _contained_path(registry_dir, Path(registry_dir) / secid_type / fs_path)
            if not (full_path and full_path.is_file()):
                continue
            data = json.loads(full_path.read_text())
        except (OSError, ValueError) as e:
            logger.debug(f"Cannot load {secid_type}/{namespace} from {registry_dir}: {e}")
            continue
        key = build_namespace_key(data)
        if key:
            store.set(key, json.dumps(data))
            return data
    return None


def load_type_info(registry_dirs: list[str], secid_type: str) -> Optional[dict]:
    """Read registry/<secid_type>.json from the first registry dir that has it.

    Returns the parsed type-level metadata (description, purpose, format,
    examples, etc.) or None if no registry directory has the file.

    Used by the resolver for bare-type queries (e.g., secid:advisory) in
    lazy mode, where the full type index isn't pre-built. Also used by
    list_all_types() to assemble the /api/v1/types response.
    """
    if _reject_unsafe_segment(secid_type):
        logger.warning(f"Rejected unsafe type: {secid_type!r}")
        return None
    for registry_dir in registry_dirs:
        try:
            type_file = _contained_path(registry_dir, Path(registry_dir) / f"{secid_type}.json")
            if type_file and type_file.is_file():
                return json.loads(type_file.read_text())
        except (OSError, ValueError) as e:
            logger.warning(f"Error reading {secid_type}.json in {registry_dir}: {e}")
    return None


def list_all_types(registry_dirs: list[str]) -> list[dict]:
    """Return metadata for all 10 SecID types in canonical order.

    Each entry has the shape:
        {
            "type": "advisory",
            "description": "<short description from registry/advisory.json>",
            "long_description": "<purpose field, same source>",
            "subtypes": []   # Python Server-API doesn't yet enumerate subtype
                             # descriptions; that data lives in SecID-Service's
                             # type-registry.ts. Future work: centralize a
                             # type-registry.json in the SecID spec repo so
                             # all implementations read from one canonical source.
        }

    Types with no registry/<type>.json file get empty description fields
    rather than being omitted — the type list itself is canonical (always 10)
    even if metadata is missing.
    """
    out: list[dict] = []
    for secid_type in SECID_TYPES:
        info = load_type_info(registry_dirs, secid_type) or {}
        out.append({
            "type": secid_type,
            "description": info.get("description", ""),
            "long_description": info.get("purpose", info.get("description", "")),
            "subtypes": [],
        })
    return out


# ---------------------------------------------------------------------------
# Reload after `git pull`
# ---------------------------------------------------------------------------


def _git(args: list[str], cwd: Path) -> Optional[str]:
    """Run git and return stdout, or None if git is missing or the command fails."""
    try:
        result = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode == 0 else None


def git_head(registry_dir: str) -> Optional[str]:
    """Commit SHA checked out in the repo containing registry_dir, or None."""
    out = _git(["rev-parse", "HEAD"], Path(registry_dir))
    return out.strip() if out else None


def loaded_commits(registry_dirs: list[str]) -> dict[str, Optional[str]]:
    """Snapshot of the HEAD commit of each registry dir. Record this when the
    registry is loaded and pass it to update_load() so a reload diffs against
    what is actually loaded."""
    return {d: git_head(d) for d in registry_dirs}


def _changed_namespaces(registry_dir: str, base: str, head: str) -> Optional[set[tuple[str, str]]]:
    """(type, namespace) pairs touched between two commits under registry_dir.

    Handles A/M/T (read the new file), D (read the old blob with `git show`,
    since the file is gone), and R/C (both sides) - `git diff -M` reports a
    rename as "R100<TAB>old<TAB>new", which the old code mis-split into one
    path. Returns None when git cannot answer (unknown base commit, not a
    repo), which tells the caller to fall back to a full reload.
    """
    reg = Path(registry_dir).resolve()
    top_out = _git(["rev-parse", "--show-toplevel"], reg)
    if not top_out:
        return None
    top = Path(top_out.strip()).resolve()
    try:
        rel_dir = reg.relative_to(top)
    except ValueError:
        return None
    diff = _git(
        ["diff", "--name-status", "-M", base, head, "--", str(rel_dir) or "."], top,
    )
    if diff is None:
        return None

    touched: set[tuple[str, str]] = set()

    def note(rev: str, path: str) -> None:
        try:
            rel = Path(path).relative_to(rel_dir)
        except ValueError:
            return
        if not _is_namespace_file(rel):
            return
        raw = _git(["show", f"{rev}:{path}"], top)
        try:
            data = json.loads(raw) if raw else None
        except ValueError:
            data = None
        if isinstance(data, dict) and data.get("namespace"):
            touched.add((rel.parts[0], data["namespace"]))

    for line in diff.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status = parts[0][:1]
        if status in ("R", "C") and len(parts) >= 3:
            if status == "R":
                note(base, parts[1])
            note(head, parts[2])
        elif status == "D":
            note(base, parts[1])
        elif status in ("A", "M", "T"):
            note(head, parts[1])
    return touched


def _full_reload(store: Store, registry_dirs: list[str],
                 commits: Optional[dict]) -> int:
    count = bulk_load(store, registry_dirs)
    if commits is not None:
        commits.update(loaded_commits(registry_dirs))
    return count


def update_load(store: Store, registry_dirs: list[str], since_commit: Optional[str] = None,
                commits: Optional[dict] = None) -> int:
    """Reload namespaces changed since the registry was last loaded.

    `commits` maps each registry dir to the commit it was last loaded at (see
    loaded_commits()); it is updated in place to the new HEAD. `since_commit`
    overrides the base commit for every dir. Changed namespaces - including
    deletions and both sides of renames - are re-resolved against ALL registry
    dirs, so overlay precedence holds and a namespace deleted from the private
    overlay falls back to the public copy rather than disappearing.

    Falls back to a full reload (which also evicts deleted namespaces) when a
    dir is not in git, git is unavailable, or no base commit is known.

    Returns the number of namespaces updated or removed.
    """
    touched: set[tuple[str, str]] = set()
    heads: dict[str, str] = {}
    for registry_dir in registry_dirs:
        head = git_head(registry_dir)
        base = since_commit or (commits or {}).get(registry_dir)
        if not head or not base:
            logger.info(f"No base commit for {registry_dir}; doing a full reload")
            return _full_reload(store, registry_dirs, commits)
        heads[registry_dir] = head
        if base == head:
            continue
        changed = _changed_namespaces(registry_dir, base, head)
        if changed is None:
            logger.info(f"git diff {base}..{head} failed for {registry_dir}; doing a full reload")
            return _full_reload(store, registry_dirs, commits)
        touched |= changed

    for secid_type in sorted({t for t, _ in touched if t in SECID_TYPES}):
        current = load_namespaces(registry_dirs, secid_type)
        for t, namespace in touched:
            if t != secid_type:
                continue
            key = f"secid:{t}/{namespace}"
            if namespace in current:
                store.set(key, json.dumps(current[namespace]))
                logger.info(f"Updated: {key}")
            else:
                store.delete(key)
                logger.info(f"Removed: {key}")

    if commits is not None:
        commits.update(heads)
    if touched:
        build_type_index(store, registry_dirs)
    logger.info(f"Update loaded {len(touched)} changed namespaces")
    return len(touched)
