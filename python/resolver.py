"""SecID resolver — core resolution logic.

Given a SecID string, parse it, look up the namespace in the store,
walk the match_nodes tree, and return the result.
"""

import json
import re
from typing import Optional

from storage import Store

SECID_TYPES = [
    "advisory", "capability", "control", "disclosure", "entity",
    "methodology", "reference", "regulation", "ttp", "weakness",
]


def resolve(store: Store, secid_query: str, registry_dirs: list[str] = None) -> dict:
    """Resolve a SecID string. Returns the API response envelope."""
    secid_query = secid_query.strip()

    # Strip scheme
    if secid_query.startswith("secid:"):
        remainder = secid_query[6:]
    else:
        return _error(secid_query, "Missing 'secid:' prefix")

    if not remainder:
        # Bare "secid:" — return global index
        global_index = store.get("secid:*")
        if global_index:
            data = json.loads(global_index)
            return {
                "secid_query": secid_query,
                "status": "found",
                "results": [{
                    "secid": "secid:*",
                    "data": data,
                }],
            }
        return _not_found(secid_query)

    # Extract type
    slash_idx = remainder.find("/")
    if slash_idx == -1:
        # Just a type, no namespace: secid:advisory
        candidate_type = remainder.lower()
        if candidate_type in SECID_TYPES:
            type_data = store.get(f"secid:{candidate_type}")
            if type_data:
                return {
                    "secid_query": secid_query,
                    "status": "found",
                    "results": [{
                        "secid": f"secid:{candidate_type}",
                        "data": json.loads(type_data),
                    }],
                }
        return _not_found(secid_query)

    secid_type = remainder[:slash_idx].lower()
    if secid_type not in SECID_TYPES:
        return _error(secid_query, f"Unknown type '{secid_type}'. Valid: {', '.join(SECID_TYPES)}")

    after_type = remainder[slash_idx + 1:]

    # Extract subpath (everything after #)
    hash_idx = after_type.find("#")
    if hash_idx != -1:
        path_part = after_type[:hash_idx]
        subpath = after_type[hash_idx + 1:]
    else:
        path_part = after_type
        subpath = None

    # Extract version from path (everything after @)
    at_idx = path_part.find("@")
    if at_idx != -1:
        path_no_version = path_part[:at_idx]
        version = path_part[at_idx + 1:]
    else:
        path_no_version = path_part
        version = None

    # Try shortest-to-longest namespace matching
    namespace, name = _match_namespace(store, secid_type, path_no_version, registry_dirs)

    if namespace is None:
        return _not_found(secid_query, f"No namespace found for '{path_no_version}' in type '{secid_type}'")

    # Load namespace data
    raw = store.get(f"secid:{secid_type}/{namespace}")
    if not raw:
        return _not_found(secid_query)

    data = json.loads(raw)
    match_nodes = data.get("match_nodes", [])

    # If no name and no subpath, return the namespace info
    if not name and not subpath:
        return _namespace_result(secid_query, secid_type, namespace, data)

    # Match against match_nodes
    search_term = name or ""
    results = _walk_match_nodes(match_nodes, search_term, subpath, version,
                                 secid_type, namespace, data)

    if results:
        return {
            "secid_query": secid_query,
            "status": "found",
            "results": results,
        }

    # Partial match — return what we have at namespace level
    return {
        "secid_query": secid_query,
        "status": "related",
        "results": [_build_namespace_summary(secid_type, namespace, data)],
    }


def _match_namespace(store: Store, secid_type: str, path: str,
                     registry_dirs: list[str] = None) -> tuple[Optional[str], Optional[str]]:
    """Shortest-to-longest namespace matching.

    Given path "github.com/advisories/ghsa", try:
      1. github.com → name = advisories/ghsa
      2. github.com/advisories → name = ghsa
      3. github.com/advisories/ghsa → name = None

    Returns (namespace, remaining_name) or (None, None).
    """
    segments = path.split("/")
    best_namespace = None
    best_name = None

    for i in range(1, len(segments) + 1):
        candidate_ns = "/".join(segments[:i])
        remaining = "/".join(segments[i:]) if i < len(segments) else None

        key = f"secid:{secid_type}/{candidate_ns}"
        if store.get(key) is not None:
            best_namespace = candidate_ns
            best_name = remaining

        # Try lazy loading if we have registry dirs
        elif registry_dirs:
            from registry_loader import load_single
            if load_single(store, registry_dirs, secid_type, candidate_ns):
                best_namespace = candidate_ns
                best_name = remaining

    return best_namespace, best_name


def _walk_match_nodes(nodes: list, name: str, subpath: Optional[str],
                       version: Optional[str], secid_type: str,
                       namespace: str, ns_data: dict) -> list[dict]:
    """Walk the match_nodes tree to find matching entries."""
    results = []

    # If we have a name, match it against top-level nodes
    if name:
        for node in nodes:
            for pattern in node.get("patterns", []):
                try:
                    if re.match(pattern, name):
                        result = _build_node_result(
                            node, subpath, version, secid_type, namespace, name, ns_data
                        )
                        if result:
                            results.append(result)
                        break
                except re.error:
                    continue
    elif subpath:
        # No name but have subpath — match subpath against nodes
        for node in nodes:
            for pattern in node.get("patterns", []):
                try:
                    if re.match(pattern, subpath):
                        result = _build_leaf_result(node, secid_type, namespace, subpath, ns_data)
                        if result:
                            results.append(result)
                        break
                except re.error:
                    continue
    else:
        # No name, no subpath — return all sources
        for node in nodes:
            desc = node.get("description", "")
            node_name = _extract_name_from_patterns(node.get("patterns", []))
            secid = f"secid:{secid_type}/{namespace}/{node_name}" if node_name else f"secid:{secid_type}/{namespace}"
            result = {
                "secid": secid,
                "data": {
                    "official_name": desc,
                    "description": desc,
                    **({"child_count": len(node.get("children", []))} if node.get("children") else {}),
                },
            }
            if node.get("weight"):
                result["weight"] = node["weight"]
            results.append(result)

    return results


def _build_node_result(node: dict, subpath: Optional[str], version: Optional[str],
                        secid_type: str, namespace: str, name: str,
                        ns_data: dict) -> Optional[dict]:
    """Build a result from a matched node, optionally drilling into children."""
    children = node.get("children", [])

    # If we have a subpath, try to match against children
    if subpath and children:
        for child in children:
            for pattern in child.get("patterns", []):
                try:
                    if re.match(pattern, subpath):
                        child_data = child.get("data", {})
                        secid = f"secid:{secid_type}/{namespace}/{name}#{subpath}"
                        result = {"secid": secid}
                        if child.get("weight"):
                            result["weight"] = child["weight"]
                        if child_data.get("url"):
                            result["url"] = child_data["url"]
                        result["data"] = {
                            "description": child.get("description", ""),
                            **{k: v for k, v in child_data.items() if k != "url"},
                        }
                        return result
                except re.error:
                    continue

    # If we have a version, try matching against children
    if version and children:
        for child in children:
            for pattern in child.get("patterns", []):
                try:
                    if re.match(pattern, version):
                        child_data = child.get("data", {})
                        secid = f"secid:{secid_type}/{namespace}/{name}@{version}"
                        result = {"secid": secid}
                        if child.get("weight"):
                            result["weight"] = child["weight"]
                        if child_data.get("url"):
                            result["url"] = child_data["url"]
                        result["data"] = {
                            "description": child.get("description", ""),
                            **{k: v for k, v in child_data.items() if k != "url"},
                        }
                        return result
                except re.error:
                    continue

    # Return the node itself
    node_data = node.get("data", {})
    secid = f"secid:{secid_type}/{namespace}/{name}"
    if version:
        secid += f"@{version}"
    if subpath:
        secid += f"#{subpath}"

    result = {"secid": secid}
    if node.get("weight"):
        result["weight"] = node["weight"]
    if node_data.get("url"):
        result["url"] = node_data["url"]

    # Build data object with description and patterns
    result_data = {
        "official_name": node.get("description", ""),
        "description": node.get("description", ""),
        "urls": ns_data.get("urls", []),
    }
    if children:
        result_data["patterns"] = [
            {"pattern": p, "description": child.get("description", "")}
            for child in children
            for p in child.get("patterns", [])
        ]
    if node_data.get("examples"):
        result_data["examples"] = node_data["examples"]

    result["data"] = result_data
    return result


def _build_leaf_result(node: dict, secid_type: str, namespace: str,
                        subpath: str, ns_data: dict) -> Optional[dict]:
    """Build a result for a direct subpath match (no name level)."""
    node_data = node.get("data", {})
    secid = f"secid:{secid_type}/{namespace}#{subpath}"
    result = {"secid": secid}
    if node.get("weight"):
        result["weight"] = node["weight"]
    if node_data.get("url"):
        result["url"] = node_data["url"]
    result["data"] = {
        "description": node.get("description", ""),
        **{k: v for k, v in node_data.items() if k != "url"},
    }
    return result


def _build_namespace_summary(secid_type: str, namespace: str, data: dict) -> dict:
    """Build a summary result for a namespace (no specific source matched)."""
    return {
        "secid": f"secid:{secid_type}/{namespace}",
        "data": {
            "official_name": data.get("official_name", ""),
            "description": data.get("official_name", ""),
            "urls": data.get("urls", []),
            "source_count": len(data.get("match_nodes", [])),
            "patterns": [
                {"pattern": p, "description": node.get("description", "")}
                for node in data.get("match_nodes", [])
                for p in node.get("patterns", [])
            ],
        },
    }


def _namespace_result(secid_query: str, secid_type: str, namespace: str, data: dict) -> dict:
    """Return namespace-level info with all sources listed."""
    return {
        "secid_query": secid_query,
        "status": "found",
        "results": [_build_namespace_summary(secid_type, namespace, data)],
    }


def _extract_name_from_patterns(patterns: list) -> Optional[str]:
    """Try to extract a readable name from regex patterns."""
    for p in patterns:
        # Strip common regex anchors and flags
        clean = re.sub(r'^\(\?[imsxu]*\)', '', p)
        clean = clean.strip("^$")
        if clean and re.match(r'^[\w.-]+$', clean):
            return clean
    return None


def _not_found(secid_query: str, message: str = None) -> dict:
    result = {
        "secid_query": secid_query,
        "status": "not_found",
        "results": [],
    }
    if message:
        result["message"] = message
    return result


def _error(secid_query: str, message: str) -> dict:
    return {
        "secid_query": secid_query,
        "status": "error",
        "results": [],
        "message": message,
    }
