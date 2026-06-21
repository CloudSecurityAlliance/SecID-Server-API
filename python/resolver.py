"""SecID resolver — core resolution logic.

Given a SecID string, parse it, look up the namespace in the store,
walk the match_nodes tree, and return the result.
"""

import json
import re
import urllib.parse
from typing import Optional

from registry_loader import SECID_TYPES, _reject_unsafe_segment
from storage import Store

# Format metadata fields lifted from child data to top-level result
_FORMAT_METADATA_FIELDS = ("parsability", "schema", "parsing_instructions", "auth", "content_type")


def _add_format_metadata(result: dict, data: dict) -> None:
    """Copy format metadata fields from registry data to top-level result."""
    for field in _FORMAT_METADATA_FIELDS:
        if data.get(field):
            result[field] = data[field]


_ALLOWED_URL_SCHEMES = ("https", "http")


def _validate_resolved_url(template: str, url: str) -> Optional[str]:
    """Return url unless substitution changed the template's scheme/authority.

    The open-redirect primitive (F-07-01) is the resolved host/scheme changing.
    Read the template's literal authority by neutralizing {placeholders}, then
    require the assembled URL's scheme + netloc to match. Path/query content on
    the template's own host is left intact, so identifiers that legitimately
    contain ':' etc. are unaffected. Returns None (caller drops to a
    description-only result) on a scheme/host change; non-absolute templates
    have no authority to enforce and pass through.
    """
    tpl = urllib.parse.urlsplit(re.sub(r"\{[^}]*\}", "x", template))
    if not tpl.netloc:
        return url
    res = urllib.parse.urlsplit(url)
    if res.scheme not in _ALLOWED_URL_SCHEMES:
        return None
    if res.scheme != tpl.scheme:
        return None
    if res.netloc != tpl.netloc:
        return None
    return url


def _substitute_url_template(template: str, child_data: dict, captured_input: str) -> Optional[str]:
    """Substitute {var} placeholders in a URL template.

    Two substitution modes coexist:

      1. Explicit variables — a `variables` dict on the child's data, mapping
         variable name to `{"extract": "<regex>"}`. The extract regex is matched
         against the captured input and capture group 1 (or group 0 if no
         groups) supplies the variable's value. Example: CWE's `{num}` is
         extracted from "CWE-79" via `^CWE-(\\d+)$` -> "79".

      2. Implicit `{id}` — defaults to the captured input itself unless an
         explicit `id` variable was already defined. Example: CVE's
         `{id}` in "https://www.cve.org/CVERecord?id={id}" gets "CVE-2021-44228".

    The two modes are layered: implicit-{id} fills in only if not already
    set explicitly. Unrecognized {placeholders} are left as-is so they're
    visible in output rather than silently swallowed.
    """
    if "{" not in template:
        return template

    variables: dict[str, str] = {}

    # Mode 1: explicit variables
    for var_name, var_def in (child_data.get("variables") or {}).items():
        extract_regex = var_def.get("extract") if isinstance(var_def, dict) else None
        if not extract_regex:
            continue
        try:
            m = re.match(extract_regex, captured_input)
        except re.error:
            continue
        if m:
            variables[var_name] = m.group(1) if m.groups() else m.group(0)

    # Mode 2: implicit {id} default
    variables.setdefault("id", captured_input)

    # Apply substitution. Values are kept verbatim — identifiers legitimately
    # contain ':' and other reserved chars; the authority check below (not
    # encoding) is what prevents an open redirect.
    url = template
    for name, value in variables.items():
        url = url.replace("{" + name + "}", value)
    return _validate_resolved_url(template, url)


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
            # Lazy fallback: read registry/<type>.json directly. Bulk mode
            # would have built this into store already, but lazy mode hasn't,
            # so we read from disk and synthesize a minimal type-info response.
            if registry_dirs:
                from registry_loader import load_type_info
                info = load_type_info(registry_dirs, candidate_type)
                if info:
                    return {
                        "secid_query": secid_query,
                        "status": "found",
                        "results": [{
                            "secid": f"secid:{candidate_type}",
                            "data": info,
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
        # Cross-source search: no namespace matched, but the path might be
        # an ID that matches a child pattern in one or more namespaces. E.g.,
        # `secid:advisory/CVE-2021-44228` should hit every advisory namespace
        # whose child patterns recognize the CVE-2021-44228 format.
        cross_results = _cross_source_search(
            store, secid_type, path_no_version, registry_dirs
        )
        if cross_results:
            return {
                "secid_query": secid_query,
                "status": "found",
                "results": cross_results,
            }
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
    # Boundary check: reject traversal/absolute/NUL before any candidate
    # namespace reaches the lazy loader's filesystem join. Returning
    # (None, None) flows into the existing not_found path — no error oracle.
    if _reject_unsafe_segment(path):
        return None, None

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
                        url_template = child_data.get("url")
                        resolved_url = (
                            _substitute_url_template(url_template, child_data, subpath)
                            if url_template else None
                        )
                        if resolved_url:
                            # URL-bearing result: substitute {var} placeholders;
                            # do NOT include `data` block (canonical contract).
                            result["url"] = resolved_url
                            _add_format_metadata(result, child_data)
                        else:
                            # Description-only result: include `data` block
                            # with descriptive context (variables is internal,
                            # not exposed in the public response).
                            _add_format_metadata(result, child_data)
                            result["data"] = {
                                "description": child.get("description", ""),
                                **{k: v for k, v in child_data.items() if k not in ("url", "variables")},
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
                        url_template = child_data.get("url")
                        resolved_url = (
                            _substitute_url_template(url_template, child_data, version)
                            if url_template else None
                        )
                        if resolved_url:
                            result["url"] = resolved_url
                            _add_format_metadata(result, child_data)
                        else:
                            _add_format_metadata(result, child_data)
                            result["data"] = {
                                "description": child.get("description", ""),
                                **{k: v for k, v in child_data.items() if k not in ("url", "variables")},
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
    _add_format_metadata(result, node_data)

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
    _add_format_metadata(result, node_data)
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


# ---------------------------------------------------------------------------
# Cross-source search (Phase 2.5d)
#
# Scans all namespaces of a type for child-pattern matches against a search
# term. Used when a bare-namespace query (no DNS-rooted namespace specified)
# is issued — e.g., `secid:advisory/CVE-2021-44228` should match every
# advisory namespace whose child patterns recognize the CVE-2021-44228
# format, returning aggregated results sorted by weight.
# ---------------------------------------------------------------------------


def _slug_from_pattern(pat: str) -> Optional[str]:
    """Extract a source slug from a regex pattern like '(?i)^cve$' -> 'cve'.

    Returns None if the pattern is too complex for a clean slug (e.g.,
    contains character classes, alternation, or quantifiers other than
    the canonical anchors and case-insensitive flag).
    """
    p = re.sub(r"^\(\?i\)", "", pat)
    p = re.sub(r"^\^|\$$", "", p)
    if re.fullmatch(r"[\w.-]+", p):
        return p
    return None


def _all_namespaces_of_type(
    store: Store, secid_type: str, registry_dirs: Optional[list[str]]
) -> list[str]:
    """Return all known namespaces of secid_type.

    Discovers namespaces from two sources:
      1. The store (already-loaded namespace data)
      2. The filesystem (registry/<type>/**/*.json files)

    Filesystem-discovered namespaces are eagerly loaded into the store
    so subsequent queries don't re-read them. The 'namespace' field
    inside each JSON file is used as canonical — avoids the reverse-DNS
    path-to-namespace ambiguity (e.g., is 'uk/gov/legislation.json' the
    three-label domain 'legislation.gov.uk' or 'legislation/uk' with path?).
    """
    namespaces: set[str] = set()

    # From store: keys like 'secid:advisory/mitre.org'
    prefix = f"secid:{secid_type}/"
    for key in store.keys():
        if not key.startswith(prefix):
            continue
        try:
            data = json.loads(store.get(key) or "{}")
            ns = data.get("namespace")
            if ns:
                namespaces.add(ns)
        except json.JSONDecodeError:
            continue

    # From filesystem: walk registry/<type>/, load whatever isn't cached
    if registry_dirs:
        from pathlib import Path
        for registry_dir in registry_dirs:
            type_dir = Path(registry_dir) / secid_type
            if not type_dir.is_dir():
                continue
            for json_file in sorted(type_dir.rglob("*.json")):
                if json_file.stem.startswith("_"):
                    continue
                try:
                    data = json.loads(json_file.read_text())
                except json.JSONDecodeError:
                    continue
                ns = data.get("namespace")
                if not ns:
                    continue
                namespaces.add(ns)
                # Cache in store for subsequent queries
                key = f"secid:{secid_type}/{ns}"
                if not store.get(key):
                    store.set(key, json.dumps(data))

    return sorted(namespaces)


def _cross_source_search(
    store: Store, secid_type: str, search_term: str,
    registry_dirs: Optional[list[str]],
) -> list[dict]:
    """Find matches for search_term across all namespaces of secid_type.

    Walks each namespace's match_nodes; for each source-level node, scans
    its children for a pattern that matches search_term. Successful matches
    build a fully-qualified result (with source slug + subpath). Results
    are sorted by weight descending (highest-weight sources first).

    Note: this only inspects ONE level of children. Grandchild patterns
    (rare in current registry data) are not traversed by cross-source.
    The Worker's equivalent behavior is the canonical reference.
    """
    if not search_term:
        return []

    results: list[dict] = []
    namespaces = _all_namespaces_of_type(store, secid_type, registry_dirs)

    for ns in namespaces:
        raw = store.get(f"secid:{secid_type}/{ns}")
        if not raw:
            continue
        try:
            ns_data = json.loads(raw)
        except json.JSONDecodeError:
            continue

        for node in ns_data.get("match_nodes", []):
            # Source slug derived from the source-level node's first
            # extractable pattern (e.g., '(?i)^cve$' -> 'cve').
            source_slug = next(
                (s for p in node.get("patterns", []) if (s := _slug_from_pattern(p))),
                None,
            )

            for child in node.get("children", []):
                child_data = child.get("data", {})
                matched = False
                for pat in child.get("patterns", []):
                    try:
                        if re.match(pat, search_term):
                            matched = True
                            break
                    except re.error:
                        continue
                if not matched:
                    continue

                # Build the result
                source_part = f"/{source_slug}" if source_slug else ""
                secid = f"secid:{secid_type}/{ns}{source_part}#{search_term}"
                result: dict = {"secid": secid}
                if child.get("weight"):
                    result["weight"] = child["weight"]
                url_template = child_data.get("url")
                resolved_url = (
                    _substitute_url_template(url_template, child_data, search_term)
                    if url_template else None
                )
                if resolved_url:
                    result["url"] = resolved_url
                    _add_format_metadata(result, child_data)
                results.append(result)
                # One child match per source-level node is enough; don't
                # double-count if multiple children of the same source match.
                break

    # Sort by weight descending; entries without weight sort last.
    results.sort(key=lambda r: -(r.get("weight", 0)))
    return results


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
