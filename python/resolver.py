"""SecID resolver - core resolution logic.

This is a port of the live resolver, SecID-Service (src/parser.ts,
src/resolver.ts, src/kv-resolve.ts, src/identity.ts). The live service is the
reference for correct behaviour; when the two disagree, this file is wrong.
Function names follow the TypeScript so a reader can diff the two side by side.

Pipeline for one query:

  1. parse_secid()      split type / namespace / name@version / #subpath / ?qualifiers.
                        Namespace boundaries need the registry (shortest-to-longest).
  2. RegistryIndex      per-type dict of namespace data, built once per type on
                        first use (lazy) or at startup (bulk) and cached.
  3. _resolve_parsed()  walk match_nodes: list namespaces -> list sources ->
                        describe a source -> resolve a subpath, including
                        version_required sources, lookup tables, ?lang and the
                        cross-source searches that produce `corrected` results.

Differences from the live service, all deliberate:
  - URL templates must be absolute http(s) URLs, and substituted variable
    values are percent-encoded (characters that are legal in a URL path, such
    as ':' and '/', are kept). The live service passes relative templates
    through unchanged and does not encode values.
  - Children with no `url` but `{placeholder}` templates in `data.urls[]` get
    those templates filled in on the registry-data result.
  - The not_found guidance points at the SecID issue tracker; the live
    service's submit_feedback MCP tool does not exist here.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Optional

from registry_loader import SECID_TYPES, load_namespaces, load_type_info
from storage import Store

logger = logging.getLogger(__name__)

# ReDoS runtime bound. Registry-authored regexes (patterns[], variables.*.extract)
# run against attacker-controlled input on every request via Python `re`, which
# has no RE2 backing and no timeout. Capping input length bounds the cost of
# polynomial backtracking; it does NOT make an exponential pattern safe (a
# nested-quantifier pattern can still blow up well inside 256 characters). The
# upstream registry CI has a pattern breadth/backtracking gate that is the real
# protection; this cap is defence in depth. FastAPI's `secid: str = Query(...)`
# is otherwise unbounded.
MAX_SECID_QUERY_CHARS = 1024  # whole query; real SecIDs are < 200 chars
MAX_REGEX_INPUT = 256         # per-component (name / subpath / version / search term)

ISSUES_URL = "https://github.com/CloudSecurityAlliance/SecID/issues"
NAMESPACE_IDENTITY_WEIGHT = 90  # just below an exact source-name match

_FORMAT_METADATA_FIELDS = ("parsability", "schema", "parsing_instructions", "auth")

# Fallback type descriptions when registry/<type>.json is missing (mirrors the
# Service's upload script).
TYPE_DESCRIPTIONS = {
    "advisory": "Publications about vulnerabilities (CVE, GHSA, vendor advisories, incident reports)",
    "weakness": "Abstract flaw patterns (CWE, OWASP Top 10)",
    "ttp": "Adversary techniques (ATT&CK, ATLAS, CAPEC)",
    "control": "Security requirements (NIST CSF, ISO 27001, benchmarks)",
    "disclosure": "Vulnerability disclosure programs, policies, reporting channels",
    "regulation": "Laws and legal requirements (GDPR, HIPAA)",
    "entity": "Organizations, products, services",
    "reference": "Documents, research, identifier systems (arXiv, DOI, ISBN, RFCs)",
}


def _too_long_for_regex(*values: Optional[str]) -> bool:
    """True if any value exceeds the per-component ReDoS bound (None is fine)."""
    return any(v is not None and len(v) > MAX_REGEX_INPUT for v in values)


# ---------------------------------------------------------------------------
# Regex handling
#
# Registry patterns are written for JavaScript RegExp. Three differences from
# Python `re` matter and are neutralised here:
#   - `(?i)` is not valid JS; the Service strips it and sets the i flag. Python
#     accepts it inline, but we strip it too so both sides agree.
#   - JS `\d`/`\w`/`\s` are ASCII; Python's are Unicode. Without re.ASCII,
#     "CVE-٢٠٢١-٤٤٢٢٨" (Arabic-Indic digits) matched ^CVE-\d{4}-\d{4,}$.
#   - JS `$` matches only at the end; Python's also matches before a trailing
#     newline. Inputs ending in "\n" are rejected.
# RegExp.test() is a search, so re.search() is used, not re.match().
# ---------------------------------------------------------------------------

_regex_cache: dict[str, Optional[re.Pattern]] = {}


def _compile(pattern: str) -> Optional[re.Pattern]:
    try:
        return _regex_cache[pattern]
    except KeyError:
        pass
    body, flags = pattern, re.ASCII
    if body.startswith("(?i)"):
        body, flags = body[4:], flags | re.IGNORECASE
    try:
        compiled: Optional[re.Pattern] = re.compile(body, flags)
    except (re.error, TypeError, ValueError, OverflowError):
        compiled = None
    _regex_cache[pattern] = compiled
    return compiled


def _search(pattern: str, value: str) -> Optional[re.Match]:
    rx = _compile(pattern)
    return rx.search(value) if rx is not None else None


def matches_any_pattern(patterns: list, value: str) -> bool:
    if value is None or len(value) > MAX_REGEX_INPUT or value.endswith("\n"):
        return False
    return any(isinstance(p, str) and _search(p, value) for p in patterns or [])


# Tokens no legitimate identifier pattern should accept. A pattern matching one
# accepts essentially anything and cannot tell a real identifier from an
# arbitrary search term. Keep in step with SecID-Service OPEN_PATTERN_SENTINELS
# (and SecID scripts/pattern-probes.json).
OPEN_PATTERN_SENTINELS = [
    "qxzjvwk", "Qx9Zjvwk7", "zzqqxxjj", "Zq7Xv9Kw", "wkqzjxvq",
    "QZX", "XQ", "ZQJ", "QQ9", "QZXJ",
    "qzx", "zj", "qqj",
    "ZQ.XJ", "QZX-99",
]

_open_cache: dict[tuple, bool] = {}


def is_open_pattern(patterns: list) -> bool:
    """Does this pattern set accept arbitrary input (e.g. ^.+$, ^[a-z-]+$)?"""
    key = tuple(p for p in patterns or [] if isinstance(p, str))
    cached = _open_cache.get(key)
    if cached is None:
        cached = any(
            (rx := _compile(p)) is not None and any(rx.search(s) for s in OPEN_PATTERN_SENTINELS)
            for p in key
        )
        _open_cache[key] = cached
    return cached


def is_node_open(node: dict) -> bool:
    """Unbounded identifier space: declared by the registry (open_pattern) or
    demonstrably accepting nonsense. Both halves are needed - `^\\d+$` accepts
    every integer yet matches no sentinel, so only the registry can say so."""
    return node.get("open_pattern") is True or is_open_pattern(node.get("patterns", []))


def node_matches(node: dict, value: str, scoped: bool) -> bool:
    """Port of Service nodeMatches():

      1. An open pattern with known_values: the enumeration is a closed set.
      2. An open pattern with no enumeration cannot discriminate, so it is
         unreachable from an unscoped (cross-namespace) search.
      3. Otherwise the regex decides.

    `scoped` is True when the caller already named the namespace, which keeps
    genuinely unbounded spaces (GitHub usernames, Jira keys) resolvable.
    """
    if is_node_open(node):
        known = (node.get("data") or {}).get("known_values")
        if known:
            return isinstance(known, dict) and value in known
        if not scoped:
            return False
    return matches_any_pattern(node.get("patterns", []), value)


def extract_name_slug(node: dict) -> str:
    """Human-readable source name from the first pattern ("(?i)^cve$" -> "cve")."""
    patterns = node.get("patterns") or [""]
    cleaned = re.sub(r"^\(\?i\)", "", patterns[0] or "", flags=re.IGNORECASE)
    cleaned = re.sub(r"^\^", "", cleaned)
    cleaned = re.sub(r"\$$", "", cleaned)
    cleaned = re.sub(r"\\(.)", r"\1", cleaned)
    if re.fullmatch(r"[\w-]+", cleaned, flags=re.ASCII):
        return cleaned.lower()
    return re.sub(r"\s+", "-", (node.get("description") or "").lower())


# ---------------------------------------------------------------------------
# Parser (port of parser.ts)
# ---------------------------------------------------------------------------


@dataclass
class ParsedSecID:
    raw: str
    prefix: bool = False
    type: Optional[str] = None
    namespace: Optional[str] = None
    name: Optional[str] = None
    version: Optional[str] = None
    subpath: Optional[str] = None
    qualifiers: Optional[dict] = None


def extract_secid_type(value: str) -> Optional[str]:
    """The type segment of a SecID, without registry access (prefix optional)."""
    remaining = (value or "").strip()
    if remaining[:6].lower() == "secid:":
        remaining = remaining[6:]
    if not remaining:
        return None
    head = remaining.split("#", 1)[0]
    candidate = head.split("/", 1)[0].lower()
    return candidate if candidate in SECID_TYPES else None


def _parse_qualifiers(raw: str) -> dict:
    """?key=value&k2=v2 -> dict. Keys lowercased, values keep their case."""
    out = {}
    for pair in raw.split("&"):
        key, sep, value = pair.partition("=")
        if sep:
            out[key.lower()] = value
    return out


def _extract_name_and_version(value: str, parsed: ParsedSecID) -> None:
    name, sep, version = value.partition("@")
    parsed.name = name or None
    if sep:
        parsed.version = version or None


def parse_secid(value: str, has_namespace: Callable[[str], bool]) -> ParsedSecID:
    """Parse a SecID. `has_namespace(candidate)` says whether a namespace exists
    for the parsed type; candidates are tried shortest-to-longest and the
    longest registered one wins."""
    parsed = ParsedSecID(raw=value)
    if not value or not isinstance(value, str):
        return parsed
    remaining = value.strip()
    if remaining[:6].lower() == "secid:":
        parsed.prefix = True
        remaining = remaining[6:]
    if not remaining:
        return parsed

    item_qualifiers = None
    head, sep, raw_subpath = remaining.partition("#")
    if sep:
        raw_subpath = raw_subpath or None
        if raw_subpath and "?" in raw_subpath:
            raw_subpath, _, q = raw_subpath.partition("?")
            item_qualifiers = _parse_qualifiers(q)
            raw_subpath = raw_subpath or None
        parsed.subpath = raw_subpath
    if not head:
        return parsed

    type_candidate, slash, remaining = head.partition("/")
    if type_candidate.lower() not in SECID_TYPES:
        return parsed
    parsed.type = type_candidate.lower()
    if not slash or not remaining:
        return parsed

    source_qualifiers = None
    if "?" in remaining:
        remaining, _, q = remaining.partition("?")
        source_qualifiers = _parse_qualifiers(q)

    segments = remaining.split("/")
    longest, match_len = None, 0
    for i in range(1, len(segments) + 1):
        candidate = "/".join(segments[:i])
        if has_namespace(candidate):
            longest, match_len = candidate, i

    if longest:
        parsed.namespace = longest
        after = "/".join(segments[match_len:])
        if after:
            _extract_name_and_version(after, parsed)
    elif "." in segments[0]:
        # Looks like a domain that is not registered - record it so the
        # response can say which namespace was missing.
        parsed.namespace = segments[0]
        after = "/".join(segments[1:])
        if after:
            _extract_name_and_version(after, parsed)
    else:
        # No domain-like segment: the whole remainder is an identifier for
        # cross-source search (e.g. "advisory/CVE-2024-1234").
        _extract_name_and_version(remaining, parsed)

    if source_qualifiers or item_qualifiers:
        parsed.qualifiers = {**(source_qualifiers or {}), **(item_qualifiers or {})}
    return parsed


# ---------------------------------------------------------------------------
# URL building
# ---------------------------------------------------------------------------

_ALLOWED_URL_SCHEMES = ("https", "http")
# Characters left unencoded in substituted values: everything that is legal in
# a URL path/query and that real identifiers use (RHSA-2024:1234, 10.1000/xyz,
# T1059.003). Encoded: '?', '#', '%', whitespace, quotes, <>\^`{|}, controls
# and non-ASCII - the characters that would re-shape the URL.
_SAFE_VALUE_CHARS = "/:@!$&'()*+,;=-._~"


def _absolute_http_template(template: str) -> Optional[urllib.parse.SplitResult]:
    """The template's literal scheme/authority, or None if it is not an
    absolute http(s) URL. {placeholders} are neutralised first so a template
    whose host is itself a placeholder is rejected rather than trusted."""
    try:
        tpl = urllib.parse.urlsplit(re.sub(r"\{[^}]*\}", "x", template))
    except ValueError:
        return None
    if tpl.scheme not in _ALLOWED_URL_SCHEMES or not tpl.netloc:
        return None
    return tpl


def _validate_resolved_url(template: str, url: str) -> Optional[str]:
    """Return url only if the template is an absolute http(s) URL and
    substitution did not change its scheme or authority (the open-redirect
    primitive, F-07-01). Relative or non-http templates are rejected: with no
    literal authority, a value like "javascript:..." would become the URL."""
    tpl = _absolute_http_template(template)
    if tpl is None:
        return None
    try:
        res = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if res.scheme != tpl.scheme or res.netloc != tpl.netloc:
        return None
    return url


def build_url(template: str, variables: dict) -> Optional[str]:
    url = template
    for key, value in variables.items():
        if value is None:
            continue
        url = url.replace("{" + key + "}", urllib.parse.quote(str(value), safe=_SAFE_VALUE_CHARS))
    return _validate_resolved_url(template, url)


def _lookup_range_table(number: int, notes: Optional[str]) -> Optional[str]:
    """Year for a sequence number from "YYYY: N" pairs in the parent's notes
    (Debian DSA/DLA): the pair with the highest start <= number."""
    if not notes:
        return None
    pairs = sorted(
        ((int(start), year) for year, start in re.findall(r"(\d{4}):\s*(\d+)", notes, flags=re.ASCII)),
    )
    result = None
    for start, year in pairs:
        if start <= number:
            result = year
        else:
            break
    return result


def _extract_variable(var_def, subpath: str, parent_notes: Optional[str]) -> Optional[str]:
    if not isinstance(var_def, dict) or not var_def.get("extract"):
        return None
    if len(subpath) > MAX_REGEX_INPUT:
        return None  # ReDoS bound
    m = _search(var_def["extract"], subpath)
    if not m:
        return None
    captured = m.group(1) if m.re.groups else m.group(0)
    if not captured:
        return None
    if var_def.get("format"):
        return var_def["format"].replace("{1}", captured)
    if var_def.get("lookup") == "range_table":
        try:
            return _lookup_range_table(int(captured), parent_notes)
        except ValueError:
            return None
    return captured


def _template_variables(child: dict, subpath: str, parent_node: dict,
                        qualifiers: Optional[dict]) -> dict:
    data = child.get("data") or {}
    parent_notes = (parent_node.get("data") or {}).get("notes")
    variables = {}
    for name, var_def in (data.get("variables") or {}).items():
        value = _extract_variable(var_def, subpath, parent_notes)
        if value is not None:
            variables[name] = value
    lang = data.get("lang")
    if isinstance(lang, dict) and lang.get("default"):
        code = (qualifiers or {}).get("lang") or lang["default"]
        transform = str(lang.get("url_transform") or "").lower()
        if transform in ("upper", "uppercase"):
            code = code.upper()
        elif transform in ("lower", "lowercase"):
            code = code.lower()
        variables["lang"] = code
    variables["id"] = subpath
    variables["id_lower"] = subpath.lower()
    variables["id_upper"] = subpath.upper()
    return variables


def _resolve_child_url(child: dict, subpath: str, parent_node: dict,
                       qualifiers: Optional[dict]) -> Optional[str]:
    template = (child.get("data") or {}).get("url")
    if not template or not isinstance(template, str):
        return None
    if "{" not in template:
        return template if _absolute_http_template(template) else None
    return build_url(template, _template_variables(child, subpath, parent_node, qualifiers))


def _substitute_url_template(template: str, child_data: dict, captured_input: str) -> Optional[str]:
    """Fill one template for a child's data (kept for callers and tests)."""
    child = {"data": {**(child_data or {}), "url": template}}
    return _resolve_child_url(child, captured_input, {"data": {}}, None)


def _substituted_urls(child: dict, subpath: str, parent_node: dict,
                      qualifiers: Optional[dict]) -> Optional[list]:
    """data.urls[] entries with {placeholders} filled in, for children that
    carry their templates there instead of in data.url. None if there are none."""
    urls = (child.get("data") or {}).get("urls")
    if not isinstance(urls, list) or not any(
        isinstance(u, dict) and "{" in str(u.get("url", "")) for u in urls
    ):
        return None
    variables = _template_variables(child, subpath, parent_node, qualifiers)
    out = []
    for entry in urls:
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
            continue
        if "{" not in entry["url"]:
            out.append(entry)
            continue
        url = build_url(entry["url"], variables)
        if url:
            out.append({**entry, "url": url})
    return out


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------


def _response(query: str, status: str, results: list, message: Optional[str] = None) -> dict:
    out = {"secid_query": query, "status": status, "results": results}
    if message:
        out["message"] = message
    return out


def _add_format_metadata(result: dict, data: dict) -> None:
    for field_name in _FORMAT_METADATA_FIELDS:
        if data.get(field_name):
            result[field_name] = data[field_name]


def _resolution_result(secid: str, weight, url: str, data: dict) -> dict:
    res = {"secid": secid}
    if weight is not None:
        res["weight"] = weight
    res["url"] = url
    if data.get("content_type"):
        res["content_type"] = data["content_type"]
    _add_format_metadata(res, data)
    return res


def _weight(result: dict) -> float:
    w = result.get("weight")
    return w if isinstance(w, (int, float)) else 0


# The Service breaks weight ties with String.prototype.localeCompare (ICU root
# collation), which orders punctuation differently from code points: "-" sorts
# before "#", so "aicm-caiq#IAM-12" precedes "aicm#IAM-12". This key reproduces
# that order for ASCII: punctuation and symbols in CLDR root order, then digits,
# then letters case-insensitively, with lowercase first on a tie.
_COLLATION_PUNCT = " _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$"
_COLLATION_RANK = {c: i for i, c in enumerate(_COLLATION_PUNCT)}


def _locale_key(value: str) -> tuple:
    primary, tertiary = [], []
    for ch in value:
        if ch in _COLLATION_RANK:
            primary.append(_COLLATION_RANK[ch])
        elif ch.isascii() and ch.isdigit():
            primary.append(100 + ord(ch))
        elif ch.isascii() and ch.isalpha():
            primary.append(200 + ord(ch.lower()))
        else:
            primary.append(1000 + ord(ch))
        tertiary.append(1 if ch.isupper() else 0)
    return (tuple(primary), tuple(tertiary))


def _sort_resolution_first(results: list) -> None:
    """URL-bearing results first (weight desc, stable), then registry data."""
    results.sort(key=lambda r: (0, -_weight(r)) if "url" in r else (1, 0))


def _node_data(node: dict) -> dict:
    data = node.get("data")
    return data if isinstance(data, dict) else {}


def _children(node: dict) -> list:
    children = node.get("children")
    return children if isinstance(children, list) else []


def _match_nodes(ns: dict) -> list:
    nodes = ns.get("match_nodes")
    return nodes if isinstance(nodes, list) else []


# ---------------------------------------------------------------------------
# Namespace identity (port of identity.ts)
# ---------------------------------------------------------------------------

_PUBLIC_SUFFIX_LABELS = {
    "co", "com", "org", "net", "gov", "edu", "ac", "go", "or", "ne", "gr", "lg",
    "gob", "gouv", "govt", "mil", "int",
}


def namespace_aliases(ns_key: str, ns: dict) -> list[str]:
    """Lowercased strings a namespace can be found by in free-text search:
    meaningful domain labels, path segments, the full domain, and declared names.
    Matching is exact - substring matching would recreate the noise this fixes."""
    domain, *path_segments = ns_key.split("/")
    labels = domain.split(".")
    meaningful = [
        label for i, label in enumerate(labels[:-1])
        if label and (i == 0 or label.lower() not in _PUBLIC_SUFFIX_LABELS)
    ]
    candidates = [*meaningful, domain, *path_segments]
    for key in ("common_name", "official_name"):
        if isinstance(ns.get(key), str):
            candidates.append(ns[key])
    if isinstance(ns.get("alternate_names"), list):
        candidates.extend(ns["alternate_names"])
    seen: dict[str, None] = {}
    for c in candidates:
        if isinstance(c, str) and c.strip():
            seen[c.strip().lower()] = None
    return list(seen)


# ---------------------------------------------------------------------------
# Resolution against a (possibly partial) type registry - port of resolver.ts
# ---------------------------------------------------------------------------


class _Resolution:
    """One query against `type_registry` (namespace -> data, for parsed.type).
    `aliases(ns)` returns cached namespace aliases."""

    def __init__(self, parsed: ParsedSecID, type_registry: dict,
                 aliases: Callable[[str, dict], list]):
        self.p = parsed
        self.q = parsed.raw
        self.reg = type_registry
        self.aliases = aliases

    def run(self) -> dict:
        p = self.p
        if not p.type:
            if not (p.raw or "").strip():
                return _response(self.q, "error", [], "Empty query. Provide a SecID string.")
            return _response(self.q, "not_found", [], f"Invalid type. Valid types: {', '.join(SECID_TYPES)}")
        if not self.reg:
            return _response(
                self.q, "not_found", [],
                f'No namespaces registered for type "{p.type}". Request one at {ISSUES_URL}',
            )
        if not p.namespace and (not p.name or p.name == "*"):
            return self.list_namespaces()
        if not p.namespace:
            return self.type_scoped_search()
        ns = self.reg.get(p.namespace)
        if ns is None:
            return _response(self.q, "not_found", [],
                             f'Namespace "{p.namespace}" not found in type "{p.type}".')
        if not p.name:
            return self.list_sources(ns)
        return self.resolve_with_name(ns)

    # Level 1
    def list_namespaces(self) -> dict:
        results = []
        for ns_key in sorted(self.reg):
            data = self.reg[ns_key]
            results.append({"secid": f"secid:{self.p.type}/{ns_key}",
                            "data": _namespace_listing_entry(ns_key, data, include_key=False)})
        return _response(self.q, "found", results)

    # Level 2
    def list_sources(self, ns: dict) -> dict:
        results = []
        for node in _match_nodes(ns):
            d = _node_data(node)
            results.append({
                "secid": f"secid:{self.p.type}/{self.p.namespace}/{extract_name_slug(node)}",
                "data": {
                    "official_name": d.get("official_name") or node.get("description"),
                    "common_name": d.get("common_name"),
                    "description": d.get("description") or node.get("description"),
                    "child_count": len(_children(node)),
                },
            })
        return _response(self.q, "found", results)

    # Level 3+4
    def resolve_with_name(self, ns: dict) -> dict:
        p = self.p
        node = next((n for n in _match_nodes(ns)
                     if matches_any_pattern(n.get("patterns", []), p.name)), None)
        if node is None:
            corrected = self.namespace_scoped_search(ns)
            if corrected:
                return _response(self.q, "corrected", corrected)
            type_results = self.type_scoped_search()
            if type_results["results"]:
                return type_results
            return _response(self.q, "related", self.list_sources(ns)["results"],
                             f'Name "{p.name}" not found in {p.namespace}. Available sources listed.')
        if not p.subpath:
            return self.describe_source(node)
        return self.resolve_subpath(node)

    def _source_secid(self, node: dict, with_version: bool = True) -> str:
        base = f"secid:{self.p.type}/{self.p.namespace}/{extract_name_slug(node)}"
        return f"{base}@{self.p.version}" if (with_version and self.p.version) else base

    def describe_source(self, node: dict) -> dict:
        data = {k: v for k, v in _node_data(node).items() if v is not None}
        if not data.get("official_name"):
            data["official_name"] = node.get("description")
        if not data.get("description"):
            data["description"] = node.get("description")
        if not data.get("urls"):
            data["urls"] = []
        if _children(node):
            data["patterns"] = [
                {"pattern": (c.get("patterns") or [None])[0], "description": c.get("description")}
                for c in _children(node)
            ]
        return _response(self.q, "found", [{"secid": self._source_secid(node), "data": data}])

    def resolve_subpath(self, node: dict) -> dict:
        p = self.p
        if _node_data(node).get("version_required"):
            return self.resolve_versioned(node)
        if not _children(node):
            return self.describe_source(node)
        results = self.match_children_and_resolve(_children(node), node)
        if results:
            return self._filtered(results)
        if (p.qualifiers or {}).get("lang"):
            msg = _lang_not_found_message(_children(node), p.subpath, p.qualifiers["lang"])
            if msg:
                return _response(self.q, "not_found", [], msg)
        return _response(self.q, "related", [self.describe_source(node)["results"][0]],
                         f'Subpath "{p.subpath}" did not match any known pattern for this source.')

    def resolve_versioned(self, node: dict) -> dict:
        p = self.p
        d = _node_data(node)
        if not p.version:
            data = {
                "official_name": d.get("official_name") or node.get("description"),
                "version_required": True,
                "versions_available": d.get("versions_available") or [],
                "version_disambiguation": d.get("version_disambiguation"),
                "unversioned_behavior": d.get("unversioned_behavior"),
            }
            return _response(self.q, "related",
                             [{"secid": self._source_secid(node, with_version=False), "data": data}],
                             "This source requires a version. Specify @version in your query.")
        if not _children(node):
            return self.describe_source(node)
        version_child = next((c for c in _children(node)
                              if matches_any_pattern(c.get("patterns", []), p.version)), None)
        if version_child is None:
            versions = [v.get("version") for v in (d.get("versions_available") or [])
                        if isinstance(v, dict) and v.get("version")]
            return _response(self.q, "not_found", [],
                             f'Version "{p.version}" not found. Available: {", ".join(versions) or "none listed"}')
        vd = _node_data(version_child)
        if not p.subpath:
            data = {
                "official_name": vd.get("official_name") or version_child.get("description"),
                "urls": vd.get("urls") or [],
                "note": vd.get("note"),
            }
            if _children(version_child):
                data["patterns"] = [
                    {"pattern": (c.get("patterns") or [None])[0], "description": c.get("description")}
                    for c in _children(version_child)
                ]
            return _response(self.q, "found", [{"secid": self._source_secid(node), "data": data}])
        if not _children(version_child):
            return _response(self.q, "related", [], "This version has no resolvable items.")
        results = self.match_children_and_resolve(_children(version_child), version_child, name_node=node)
        if results:
            return self._filtered(results)
        if (p.qualifiers or {}).get("lang"):
            msg = _lang_not_found_message(_children(version_child), p.subpath, p.qualifiers["lang"])
            if msg:
                return _response(self.q, "not_found", [], msg)
        return _response(self.q, "related", [],
                         f'Item "{p.subpath}" not found in version {p.version}.')

    def _filtered(self, results: list) -> dict:
        filtered = _apply_qualifier_filters(results, self.p.qualifiers)
        if filtered is None:
            return _qualifier_not_found(self.q, results, self.p.qualifiers)
        return _response(self.q, "found", filtered)

    def match_children_and_resolve(self, children: list, parent_node: dict,
                                   name_node: Optional[dict] = None) -> list:
        p = self.p
        subpath = p.subpath
        qualifiers = p.qualifiers or {}
        slug_node = name_node or parent_node
        results = []
        for child in children:
            if not node_matches(child, subpath, True):
                continue
            cd = _node_data(child)
            lang = cd.get("lang") if isinstance(cd.get("lang"), dict) else None
            if qualifiers.get("lang") and lang and qualifiers["lang"] not in (lang.get("available") or []):
                continue
            base = f"secid:{p.type}/{p.namespace}/{extract_name_slug(slug_node)}"
            secid = f"{base}@{p.version}#{subpath}" if p.version else f"{base}#{subpath}"

            url = _resolve_child_url(child, subpath, parent_node, p.qualifiers)
            if url:
                res = _resolution_result(secid, child.get("weight"), url, cd)
                if lang:
                    res["lang"] = qualifiers.get("lang") or lang.get("default")
                    if not qualifiers.get("lang"):
                        res["weight"] = _weight(res) + 1
                results.append(res)
            elif isinstance(cd.get("lookup_table"), dict):
                # Own-key semantics: the subpath itself is the key.
                entry = cd["lookup_table"].get(subpath)
                lookup_url = entry if isinstance(entry, str) else (entry or {}).get("url")
                if lookup_url and _absolute_http_template(lookup_url):
                    results.append(_resolution_result(secid, child.get("weight"), lookup_url, cd))
                else:
                    results.append({"secid": secid, "data": {
                        "description": child.get("description"),
                        "available_items": list(cd["lookup_table"].keys()),
                    }})
            else:
                data = {"description": child.get("description"), "weight": child.get("weight"),
                        "note": cd.get("note")}
                urls = _substituted_urls(child, subpath, parent_node, p.qualifiers)
                if urls is not None:
                    data["urls"] = urls
                results.append({"secid": secid, "data": data})
        _sort_resolution_first(results)
        return results

    def _child_hit(self, secid: str, child: dict, identifier: str, node: dict) -> dict:
        url = _resolve_child_url(child, identifier, node, self.p.qualifiers)
        if url:
            return _resolution_result(secid, child.get("weight"), url, _node_data(child))
        return {"secid": secid, "data": {"description": child.get("description"),
                                         "weight": child.get("weight")}}

    def namespace_scoped_search(self, ns: dict) -> list:
        """The name matched no source: treat it as an item identifier within
        this namespace (redhat.com/RHSA-2026:0932 -> errata#RHSA-2026:0932)."""
        p = self.p
        identifier = p.name + (p.subpath or "")
        results = []
        for node in _match_nodes(ns):
            for child in _children(node):
                if not node_matches(child, identifier, True):
                    continue
                secid = f"secid:{p.type}/{p.namespace}/{extract_name_slug(node)}#{identifier}"
                results.append(self._child_hit(secid, child, identifier, node))
        results.sort(key=lambda r: -_weight(r))
        return results

    def type_scoped_search(self) -> dict:
        p = self.p
        identifier = p.name or ""
        if not identifier:
            return _response(self.q, "not_found", [], "No identifier to search for.")
        needle = identifier.strip().lower()
        results = []
        for ns_key, ns in self.reg.items():
            if needle and needle in self.aliases(ns_key, ns):
                secid = f"secid:{p.type}/{ns_key}"
                urls = ns.get("urls") if isinstance(ns.get("urls"), list) else []
                ns_url = urls[0].get("url") if urls and isinstance(urls[0], dict) else None
                if ns_url:
                    results.append({"secid": secid, "weight": NAMESPACE_IDENTITY_WEIGHT, "url": ns_url})
                else:
                    results.append({"secid": secid, "data": {
                        "description": ns.get("official_name"),
                        "weight": NAMESPACE_IDENTITY_WEIGHT,
                        "official_name": ns.get("official_name"),
                        "common_name": ns.get("common_name"),
                        "source_count": len(_match_nodes(ns)),
                    }})
            for node in _match_nodes(ns):
                slug = extract_name_slug(node)
                if node_matches(node, identifier, False):
                    secid = f"secid:{p.type}/{ns_key}/{slug}"
                    nd = _node_data(node)
                    source_url = nd.get("url") or ((ns.get("urls") or [{}])[0] or {}).get("url")
                    weight = node.get("weight") if node.get("weight") is not None else 100
                    if source_url:
                        res = {"secid": secid, "weight": weight, "url": source_url}
                        _add_format_metadata(res, nd)
                        results.append(res)
                    else:
                        results.append({"secid": secid, "data": {
                            "description": node.get("description"),
                            "weight": weight,
                            "official_name": ns.get("official_name"),
                            "common_name": ns.get("common_name"),
                            "child_count": len(_children(node)),
                        }})
                for child in _children(node):
                    if not node_matches(child, identifier, False):
                        continue
                    secid = f"secid:{p.type}/{ns_key}/{slug}#{identifier}"
                    results.append(self._child_hit(secid, child, identifier, node))
        if not results:
            return _response(
                self.q, "not_found", [],
                f'No results found for "{identifier}" in type "{p.type}". If this source should be '
                f"covered, request it at {ISSUES_URL}",
            )
        results.sort(key=lambda r: (-_weight(r), _locale_key(r.get("secid", ""))))
        return _response(self.q, "found", results)


def _apply_qualifier_filters(results: list, qualifiers: Optional[dict]) -> Optional[list]:
    if not qualifiers:
        return results
    filtered = results
    for key in ("content_type", "parsability"):
        if qualifiers.get(key):
            target = qualifiers[key]
            filtered = [r for r in filtered if "url" not in r or r.get(key) == target]
    if qualifiers.get("lang"):
        target = qualifiers["lang"]
        filtered = [r for r in filtered if "url" not in r or not r.get("lang") or r["lang"] == target]
    if not any("url" in r for r in filtered) and any("url" in r for r in results):
        return None
    return filtered


def _qualifier_not_found(query: str, results: list, qualifiers: dict) -> dict:
    parts = []
    if qualifiers.get("content_type"):
        available = sorted({r["content_type"] for r in results if "url" in r and r.get("content_type")})
        parts.append(f'No results with content_type "{qualifiers["content_type"]}". '
                     f'Available: {", ".join(available) or "none declared"}.')
    if qualifiers.get("lang"):
        available = sorted({r["lang"] for r in results if "url" in r and r.get("lang")})
        parts.append(f'No results for lang "{qualifiers["lang"]}". '
                     f'Available: {", ".join(available) or "none declared"}.')
    parts.append("Remove qualifiers to see all results.")
    return _response(query, "not_found", [], " ".join(parts))


def _lang_not_found_message(children: list, subpath: str, lang: str) -> Optional[str]:
    for child in children:
        if not matches_any_pattern(child.get("patterns", []), subpath):
            continue
        cfg = _node_data(child).get("lang")
        if isinstance(cfg, dict) and lang not in (cfg.get("available") or []):
            return (f'Language "{lang}" not available. Available: {", ".join(cfg.get("available") or [])}. '
                    f'Remove ?lang to use default ({cfg.get("default")}).')
    return None


def _namespace_listing_entry(ns_key: str, data: dict, include_key: bool = True) -> dict:
    subtypes: set[str] = set()
    for node in _match_nodes(data):
        raw = _node_data(node).get("subtype")
        if isinstance(raw, list):
            subtypes.update(v for v in raw if isinstance(v, str))
        elif isinstance(raw, str):
            subtypes.add(raw)
    entry = {}
    if include_key:
        entry["namespace"] = ns_key
    entry.update({
        "official_name": data.get("official_name"),
        "common_name": data.get("common_name"),
        "source_count": len(_match_nodes(data)),
        "subtypes": sorted(subtypes),
    })
    country = (data.get("tags") or {}).get("country") if isinstance(data.get("tags"), dict) else None
    if isinstance(country, list) and country:
        entry["country"] = country
    return entry


# ---------------------------------------------------------------------------
# Registry index + query orchestration (port of kv-resolve.ts)
# ---------------------------------------------------------------------------


class RegistryIndex:
    """Per-type namespace data, built once per type and cached.

    With registry_dirs, each type is read from disk on first use (lazy mode)
    or all at once via preload() (bulk mode), applying overlay precedence
    (later dirs override earlier ones) and writing through to the store.
    Without registry_dirs, the store is the source (e.g. a store populated by
    another process). invalidate() drops the cache after a reload.
    """

    def __init__(self, store: Store, registry_dirs: Optional[list[str]] = None):
        self.store = store
        self.registry_dirs = list(registry_dirs or [])
        self._lock = threading.RLock()
        self._types: dict[str, dict] = {}
        self._child_patterns: dict[str, list] = {}
        self._aliases: dict[tuple, list] = {}
        self._type_info: dict[str, Optional[dict]] = {}

    def invalidate(self) -> None:
        with self._lock:
            self._types.clear()
            self._child_patterns.clear()
            self._aliases.clear()
            self._type_info.clear()

    def preload(self) -> None:
        for secid_type in SECID_TYPES:
            self.namespaces(secid_type)

    def namespaces(self, secid_type: str) -> dict:
        cached = self._types.get(secid_type)
        if cached is not None:
            return cached
        with self._lock:
            cached = self._types.get(secid_type)
            if cached is not None:
                return cached
            if self.registry_dirs:
                data = load_namespaces(self.registry_dirs, secid_type)
                for ns_key, ns in data.items():
                    self.store.set(f"secid:{secid_type}/{ns_key}", json.dumps(ns))
            else:
                data = {}
                prefix = f"secid:{secid_type}/"
                for key in self.store.keys():
                    if not key.startswith(prefix):
                        continue
                    try:
                        ns = json.loads(self.store.get(key) or "null")
                    except ValueError:
                        continue
                    if isinstance(ns, dict):
                        data[key[len(prefix):]] = ns
            self._child_patterns[secid_type] = [
                (ns_key, child.get("patterns", []))
                for ns_key, ns in data.items()
                for node in _match_nodes(ns)
                for child in _children(node)
            ]
            self._types[secid_type] = data
            return data

    def type_info(self, secid_type: str) -> Optional[dict]:
        if secid_type not in self._type_info:
            self._type_info[secid_type] = (
                load_type_info(self.registry_dirs, secid_type) if self.registry_dirs else None
            )
        return self._type_info[secid_type]

    def aliases(self, ns_key: str, ns: dict) -> list:
        key = (id(ns), ns_key)
        cached = self._aliases.get(key)
        if cached is None:
            cached = namespace_aliases(ns_key, ns)
            self._aliases[key] = cached
        return cached

    def child_index_matches(self, secid_type: str, identifier: str) -> list[str]:
        """Namespaces with a child pattern matching identifier (raw regex, as
        the Service's child_index prefilter does - open-pattern handling
        happens later in node_matches)."""
        self.namespaces(secid_type)
        if len(identifier) > MAX_REGEX_INPUT:
            return []
        matched: dict[str, None] = {}
        for ns_key, patterns in self._child_patterns.get(secid_type, []):
            if ns_key not in matched and matches_any_pattern(patterns, identifier):
                matched[ns_key] = None
        return list(matched)

    # -- orchestration -------------------------------------------------------

    def resolve(self, query: str) -> dict:
        if len(query) > MAX_SECID_QUERY_CHARS:
            return _response(
                query[:MAX_SECID_QUERY_CHARS], "error", [],
                f"Query too long: SecID queries are limited to {MAX_SECID_QUERY_CHARS} characters.",
            )
        trimmed = query.strip()
        if not trimmed:
            return _response(query, "error", [], "Empty query. Provide a SecID string.")

        if re.fullmatch(r"secid:?", trimmed, flags=re.IGNORECASE):
            return self._root(query)

        secid_type = extract_secid_type(trimmed)
        if not secid_type:
            if trimmed[:6].lower() != "secid:":
                bare = self._search_bare_identifier(query, trimmed)
                if bare:
                    return bare
            return _Resolution(parse_secid(query, lambda _c: False), {}, self.aliases).run()

        ns_map = self.namespaces(secid_type)
        parsed = parse_secid(query, lambda candidate: candidate in ns_map)
        if not ns_map:
            return _Resolution(parsed, {}, self.aliases).run()

        if not parsed.namespace and (not parsed.name or parsed.name == "*"):
            return self._type_listing(query, secid_type, ns_map)

        subset = {ns: ns_map[ns] for ns in self._determine_namespaces(parsed, secid_type, ns_map)
                  if ns in ns_map}
        result = _Resolution(parsed, subset, self.aliases).run()

        if result["status"] == "not_found" and parsed.namespace and parsed.namespace not in ns_map:
            result["message"] = (
                f'Namespace "{parsed.namespace}" not found in type "{secid_type}". '
                f"If it should be covered, request it at {ISSUES_URL}"
            )
        return result

    def _determine_namespaces(self, parsed: ParsedSecID, secid_type: str, ns_map: dict) -> list[str]:
        """Which namespaces the resolver sees. Mirrors the Service, whose
        resolver only ever sees the namespaces it fetched from KV - so an
        unscoped search considers namespaces whose child patterns match the
        identifier, or every namespace when none do."""
        if parsed.namespace:
            namespaces = [parsed.namespace]
            if parsed.name and parsed.subpath:
                for ns in self.child_index_matches(secid_type, parsed.subpath):
                    if ns not in namespaces:
                        namespaces.append(ns)
            return namespaces
        if parsed.name:
            matches = self.child_index_matches(secid_type, parsed.name)
            return matches or list(ns_map)
        return list(ns_map)

    def _type_description(self, secid_type: str) -> str:
        info = self.type_info(secid_type) or {}
        return info.get("description") or TYPE_DESCRIPTIONS.get(secid_type, secid_type)

    def _root(self, query: str) -> dict:
        results = []
        for secid_type in SECID_TYPES:
            ns_map = self.namespaces(secid_type)
            if not ns_map and not self.type_info(secid_type):
                continue
            results.append({"secid": f"secid:{secid_type}", "data": {
                "description": self._type_description(secid_type),
                "namespace_count": len(ns_map),
            }})
        if not results:
            return _response(query, "not_found", [], "No registry data loaded.")
        return _response(query, "found", results)

    def _type_listing(self, query: str, secid_type: str, ns_map: dict) -> dict:
        info = self.type_info(secid_type) or {}
        return _response(query, "found", [{"secid": f"secid:{secid_type}", "data": {
            "description": self._type_description(secid_type),
            "purpose": info.get("purpose"),
            "format": info.get("format"),
            "examples": info.get("examples") or [],
            "notes": info.get("notes"),
            "namespace_count": len(ns_map),
            "namespaces": [_namespace_listing_entry(ns, ns_map[ns]) for ns in sorted(ns_map)],
        }}])

    def _search_bare_identifier(self, query: str, trimmed: str) -> Optional[dict]:
        """No type and no 'secid:' prefix: search every type (e.g. "cwe",
        "CVE-2021-44228"). Open patterns never answer a bare term."""
        if len(trimmed) > MAX_REGEX_INPUT:
            return None
        needle = trimmed.lower()
        source_matches: list[tuple[str, str, str]] = []
        child_matches: dict[str, dict[str, None]] = {}
        for secid_type in SECID_TYPES:
            for ns_key, ns in self.namespaces(secid_type).items():
                for node in _match_nodes(ns):
                    if not is_node_open(node) and matches_any_pattern(node.get("patterns", []), trimmed):
                        source_matches.append((secid_type, ns_key, extract_name_slug(node)))
                    for child in _children(node):
                        if not is_node_open(child) and matches_any_pattern(child.get("patterns", []), trimmed):
                            child_matches.setdefault(secid_type, {})[ns_key] = None
                if needle in self.aliases(ns_key, ns):
                    child_matches.setdefault(secid_type, {})[ns_key] = None
        if not source_matches and not child_matches:
            return None

        results: list = []
        for secid_type, ns_key, slug in source_matches:
            parsed = ParsedSecID(raw=query, type=secid_type, namespace=ns_key, name=slug)
            ns_map = self.namespaces(secid_type)
            results += _Resolution(parsed, {ns_key: ns_map[ns_key]}, self.aliases).run()["results"]
        for secid_type, namespaces in child_matches.items():
            parsed = ParsedSecID(raw=query, type=secid_type, name=trimmed)
            ns_map = self.namespaces(secid_type)
            subset = {ns: ns_map[ns] for ns in namespaces}
            results += _Resolution(parsed, subset, self.aliases).run()["results"]
        if not results:
            return None
        _sort_resolution_first(results)
        return _response(query, "found", results)


def index_for(store: Store, registry_dirs: Optional[list[str]] = None) -> RegistryIndex:
    """The RegistryIndex for this store + registry dirs, created on first use
    and kept on the store object so repeated resolve() calls share it."""
    indexes = store.__dict__.setdefault("_secid_indexes", {})
    key = tuple(registry_dirs or [])
    index = indexes.get(key)
    if index is None:
        index = indexes[key] = RegistryIndex(store, list(key))
    return index


def resolve(store: Store, secid_query: str, registry_dirs: Optional[list[str]] = None) -> dict:
    """Resolve a SecID string. Returns the API response envelope."""
    return index_for(store, registry_dirs).resolve(secid_query)
