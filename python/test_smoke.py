"""Smoke tests — verify the core resolver modules import cleanly, basic
constants/behavior are sane, and the secid_server factory produces a
working FastAPI app.

After the secid_server.py refactor (factory pattern), this file can now
test the HTTP layer too via fastapi.testclient.TestClient.
"""

import pytest
from fastapi.testclient import TestClient

from secid_server import ServerConfig, create_app


# ---------------------------------------------------------------------------
# Module imports
# ---------------------------------------------------------------------------


def test_resolver_module_imports():
    """resolver.py is the core resolution logic; must import without side effects."""
    from resolver import resolve, SECID_TYPES
    assert callable(resolve)
    assert isinstance(SECID_TYPES, list)


def test_registry_loader_module_imports():
    """registry_loader.py owns SECID_TYPES and the bulk_load function."""
    from registry_loader import SECID_TYPES, bulk_load
    assert callable(bulk_load)
    assert isinstance(SECID_TYPES, list)


def test_storage_module_imports():
    """storage.py provides the pluggable Store abstraction."""
    from storage import create_store, Store
    assert callable(create_store)


def test_secid_server_module_imports_without_side_effects():
    """secid_server.py must be importable without running argparse or
    starting a server. This is the property the pre-Phase-1 refactor
    delivered — broken before, working after.
    """
    import secid_server
    assert hasattr(secid_server, "create_app")
    assert hasattr(secid_server, "ServerConfig")
    assert hasattr(secid_server, "main")


# ---------------------------------------------------------------------------
# Type-list invariants
# ---------------------------------------------------------------------------


def test_secid_types_canonical():
    """The 10 official SecID types — frozen at v1.0, must not drift silently."""
    from registry_loader import SECID_TYPES
    expected = {
        "advisory", "capability", "control", "disclosure", "entity",
        "methodology", "reference", "regulation", "ttp", "weakness",
    }
    assert set(SECID_TYPES) == expected, (
        f"Type list drift detected. "
        f"Missing: {expected - set(SECID_TYPES)}. "
        f"Extra: {set(SECID_TYPES) - expected}."
    )
    assert len(SECID_TYPES) == 10


def test_secid_types_single_source():
    """resolver.py should import SECID_TYPES from registry_loader, not redefine it."""
    import resolver
    import registry_loader
    assert resolver.SECID_TYPES is registry_loader.SECID_TYPES, (
        "resolver.SECID_TYPES should be the same object as "
        "registry_loader.SECID_TYPES (imported, not redefined). "
        "If they differ, the dedup from PR #4 has regressed."
    )


# ---------------------------------------------------------------------------
# URL template substitution (added in Phase 2.5a)
# ---------------------------------------------------------------------------


def test_substitute_template_no_placeholders():
    """Template without {} placeholders is returned verbatim."""
    from resolver import _substitute_url_template
    assert _substitute_url_template("https://example.com/static", {}, "anything") == "https://example.com/static"


def test_substitute_implicit_id():
    """{id} defaults to the whole captured input when no explicit variable is defined.
    Tests the CVE case: pattern is '^CVE-\\d{4}-\\d{4,}$', URL is '...?id={id}'.
    """
    from resolver import _substitute_url_template
    url = _substitute_url_template(
        "https://www.cve.org/CVERecord?id={id}",
        {},
        "CVE-2021-44228",
    )
    assert url == "https://www.cve.org/CVERecord?id=CVE-2021-44228"


def test_substitute_explicit_variable():
    """Explicit {num} via variables.num.extract regex.
    Tests the CWE case: extract '^CWE-(\\d+)$' against 'CWE-79' yields '79'."""
    from resolver import _substitute_url_template
    child_data = {
        "variables": {
            "num": {"extract": r"^CWE-(\d+)$", "description": "Numeric CWE ID"}
        }
    }
    url = _substitute_url_template(
        "https://cwe.mitre.org/data/definitions/{num}.html",
        child_data,
        "CWE-79",
    )
    assert url == "https://cwe.mitre.org/data/definitions/79.html"


def test_substitute_multiple_variables():
    """ATT&CK sub-techniques use {parent} and {sub} from two extract regexes."""
    from resolver import _substitute_url_template
    child_data = {
        "variables": {
            "parent": {"extract": r"^(T\d{4})\.\d{3}$"},
            "sub": {"extract": r"^T\d{4}\.(\d{3})$"},
        }
    }
    url = _substitute_url_template(
        "https://attack.mitre.org/techniques/{parent}/{sub}/",
        child_data,
        "T1059.003",
    )
    assert url == "https://attack.mitre.org/techniques/T1059/003/"


def test_substitute_implicit_id_with_explicit_others():
    """Implicit {id} should still default even when explicit variables exist
    for other placeholders. Layered, not mutually exclusive."""
    from resolver import _substitute_url_template
    child_data = {
        "variables": {
            "num": {"extract": r"^CAPEC-(\d+)$"},
        }
    }
    # If a template used both {id} and {num}, both should be filled
    url = _substitute_url_template(
        "https://example.com/{id}-num{num}",
        child_data,
        "CAPEC-66",
    )
    assert url == "https://example.com/CAPEC-66-num66"


def test_substitute_unrecognized_placeholder_left_visible():
    """Unknown {placeholders} are left as-is so they're visible in output
    rather than silently swallowed — easier to diagnose registry bugs."""
    from resolver import _substitute_url_template
    url = _substitute_url_template(
        "https://example.com/{unknown}/{id}",
        {},
        "test123",
    )
    # {unknown} stays; {id} is implicit-default
    assert url == "https://example.com/{unknown}/test123"


# ---------------------------------------------------------------------------
# resolve() basic invariants
# ---------------------------------------------------------------------------


def test_resolve_handles_empty_input():
    """resolve() must not crash on edge inputs — minimum contract."""
    from resolver import resolve
    from storage import create_store

    store = create_store("memory")
    result = resolve(store, "")
    assert isinstance(result, dict)


def test_resolve_handles_missing_prefix():
    """A SecID without the 'secid:' prefix is malformed; must return an envelope, not raise."""
    from resolver import resolve
    from storage import create_store

    store = create_store("memory")
    result = resolve(store, "advisory/mitre.org/cve#CVE-2021-44228")
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# create_app() factory + HTTP endpoints
# ---------------------------------------------------------------------------


def _empty_app():
    """Build a minimal app with no registry data. Sufficient for HTTP-layer smoke tests."""
    config = ServerConfig(registry_dirs=[], storage_type="memory")
    return create_app(config)


def test_create_app_factory_returns_fastapi_app():
    """The factory should produce a FastAPI app with the expected title."""
    app = _empty_app()
    assert app.title == "SecID Server"


def test_health_endpoint_returns_ok():
    """GET /health returns 200 with status=ok and the storage type."""
    client = TestClient(_empty_app())
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["store"] == "memory"
    assert "keys" in data


def test_resolve_endpoint_returns_envelope_for_garbage_input():
    """GET /api/v1/resolve always returns a 200 with an envelope, even for malformed input.
    This is the 'helpful over correct' contract from PRINCIPLES.md.
    """
    client = TestClient(_empty_app())
    response = client.get("/api/v1/resolve?secid=this-is-not-a-valid-secid")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)


def test_resolve_endpoint_requires_secid_param():
    """GET /api/v1/resolve without ?secid= should return 422 (FastAPI validation error)."""
    client = TestClient(_empty_app())
    response = client.get("/api/v1/resolve")
    assert response.status_code == 422


def test_create_app_no_side_effects_on_import():
    """Multiple calls to create_app must produce independent apps without leaking
    state between them (no module-level state from the old non-factory shape).
    """
    app_a = _empty_app()
    app_b = _empty_app()
    assert app_a is not app_b


# ---------------------------------------------------------------------------
# Discovery endpoints (added in Phase 2.5c)
# ---------------------------------------------------------------------------


def test_types_endpoint_returns_all_ten():
    """GET /api/v1/types returns the canonical 10 SecID types, even with no
    registry directories (the type list itself is canonical, metadata is the
    only thing that varies)."""
    client = TestClient(_empty_app())
    response = client.get("/api/v1/types")
    assert response.status_code == 200
    body = response.json()
    assert "types" in body
    assert len(body["types"]) == 10
    type_names = {t["type"] for t in body["types"]}
    assert type_names == {
        "advisory", "capability", "control", "disclosure", "entity",
        "methodology", "reference", "regulation", "ttp", "weakness",
    }


def test_types_endpoint_each_entry_has_required_fields():
    """Each /api/v1/types entry must include the canonical shape:
    type, description, long_description, subtypes."""
    client = TestClient(_empty_app())
    response = client.get("/api/v1/types")
    for entry in response.json()["types"]:
        assert "type" in entry
        assert "description" in entry
        assert "long_description" in entry
        assert "subtypes" in entry
        assert isinstance(entry["subtypes"], list)


def test_list_all_types_with_no_registry():
    """list_all_types() should always return 10 entries, with empty description
    fields when no registry data is available."""
    from registry_loader import list_all_types
    types = list_all_types([])
    assert len(types) == 10
    # All descriptions empty when no registry
    assert all(t["description"] == "" for t in types)
    assert all(t["long_description"] == "" for t in types)


def test_load_type_info_returns_none_for_missing_registry():
    """load_type_info() returns None when no registry directory has the file."""
    from registry_loader import load_type_info
    assert load_type_info([], "advisory") is None
    assert load_type_info(["/nonexistent/path"], "advisory") is None


# ---------------------------------------------------------------------------
# Cross-source search (Phase 2.5d)
# ---------------------------------------------------------------------------


def test_extract_name_slug():
    """Source slug comes from the first pattern when it is a plain literal,
    otherwise from the description (same rule as SecID-Service)."""
    from resolver import extract_name_slug
    assert extract_name_slug({"patterns": ["(?i)^cve$"], "description": "CVE"}) == "cve"
    assert extract_name_slug({"patterns": ["(?i)^cna\\-tlr$"], "description": "x"}) == "cna-tlr"
    assert extract_name_slug(
        {"patterns": ["^[A-Za-z0-9]+$"], "description": "GitHub user name"}
    ) == "github-user-name"


def test_type_scoped_search_empty_registry():
    """No registry data at all: an unscoped query is not_found, not a crash."""
    from resolver import resolve
    from storage import create_store
    resp = resolve(create_store("memory"), "secid:advisory/CVE-2021-44228")
    assert resp["status"] == "not_found"


# ---------------------------------------------------------------------------
# Resolved-URL authority validation (F-07-01)
# ---------------------------------------------------------------------------


def test_substitute_drops_authority_injection():
    """A value that changes the template's host/scheme yields None (dropped)."""
    from resolver import _substitute_url_template
    assert _substitute_url_template("https://{id}.example.com/", {}, "evil.com") is None
    assert _substitute_url_template("https://{id}/path", {}, "evil.com") is None


def test_substitute_preserves_reserved_chars_on_same_host():
    """Reserved chars (e.g. ':') in a path-position ID are preserved, not mangled,
    and the result is returned because the host is unchanged."""
    from resolver import _substitute_url_template
    assert (
        _substitute_url_template("https://access.redhat.com/errata/{id}", {}, "RHSA-2024:1234")
        == "https://access.redhat.com/errata/RHSA-2024:1234"
    )


# ---------------------------------------------------------------------------
# Path-traversal containment (F-05-01 regression)
# ---------------------------------------------------------------------------


def test_reject_unsafe_segment():
    """The segment guard rejects traversal/absolute/NUL but allows dotted labels."""
    from registry_loader import _reject_unsafe_segment
    assert _reject_unsafe_segment("a/../b") is True
    assert _reject_unsafe_segment("../etc") is True
    assert _reject_unsafe_segment("/etc/passwd") is True
    assert _reject_unsafe_segment("a\\b") is True
    assert _reject_unsafe_segment("a\x00b") is True
    # Legitimate: dots inside a label are fine; only '..' *segments* are rejected.
    assert _reject_unsafe_segment("redhat.com") is False
    assert _reject_unsafe_segment("legislation.gov.uk/advisories") is False
    assert _reject_unsafe_segment("a..b") is False
    assert _reject_unsafe_segment(None) is False


def test_contained_path(tmp_path):
    """_contained_path returns an in-tree path but None for an escape."""
    from registry_loader import _contained_path
    base = tmp_path / "registry"
    (base / "advisory" / "com").mkdir(parents=True)
    legit = base / "advisory" / "com" / "redhat.json"
    legit.write_text("{}")
    assert _contained_path(str(base), legit) == legit.resolve()
    secret = tmp_path / "secret.json"
    secret.write_text("{}")
    escape = base / "advisory" / "com" / "redhat" / ".." / ".." / ".." / ".." / "secret.json"
    assert _contained_path(str(base), escape) is None


def _make_registry(tmp_path):
    """Minimal registry with one legit namespace + a secret file OUTSIDE the root."""
    import json
    base = tmp_path / "registry"
    (base / "advisory" / "com").mkdir(parents=True)
    (base / "advisory" / "com" / "redhat.json").write_text(json.dumps({
        "type": "advisory", "namespace": "redhat.com", "match_nodes": [],
    }))
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({
        "type": "advisory", "namespace": "secret.internal", "data": "TOPSECRET",
    }))
    return str(base), secret


def test_load_single_blocks_traversal(tmp_path):
    """A traversal namespace must not read a .json outside the registry root."""
    from registry_loader import load_single
    from storage import create_store
    reg, _secret = _make_registry(tmp_path)
    store = create_store("memory")
    # Legit namespace still loads (the fix must not break normal use).
    assert load_single(store, [reg], "advisory", "redhat.com") is not None
    # Traversal to the out-of-tree secret returns None (not the secret).
    assert load_single(store, [reg], "advisory", "redhat.com/../../../../secret") is None
    # The secret's content never entered the store.
    assert all("TOPSECRET" not in (store.get(k) or "") for k in store.keys())


def test_resolve_traversal_is_not_found(tmp_path):
    """End-to-end: a traversal query resolves to not-found, never the secret."""
    import json
    from resolver import resolve
    from storage import create_store
    reg, _secret = _make_registry(tmp_path)
    store = create_store("memory")
    resp = resolve(store, "secid:advisory/redhat.com/../../../../secret", registry_dirs=[reg])
    assert resp["status"] != "found"
    assert "TOPSECRET" not in json.dumps(resp)


# ---------------------------------------------------------------------------
# Safe-by-default server: reload token, CORS allowlist (F-06-01, F-06-02, F-06-03)
# ---------------------------------------------------------------------------


def _app_with(**kwargs):
    return create_app(ServerConfig(registry_dirs=[], storage_type="memory", **kwargs))


def test_admin_reload_disabled_without_token():
    """No reload token configured => POST /admin/reload fails closed with 401,
    before any reload runs. This is the F-06-01 fix (was unauth)."""
    client = TestClient(_empty_app())
    resp = client.post("/admin/reload")
    assert resp.status_code == 401
    assert "no reload token" in resp.json()["detail"].lower()


def test_admin_reload_rejects_wrong_token():
    """Token configured, missing/wrong X-Reload-Token => 401."""
    client = TestClient(_app_with(reload_token="s3cret"))
    assert client.post("/admin/reload").status_code == 401  # missing header
    assert client.post("/admin/reload", headers={"X-Reload-Token": "wrong"}).status_code == 401


def test_admin_reload_accepts_correct_token():
    """Token configured + matching X-Reload-Token => handler runs (200)."""
    client = TestClient(_app_with(reload_token="s3cret"))
    resp = client.post("/admin/reload", headers={"X-Reload-Token": "s3cret"})
    assert resp.status_code == 200
    assert "reloaded" in resp.json()


def test_read_endpoints_need_no_token():
    """The read path stays anonymous by design — the token guards only reload."""
    client = TestClient(_app_with(reload_token="s3cret"))
    assert client.get("/health").status_code == 200
    assert client.get("/api/v1/resolve?secid=secid:advisory/x").status_code == 200


def test_cors_disabled_by_default():
    """No --cors-origin configured => no Access-Control-Allow-Origin header."""
    client = TestClient(_empty_app())
    resp = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in {k.lower() for k in resp.headers}


def test_cors_enabled_for_configured_origin():
    """An explicitly allowlisted origin gets the CORS header; others do not."""
    client = TestClient(_app_with(cors_origins=["https://good.example"]))
    ok = client.get("/health", headers={"Origin": "https://good.example"})
    assert ok.headers.get("access-control-allow-origin") == "https://good.example"


# ---------------------------------------------------------------------------
# ReDoS runtime bound (F-03-02): cap untrusted input fed to registry regexes
# ---------------------------------------------------------------------------


def test_resolve_rejects_oversize_query():
    """A query past MAX_SECID_QUERY_CHARS returns a clean error before any regex."""
    from resolver import resolve, MAX_SECID_QUERY_CHARS
    from storage import create_store
    store = create_store("memory")
    resp = resolve(store, "secid:advisory/" + "a" * (MAX_SECID_QUERY_CHARS + 10))
    assert resp["status"] == "error"
    assert "too long" in resp["message"].lower()


def test_oversize_query_via_http():
    """The cap is enforced through the HTTP layer too (FastAPI Query is unbounded)."""
    from resolver import MAX_SECID_QUERY_CHARS
    client = TestClient(_empty_app())
    resp = client.get("/api/v1/resolve?secid=secid:advisory/" + "a" * (MAX_SECID_QUERY_CHARS + 10))
    assert resp.status_code == 200  # envelope contract: always 200
    assert resp.json()["status"] == "error"


def test_too_long_for_regex_helper():
    """Per-component bound: None and short values pass; an over-long one trips."""
    from resolver import _too_long_for_regex, MAX_REGEX_INPUT
    assert not _too_long_for_regex(None, "cve", "CVE-2021-44228")
    assert _too_long_for_regex("a" * (MAX_REGEX_INPUT + 1))


# ---------------------------------------------------------------------------
# Synthetic registry helpers
# ---------------------------------------------------------------------------


def _write_ns(root, secid_type, rel, namespace, match_nodes, **extra):
    import json
    path = root / secid_type / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema_version": "1.0", "type": secid_type, "namespace": namespace,
        "official_name": extra.pop("official_name", namespace),
        "urls": extra.pop("urls", []), "match_nodes": match_nodes, **extra,
    }))
    return path


def _cve_node(url):
    return [{
        "patterns": ["(?i)^cve$"], "description": "CVE", "weight": 100, "data": {},
        "children": [{
            "patterns": ["^CVE-\\d{4}-\\d{4,}$"], "description": "CVE ID", "weight": 100,
            "data": {"url": url},
        }],
    }]


# ---------------------------------------------------------------------------
# Overlay precedence (H5): a later registry dir overrides an earlier one,
# regardless of load mode or which query arrives first
# ---------------------------------------------------------------------------


def _overlay_dirs(tmp_path):
    public, private = tmp_path / "public", tmp_path / "private"
    _write_ns(public, "advisory", "org/example.json", "example.org",
              _cve_node("https://public.example.org/{id}"))
    _write_ns(private, "advisory", "org/example.json", "example.org",
              _cve_node("https://private.example.org/{id}"))
    return [str(public), str(private)]


def _urls(resp):
    return [r["url"] for r in resp["results"] if "url" in r]


def test_overlay_private_wins_in_every_query_order(tmp_path):
    dirs = _overlay_dirs(tmp_path)
    scoped = "secid:advisory/example.org/cve#CVE-2021-44228"
    unscoped = "secid:advisory/CVE-2021-44228"
    want = "https://private.example.org/CVE-2021-44228"
    for mode in ("lazy", "bulk"):
        for order in ((scoped, unscoped), (unscoped, scoped)):
            client = TestClient(create_app(ServerConfig(registry_dirs=dirs, load_mode=mode)))
            for q in order:
                body = client.get("/api/v1/resolve", params={"secid": q}).json()
                assert _urls(body) == [want], (mode, order, q, body)


def test_overlay_bulk_load_and_load_single_agree(tmp_path):
    import json
    from registry_loader import bulk_load, load_single
    from storage import create_store
    dirs = _overlay_dirs(tmp_path)
    bulk_store, lazy_store = create_store("memory"), create_store("memory")
    bulk_load(bulk_store, dirs)
    load_single(lazy_store, dirs, "advisory", "example.org")
    key = "secid:advisory/example.org"
    assert json.loads(bulk_store.get(key)) == json.loads(lazy_store.get(key))
    assert "private.example.org" in bulk_store.get(key)


# ---------------------------------------------------------------------------
# Hostile-but-harmless input never becomes a 500
# ---------------------------------------------------------------------------


def test_overlong_namespace_segment_is_not_found(tmp_path):
    """A segment longer than the filesystem's name limit used to raise
    OSError (File name too long) from the lazy loader -> HTTP 500."""
    from registry_loader import load_single
    from storage import create_store
    dirs = _overlay_dirs(tmp_path)
    assert load_single(create_store("memory"), dirs, "advisory", "a" * 300 + ".com") is None
    client = TestClient(create_app(ServerConfig(registry_dirs=dirs)))
    resp = client.get("/api/v1/resolve", params={"secid": "secid:advisory/" + "a" * 300 + ".com/x"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "not_found"


def test_unicode_digits_do_not_match_ascii_patterns(tmp_path):
    """Registry regexes are JavaScript regexes, where \\d is ASCII-only."""
    dirs = _overlay_dirs(tmp_path)
    client = TestClient(create_app(ServerConfig(registry_dirs=dirs)))
    q = "secid:advisory/example.org/cve#CVE-\u0662\u0660\u0662\u0661-\u0664\u0664\u0662\u0662\u0668"
    body = client.get("/api/v1/resolve", params={"secid": q}).json()
    assert body["status"] == "related"
    assert not _urls(body)


# ---------------------------------------------------------------------------
# URL substitution hardening
# ---------------------------------------------------------------------------


def test_relative_or_non_http_templates_rejected():
    """A template with no literal http(s) authority has nothing to pin the
    result to, so the substituted value would become the URL."""
    from resolver import _substitute_url_template
    assert _substitute_url_template("{id}", {}, "javascript:alert(1)") is None
    assert _substitute_url_template("/advisories/{id}", {}, "x") is None
    assert _substitute_url_template("ftp://example.com/{id}", {}, "x") is None
    assert _substitute_url_template("https://example.com/static", {}, "x") == "https://example.com/static"


def test_substituted_values_are_percent_encoded():
    """Characters that would re-shape the URL are encoded; characters real
    identifiers use in paths (':' '/' '.') are kept."""
    from resolver import _substitute_url_template
    assert _substitute_url_template("https://example.com/{id}", {}, "a?b#c d") == \
        "https://example.com/a%3Fb%23c%20d"
    assert _substitute_url_template("https://doi.org/{id}", {}, "10.1000/xyz:1") == \
        "https://doi.org/10.1000/xyz:1"


def test_id_lower_and_upper_variables():
    from resolver import _substitute_url_template
    assert _substitute_url_template("https://e.com/{id_lower}/{id_upper}", {}, "CVE-1-Ab") == \
        "https://e.com/cve-1-ab/CVE-1-AB"


# ---------------------------------------------------------------------------
# Parser: qualifiers
# ---------------------------------------------------------------------------


def test_parse_qualifiers_source_and_item_level():
    from resolver import parse_secid
    p = parse_secid(
        "secid:regulation/europa.eu/gdpr?lang=fr&x=1#art-32?lang=de",
        lambda c: c == "europa.eu",
    )
    assert (p.type, p.namespace, p.name, p.subpath) == ("regulation", "europa.eu", "gdpr", "art-32")
    assert p.qualifiers == {"lang": "de", "x": "1"}  # item-level wins


# ---------------------------------------------------------------------------
# /admin/reload diffs against the loaded commit and handles A/M/D/R
# ---------------------------------------------------------------------------


def _git(cwd, *args):
    import subprocess
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
                        "PATH": __import__("os").environ.get("PATH", "")})


def test_admin_reload_applies_modify_delete_rename(tmp_path):
    import shutil
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    repo = tmp_path / "SecID"
    reg = repo / "registry"
    _write_ns(reg, "advisory", "org/alpha.json", "alpha.org", _cve_node("https://alpha.org/v1/{id}"))
    _write_ns(reg, "advisory", "org/beta.json", "beta.org", _cve_node("https://beta.org/{id}"))
    _write_ns(reg, "advisory", "org/gamma.json", "gamma.org", _cve_node("https://gamma.org/{id}"))
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")

    for mode in ("lazy", "bulk"):
        client = TestClient(create_app(ServerConfig(
            registry_dirs=[str(reg)], load_mode=mode, reload_token="t")))

        def urls(q):
            return _urls(client.get("/api/v1/resolve", params={"secid": q}).json())

        assert urls("secid:advisory/alpha.org/cve#CVE-2021-0001") == ["https://alpha.org/v1/CVE-2021-0001"]
        assert urls("secid:advisory/beta.org/cve#CVE-2021-0001")
        # Commit a modify, a delete and a rename (the rename also changes the namespace).
        _write_ns(reg, "advisory", "org/alpha.json", "alpha.org", _cve_node("https://alpha.org/v2/{id}"))
        (reg / "advisory" / "org" / "beta.json").unlink()
        _git(repo, "mv", "registry/advisory/org/gamma.json", "registry/advisory/org/delta.json")
        _write_ns(reg, "advisory", "org/delta.json", "delta.org", _cve_node("https://gamma.org/{id}"))
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "-m", "change")

        resp = client.post("/admin/reload", headers={"X-Reload-Token": "t"})
        assert resp.status_code == 200
        assert resp.json()["reloaded"] == 4  # alpha, beta, gamma, delta

        assert urls("secid:advisory/alpha.org/cve#CVE-2021-0001") == ["https://alpha.org/v2/CVE-2021-0001"]
        beta = client.get("/api/v1/resolve", params={"secid": "secid:advisory/beta.org/cve#CVE-2021-0001"}).json()
        assert beta["status"] == "not_found"
        assert client.get("/api/v1/resolve", params={"secid": "secid:advisory/gamma.org"}).json()["status"] == "not_found"
        assert urls("secid:advisory/delta.org/cve#CVE-2021-0001") == ["https://gamma.org/CVE-2021-0001"]

        # A second reload with nothing new changes nothing.
        assert client.post("/admin/reload", headers={"X-Reload-Token": "t"}).json()["reloaded"] == 0

        # Reset the repo for the next mode.
        _git(repo, "reset", "-q", "--hard", "HEAD~1")


def test_reload_without_git_does_full_reload_and_evicts(tmp_path):
    """Not a git checkout: reload falls back to a full reload, which must
    also evict namespaces whose files were deleted."""
    from registry_loader import update_load
    from storage import create_store
    reg = tmp_path / "registry"
    _write_ns(reg, "advisory", "org/alpha.json", "alpha.org", _cve_node("https://alpha.org/{id}"))
    _write_ns(reg, "advisory", "org/beta.json", "beta.org", _cve_node("https://beta.org/{id}"))
    store = create_store("memory")
    commits = {}
    update_load(store, [str(reg)], commits=commits)
    assert store.get("secid:advisory/beta.org")
    (reg / "advisory" / "org" / "beta.json").unlink()
    update_load(store, [str(reg)], commits=commits)
    assert store.get("secid:advisory/beta.org") is None
    assert store.get("secid:advisory/alpha.org")
