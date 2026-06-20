"""Smoke tests — verify the core resolver modules import cleanly, basic
constants/behavior are sane, and the secid_server factory produces a
working FastAPI app.

After the secid_server.py refactor (factory pattern), this file can now
test the HTTP layer too via fastapi.testclient.TestClient.
"""

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


def test_slug_from_pattern_simple():
    """Canonical case-insensitive pattern produces a clean slug."""
    from resolver import _slug_from_pattern
    assert _slug_from_pattern("(?i)^cve$") == "cve"
    assert _slug_from_pattern("(?i)^kev$") == "kev"


def test_slug_from_pattern_with_dots_and_dashes():
    """Patterns with dots and dashes (allowed in slugs) extract correctly."""
    from resolver import _slug_from_pattern
    assert _slug_from_pattern("(?i)^av-collision$") == "av-collision"
    assert _slug_from_pattern("(?i)^ml.top10$") == "ml.top10"


def test_slug_from_pattern_complex_returns_none():
    """Patterns with character classes, alternation, or quantifiers don't
    yield a clean slug — we return None and the caller falls back to omitting
    the source segment from the SecID."""
    from resolver import _slug_from_pattern
    assert _slug_from_pattern("^CVE-\\d{4}-\\d{4,}$") is None
    assert _slug_from_pattern("(a|b)") is None


def test_cross_source_search_empty_term():
    """Empty search_term should return empty list immediately."""
    from resolver import _cross_source_search
    from storage import create_store
    store = create_store("memory")
    assert _cross_source_search(store, "advisory", "", None) == []


def test_cross_source_search_no_registry():
    """No registry data + no registry_dirs = no results."""
    from resolver import _cross_source_search
    from storage import create_store
    store = create_store("memory")
    assert _cross_source_search(store, "advisory", "CVE-2021-44228", None) == []


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
