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
