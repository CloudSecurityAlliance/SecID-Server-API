"""Smoke tests — verify the core resolver modules import cleanly and basic
constants/behavior are sane.

This is intentionally minimal: import-level guarantees plus a couple of
sanity assertions. Full test coverage will come with the conformance suite
work tracked in SecID-Client-SDK.

Note: deliberately does NOT import secid_server.py — that module runs
argparse + storage initialization at import time, which makes it untestable
without restructuring. A future PR will move its CLI bootstrap into a
main() function gated by `if __name__ == "__main__":`.
"""

import pytest


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
    """Confirm resolver.py imports SECID_TYPES from registry_loader rather
    than redefining it (PR #4 dedup)."""
    import resolver
    import registry_loader
    assert resolver.SECID_TYPES is registry_loader.SECID_TYPES, (
        "resolver.SECID_TYPES should be the same object as "
        "registry_loader.SECID_TYPES (imported, not redefined). "
        "If they differ, the dedup from PR #4 has regressed."
    )


def test_resolve_handles_empty_input():
    """resolve() must not crash on edge inputs — minimum contract."""
    from resolver import resolve
    from storage import create_store

    store = create_store("memory")
    result = resolve(store, "")
    assert isinstance(result, dict)
    # Empty input should produce an error envelope, not raise.
    assert "secid_query" in result or "error" in result or "results" in result


def test_resolve_handles_missing_prefix():
    """A SecID without the 'secid:' prefix is malformed; must return an error envelope."""
    from resolver import resolve
    from storage import create_store

    store = create_store("memory")
    result = resolve(store, "advisory/mitre.org/cve#CVE-2021-44228")
    assert isinstance(result, dict)
    # Should produce SOME response, not raise.
