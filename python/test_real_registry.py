"""Resolver behaviour against the REAL SecID registry.

The smoke tests use hand-built fixtures, which is how the resolver drifted
from the live service without anyone noticing: a tiny synthetic registry
never exercises version_required sources, lookup tables, open patterns, or
cross-source search over 2,000 namespaces. This file loads the actual
registry and checks the self-hosted server's answers against the live
resolver at secid.cloudsecurityalliance.org (SecID-Service), which is the
reference for correct behaviour.

Three sources of cases:

  1. SecID-Client-SDK/tests/fixtures.json - the shared client fixtures.
     Those carry *mock* response bodies written for client tests, so only
     the parts that describe resolver behaviour are checked (status and
     best URL). Where a mock disagrees with the live resolver, LIVE_OVERRIDES
     records the live answer and why.
  2. SecID-Client-SDK/tests/conformance/fixtures.json - the resolver
     conformance suite, checked with that suite's own behavioural assertions.
  3. TARGETED_CASES below - specific behaviours, each expectation taken from
     the live resolver.

Every case runs in both load modes (lazy and bulk), because the two paths
have diverged before.

Locations (both optional; the tests skip with a clear message if absent):

  SECID_REGISTRY_DIR    path to SecID/registry   (default: ../../SecID/registry)
  SECID_CLIENT_SDK_DIR  path to SecID-Client-SDK (default: ../../SecID-Client-SDK)

Run:  cd python && pytest test_real_registry.py -v
"""

from __future__ import annotations

import importlib.util
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest
from fastapi.testclient import TestClient

from secid_server import ServerConfig, create_app

_HERE = Path(__file__).resolve().parent
REGISTRY_DIR = Path(
    os.environ.get("SECID_REGISTRY_DIR") or _HERE.parent.parent / "SecID" / "registry"
)
SDK_DIR = Path(
    os.environ.get("SECID_CLIENT_SDK_DIR") or _HERE.parent.parent / "SecID-Client-SDK"
)
CLIENT_FIXTURES = SDK_DIR / "tests" / "fixtures.json"
CONFORMANCE_FIXTURES = SDK_DIR / "tests" / "conformance" / "fixtures.json"
CONFORMANCE_HARNESS = SDK_DIR / "tests" / "conformance-harness" / "python" / "run.py"

if not (REGISTRY_DIR / "advisory").is_dir():
    pytest.skip(
        f"Real SecID registry not found at {REGISTRY_DIR}. Clone "
        "https://github.com/CloudSecurityAlliance/SecID next to this repo or "
        "set SECID_REGISTRY_DIR=/path/to/SecID/registry.",
        allow_module_level=True,
    )

SDK_MISSING = (
    f"SecID-Client-SDK not found at {SDK_DIR}. Clone "
    "https://github.com/CloudSecurityAlliance/SecID-Client-SDK next to this "
    "repo or set SECID_CLIENT_SDK_DIR=/path/to/SecID-Client-SDK."
)


# ---------------------------------------------------------------------------
# App under test - one per load mode, shared across the module
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", params=["lazy", "bulk"])
def client(request) -> TestClient:
    app = create_app(ServerConfig(registry_dirs=[str(REGISTRY_DIR)], load_mode=request.param))
    return TestClient(app)


def _resolve(client: TestClient, secid: str) -> tuple[int, dict]:
    resp = client.get("/api/v1/resolve", params={"secid": secid})
    try:
        body = resp.json()
    except ValueError:
        body = {"_raw": resp.text[:500]}
    return resp.status_code, body


def _urls(body: dict) -> list[str]:
    return [r["url"] for r in body.get("results", []) if isinstance(r, dict) and r.get("url")]


# ---------------------------------------------------------------------------
# Known divergences from the live resolver
#
# Each entry is a case id that currently fails, with the reason. They are
# strict xfails: when a fix lands the case XPASSes, which fails the run, so
# the entry has to be deleted in the same change. Delete this block once it
# is empty.
# ---------------------------------------------------------------------------

_UNMATCHED = "unmatched subpath returns the parent as found instead of related"
_OPEN = "open_pattern / known_values ignored, so open patterns fabricate matches"
_DEPTH = "resolution only walks one level: version_required, lookup_table and versioned grandchildren are not handled"
_VARS = "URL variables beyond {id} / simple extract ({id_lower}, range_table, lang) not implemented"
_QUAL = "?qualifiers are not parsed"
_CORRECTED = "'corrected' status never returned"
_ASCII = "registry regexes compiled without re.ASCII, so Unicode digits match \\d"
_DISCOVERY = "discovery responses (root, bare type, wildcard, namespace listing) differ from live"
_NOTFOUND = "not_found paths differ from live (unknown type is 'error', no guidance message)"

KNOWN_FAILURES = {
    # client fixtures
    "corrected_misplaced_subpath": _CORRECTED,
    "error_malformed": _NOTFOUND,
    "not_found_unknown_type": _NOTFOUND,
    # targeted
    "unmatched-subpath-disa": _UNMATCHED,
    "unmatched-subpath-cve": _UNMATCHED,
    "unknown-version": _DEPTH,
    "open-pattern-unscoped": _OPEN,
    "no-fabricated-torvalds": _OPEN,
    "no-fabricated-ismap": _OPEN,
    "namespace-identity": "namespace identity search (identity.ts) not implemented",
    "versioned-lookup-table": _DEPTH,
    "version-required-without-version": _DEPTH,
    "version-kept-in-secid": "the @version is dropped from result secids",
    "lookup-table-versioned": _DEPTH,
    "lookup-table-unversioned": _DEPTH,
    "id-lower": _VARS,
    "range-table": _VARS,
    "lang-default": _VARS,
    "lang-qualifier": _QUAL,
    "lang-unavailable": _QUAL,
    "source-qualifier-stripped": _QUAL,
    "content-type-qualifier": _QUAL,
    "corrected-misplaced-subpath": _CORRECTED,
    "unicode-digits-unscoped": _ASCII,
    "unicode-digits-scoped": _ASCII,
    "unknown-type": _NOTFOUND,
    "namespace-miss": _NOTFOUND,
    "overlong-namespace-segment": "a 256-char namespace segment raises OSError (File name too long) -> HTTP 500",
    "root": _DISCOVERY,
    "type-wildcard": _DISCOVERY,
    "namespace-listing": _DISCOVERY,
}


def _known_failure(case_id: str) -> list:
    reason = KNOWN_FAILURES.get(case_id)
    return [pytest.mark.xfail(reason=reason, strict=True)] if reason else []


# ---------------------------------------------------------------------------
# 1. Shared client fixtures
# ---------------------------------------------------------------------------

# fixture name -> (live status, reason the mock body is not what live returns)
LIVE_OVERRIDES = {
    "error_malformed": (
        "not_found",
        "Input without a 'secid:' prefix is a bare-identifier search on the "
        "live resolver; nothing matches, so it answers not_found (Invalid type).",
    ),
    "related_version_required": (
        "found",
        "A version_required source queried with no version and no subpath is "
        "described (found); 'related' + disambiguation applies once a subpath "
        "is given without @version.",
    ),
}


def _client_fixture_cases() -> list:
    if not CLIENT_FIXTURES.is_file():
        return [pytest.param(None, marks=pytest.mark.skip(reason=SDK_MISSING), id="client-fixtures")]
    tests = json.loads(CLIENT_FIXTURES.read_text())["tests"]
    cases = []
    for t in tests:
        if t.get("category") == "client_error" or t["input"].get("method") != "resolve":
            continue  # transport-level client behaviour; nothing to check server-side
        cases.append(pytest.param(t, id=t["name"], marks=_known_failure(t["name"])))
    return cases


@pytest.mark.parametrize("fixture", _client_fixture_cases())
def test_client_fixture(client: TestClient, fixture: dict) -> None:
    expected = fixture["expected"]
    want_status = LIVE_OVERRIDES.get(fixture["name"], (expected["status"], ""))[0]
    http_status, body = _resolve(client, fixture["input"]["secid"])
    assert http_status == 200, body
    assert body.get("status") == want_status, body
    if expected.get("best_url"):
        assert expected["best_url"] in _urls(body), body


# ---------------------------------------------------------------------------
# 2. Resolver conformance suite (behavioural assertions)
# ---------------------------------------------------------------------------


def _load_check_behavioral():
    spec = importlib.util.spec_from_file_location("secid_conformance_run", CONFORMANCE_HARNESS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.check_behavioral


def _conformance_cases() -> list:
    if not (CONFORMANCE_FIXTURES.is_file() and CONFORMANCE_HARNESS.is_file()):
        return [pytest.param(None, marks=pytest.mark.skip(reason=SDK_MISSING), id="conformance")]
    tests = json.loads(CONFORMANCE_FIXTURES.read_text())["tests"]
    return [pytest.param(t, id=t["name"]) for t in tests]


@pytest.mark.parametrize("fixture", _conformance_cases())
def test_conformance_fixture(client: TestClient, fixture: dict) -> None:
    check_behavioral = _load_check_behavioral()
    inp = fixture["input"]
    resp = client.request(inp.get("method", "GET"), inp["endpoint"], params=inp.get("query") or {})
    failures = check_behavioral(resp.json(), resp.status_code, fixture["expected"])
    assert not failures, failures


# ---------------------------------------------------------------------------
# 3. Targeted cases (expectations taken from the live resolver)
# ---------------------------------------------------------------------------


@dataclass
class Case:
    id: str
    secid: str
    status: str
    url: Optional[str] = None            # must appear among result URLs
    first_secid: Optional[str] = None    # results[0].secid must equal this
    message: Optional[str] = None        # response message must contain this
    no_urls: bool = False                # no result may carry a URL
    absent_url: Optional[str] = None     # this URL must NOT appear
    result_secids: Optional[list] = None # exact list of result secids, in order


ISSUES = "https://github.com/CloudSecurityAlliance/SecID/issues"
CVE_URL = "https://www.cve.org/CVERecord?id=CVE-2021-44228"
GDPR = "https://eur-lex.europa.eu/legal-content/{}/TXT/HTML/?uri=CELEX:32016R0679"
ALL_TYPES = [
    "advisory", "capability", "control", "disclosure", "entity",
    "methodology", "reference", "regulation", "ttp", "weakness",
]

TARGETED_CASES = [
    # --- subpath that matches no child pattern: related, never the parent as found
    Case("unmatched-subpath-disa", "secid:control/disa.mil/aaa-services#V-999999",
         "related", message="did not match"),
    Case("unmatched-subpath-cve", "secid:advisory/mitre.org/cve#NOTACVE",
         "related", message="did not match", no_urls=True),
    Case("unknown-version", "secid:weakness/owasp.org/top10@2025#LLM01",
         "not_found", message='Version "2025" not found'),

    # --- open_pattern / known_values: open spaces never answer an unscoped search
    Case("open-pattern-unscoped", "secid:advisory/HADOOP-1234",
         "not_found", message=ISSUES),
    Case("open-pattern-scoped", "secid:advisory/apache.org/jira#HADOOP-1234",
         "found", url="https://issues.apache.org/jira/browse/HADOOP-1234"),
    Case("no-fabricated-torvalds", "secid:reference/torvalds", "not_found"),
    Case("no-fabricated-ismap", "secid:reference/ismap", "not_found"),
    Case("namespace-identity", "secid:control/ismap",
         "found", url="https://www.ismap.go.jp/", first_secid="secid:control/ismap.go.jp"),

    # --- versioned (3-level) resolution
    Case("versioned-lookup-table", "secid:weakness/owasp.org/top10@2021#A01",
         "found", url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
         first_secid="secid:weakness/owasp.org/top10@2021#A01"),
    Case("version-required-without-version", "secid:weakness/owasp.org/top10#A01",
         "related", message="requires a version"),
    Case("version-kept-in-secid", "secid:control/cloudsecurityalliance.org/ccm@4.0#IAM-12",
         "found", first_secid="secid:control/cloudsecurityalliance.org/ccm@4.0#IAM-12"),
    Case("describe-version", "secid:methodology/first.org/cvss@4.0",
         "found", first_secid="secid:methodology/first.org/cvss@4.0"),

    # --- lookup_table (own-key semantics)
    Case("lookup-table-versioned", "secid:weakness/owasp.org/llm-top10@2.0#LLM01",
         "found", url="https://genai.owasp.org/llmrisk/llm01-prompt-injection/"),
    Case("lookup-table-missing-key", "secid:weakness/owasp.org/llm-top10@2.0#LLM99",
         "found", no_urls=True),
    Case("lookup-table-unversioned", "secid:reference/spdx.dev/spdx#ai",
         "found", url="https://spdx.github.io/spdx-spec/v3.0.1/model/AI/AI/"),

    # --- URL template variables
    Case("id-lower", "secid:advisory/oracle.com/alert#CVE-2021-44228",
         "found", url="https://www.oracle.com/security-alerts/alert-cve-2021-44228.html"),
    Case("range-table", "secid:advisory/debian.org/dsa#DSA-5000-1",
         "found", url="https://www.debian.org/security/2021/dsa-5000"),

    # --- qualifiers
    Case("lang-default", "secid:regulation/europa.eu/gdpr#art-32",
         "found", url=GDPR.format("EN")),
    Case("lang-qualifier", "secid:regulation/europa.eu/gdpr#art-32?lang=de",
         "found", url=GDPR.format("DE"), absent_url=GDPR.format("EN")),
    Case("lang-unavailable", "secid:regulation/europa.eu/gdpr#art-32?lang=xx",
         "not_found", message='Language "xx" not available'),
    Case("source-qualifier-stripped", "secid:advisory/mitre.org/cve?foo=bar#CVE-2021-44228",
         "found", url=CVE_URL),
    Case("content-type-qualifier",
         "secid:advisory/mitre.org/cve#CVE-2021-44228?content_type=application/json",
         "found", url="https://cveawg.mitre.org/api/cve/CVE-2021-44228", absent_url=CVE_URL),

    # --- corrected
    Case("corrected-misplaced-subpath", "secid:advisory/redhat.com/RHSA-2026:0932",
         "corrected", url="https://access.redhat.com/errata/RHSA-2026:0932",
         first_secid="secid:advisory/redhat.com/errata#RHSA-2026:0932"),

    # --- regexes are ASCII: Unicode digits are not \d
    Case("unicode-digits-unscoped", "secid:advisory/CVE-٢٠٢١-٤٤٢٢٨",
         "not_found"),
    Case("unicode-digits-scoped", "secid:advisory/mitre.org/cve#CVE-٢٠٢١-٤٤٢٢٨",
         "related", no_urls=True),

    # --- error / not_found paths
    Case("unknown-type", "secid:notatype/foo", "not_found", message="Invalid type"),
    Case("empty-query", "", "error"),
    Case("namespace-miss", "secid:advisory/nonexistent.example.com/foo#BAR-123",
         "not_found", message="not found"),
    Case("overlong-namespace-segment", "secid:advisory/" + "a" * 256 + ".com/x", "not_found"),

    # --- discovery
    Case("root", "secid:", "found", result_secids=[f"secid:{t}" for t in ALL_TYPES]),
    Case("bare-type", "secid:advisory", "found", first_secid="secid:advisory"),
    Case("type-wildcard", "secid:control/*", "found", first_secid="secid:control"),
    Case("namespace-listing", "secid:advisory/oracle.com", "found",
         first_secid="secid:advisory/oracle.com/cpu"),
]


def _targeted_params() -> list:
    return [pytest.param(c, id=c.id, marks=_known_failure(c.id)) for c in TARGETED_CASES]


@pytest.mark.parametrize("case", _targeted_params())
def test_targeted(client: TestClient, case: Case) -> None:
    http_status, body = _resolve(client, case.secid)
    assert http_status == 200, body
    assert body.get("status") == case.status, body
    results = body.get("results", [])
    urls = _urls(body)
    if case.url:
        assert case.url in urls, body
    if case.absent_url:
        assert case.absent_url not in urls, body
    if case.no_urls:
        assert not urls, body
    if case.first_secid:
        assert results and results[0].get("secid") == case.first_secid, body
    if case.result_secids is not None:
        assert [r.get("secid") for r in results] == case.result_secids, body
    if case.message:
        assert case.message in (body.get("message") or ""), body
