"""Port coverage for optional version trees; independent of registry rollout."""
import json
import pytest
from fastapi.testclient import TestClient
from secid_server import ServerConfig, create_app


@pytest.fixture(params=["lazy", "bulk"])
def optional_client(tmp_path, request):
    source = {"patterns": ["^cwe$"], "description": "CWE fixture", "weight": 100,
              "data": {"version_required": False, "versions_available": [
                  {"version": "5.0"}, {"version": "4.19", "aliases": [{"label": "old", "on_match": "resolve"}]},
                  {"version": "empty"}, {"version": "metadata-only"}]},
              "children": [
                  {"patterns": ["(?i)^CWE-(?:79|1448)$"], "description": "Live", "weight": 100,
                   "data": {"url": "https://test.example/live/{id_upper}"}},
                  {"patterns": [r"^8\.0$"], "description": "Schema", "weight": 100,
                   "data": {"type": "version", "url": "https://test.example/schema/8.0"}}]}
    for v in ["5.0", "4.19", "empty"]:
        source["children"].append({"patterns": ["^" + v.replace(".", r"\.") + "$"],
            "description": v, "weight": 100,
            "data": {"type": "version", "urls": [{"type": "bulk_data", "url": f"https://test.example/{v}.zip"}]},
            "children": [] if v == "empty" else [{
                "patterns": ["(?i)^CWE-(?:79|1448)$" if v == "5.0" else "(?i)^CWE-79$"],
                "description": "Archive entry", "weight": 100,
                "data": {"url": f"https://test.example/{v}.zip", "content_type": "application/zip"}}]})
    path = tmp_path / "weakness" / "example"
    path.mkdir(parents=True)
    (path / "test.json").write_text(json.dumps({"schema_version": "1.0", "namespace": "test.example",
        "type": "weakness", "status": "draft", "official_name": "Test", "match_nodes": [source]}))
    return TestClient(create_app(ServerConfig(registry_dirs=[str(tmp_path)], load_mode=request.param)))


def query(client, q):
    response = client.get("/api/v1/resolve", params={"secid": q})
    assert response.status_code == 200
    return response.json()


def urls(result):
    return [r["url"] for r in result["results"] if "url" in r]


BASE = "secid:weakness/test.example/cwe"


def test_live_and_bare(optional_client):
    for q in [BASE + "#cwe-79", "cwe-79", "CWE-79", "secid:weakness/CWE-79", "secid:weakness/test.example/CWE-79"]:
        assert urls(query(optional_client, q)) == ["https://test.example/live/CWE-79"]


def test_explicit_versions_and_aliases(optional_client):
    for v in ["5.0", "4.19", "old"]:
        expected = "4.19" if v == "old" else v
        result = query(optional_client, BASE + f"@{v}#cwe-79")
        assert result["status"] == "found"
        assert urls(result) == [f"https://test.example/{expected}.zip"]
        assert result["results"][0]["secid"] == BASE + f"@{expected}#cwe-79"
        description = query(optional_client, BASE + f"@{v}")
        assert description["results"][0]["data"]["urls"] == [{"type": "bulk_data", "url": f"https://test.example/{expected}.zip"}]


def test_no_live_fallback(optional_client):
    for suffix in ["@4.19#CWE-1448", "@5.0#CWE-999999", "@empty#CWE-79", "@missing#CWE-79", "@metadata-only#CWE-79"]:
        result = query(optional_client, BASE + suffix)
        assert result["status"] != "found"
        assert urls(result) == []


def test_versions_are_not_items(optional_client):
    assert urls(query(optional_client, BASE + "#5.0")) == []
    assert urls(query(optional_client, "secid:weakness/5.0")) == []
    assert urls(query(optional_client, BASE + "#8.0")) == ["https://test.example/schema/8.0"]
