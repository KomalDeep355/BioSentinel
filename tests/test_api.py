from fastapi.testclient import TestClient
from biosentinel.api import create_app


def test_demo_endpoint_and_dashboard():
    c = TestClient(create_app())
    r = c.post("/demo/poisoned_dependency")
    assert r.status_code == 200 and "Incident report" in r.json()["report"]
    assert "BioSentinel" in c.get("/").text
    assert c.post("/demo/nope").status_code == 404


def test_dashboard_assets():
    c = TestClient(create_app())

    css = c.get("/styles.css")
    assert css.status_code == 200
    assert css.headers["content-type"].startswith("text/css")
    assert "body" in css.text

    javascript = c.get("/app.js")
    assert javascript.status_code == 200
    assert javascript.headers["content-type"].startswith("application/javascript")
    assert javascript.text

    live_javascript = c.get("/live.js")
    assert live_javascript.status_code == 200
    assert live_javascript.headers["content-type"].startswith("application/javascript")
    assert "Live agent feed" in live_javascript.text


def test_ingest_and_gateway():
    c = TestClient(create_app())
    r = c.post("/ingest", json={"agent_id": "a1", "step": 0, "text": "Summarized the report."})
    assert r.json()["state"] == "HEALTHY"
    assert c.get("/allow/a1").json()["allowed"] is True
import pytest
from fastapi.testclient import TestClient
from biosentinel.api import create_app


@pytest.mark.parametrize(
    "scenario",
    [
        "obfuscated_rce",
        "weak_key_gatekeeper",
        "poisoned_dependency",
        "prompt_leak",
    ],
)
def test_demo_scenarios_return_forensic_results(scenario):
    client = TestClient(create_app())

    response = client.post(f"/demo/{scenario}")

    assert response.status_code == 200

    data = response.json()

    assert data["description"]
    assert isinstance(data["breach_step"], int)
    assert isinstance(data["timeline"], list)
    assert len(data["timeline"]) > 0

    assert any(
        item["state"] == "QUARANTINED"
        for item in data["timeline"]
    )

    assert isinstance(data["report"], str)
    assert "Incident report" in data["report"]