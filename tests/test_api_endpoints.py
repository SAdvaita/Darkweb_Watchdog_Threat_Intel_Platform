import pytest
from app.models import Finding, SourceHealth, Asset, Canary


def test_health_and_root(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}

    r = client.get("/", headers={"accept": "application/json"})
    assert r.status_code == 200
    assert r.json()["status"] == "operational"

    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


def test_metrics_summary_and_sources_health(client, session):
    f = Finding(
        rule_id="DWW-TEST-001",
        title="Test Finding",
        category="credential",
        severity="critical",
        score=95,
        confidence=0.9,
        status="new",
    )
    session.add(f)
    src = SourceHealth(
        source="github_gist",
        status="healthy",
        items_fetched=42,
        errors_total=0,
    )
    session.add(src)
    session.commit()

    # Metrics summary
    r = client.get("/metrics/summary")
    assert r.status_code == 200
    data = r.json()
    assert "total_findings" in data
    assert "severity_counts" in data
    assert data["severity_counts"]["critical"] >= 1
    assert "open_cases" in data

    # Sources health
    r = client.get("/sources/health")
    assert r.status_code == 200
    sources = r.json()
    assert isinstance(sources, list)
    assert any(s["source"] == "github_gist" for s in sources)


def test_cases_crud_and_status_update(client):
    # Create case
    r = client.post("/cases/", json={"title": "Investigate DB leak", "severity": "high", "finding_ids": []})
    assert r.status_code == 200
    case_data = r.json()
    assert case_data["id"] is not None
    case_id = case_data["id"]
    assert case_data["title"] == "Investigate DB leak"

    # Update case status
    r = client.patch(f"/cases/{case_id}", json={"status": "triage"})
    assert r.status_code == 200
    assert r.json()["status"] == "triage"

    # List cases
    r = client.get("/cases/")
    assert r.status_code == 200
    assert any(c["id"] == case_id for c in r.json())


def test_findings_list_and_detail(client, session):
    f = Finding(
        rule_id="DWW-CRED-001",
        title="Email password leaked",
        category="credential",
        severity="critical",
        score=92,
        confidence=0.95,
        status="new",
        score_breakdown='{"category_base": 50, "plaintext_secret": 15}',
        attack_techniques='["T1552.001"]',
    )
    session.add(f)
    session.commit()
    session.refresh(f)

    # List with filters
    r = client.get("/findings/?severity=critical&status=new")
    assert r.status_code == 200
    results = r.json()
    assert len(results) >= 1
    assert results[0]["id"] == f.id
    assert results[0]["score_breakdown"]["category_base"] == 50

    # Get single finding
    r = client.get(f"/findings/{f.id}")
    assert r.status_code == 200
    single = r.json()
    assert single["id"] == f.id
    assert single["attack_techniques"] == ["T1552.001"]


def test_rules_endpoints(client):
    r = client.get("/rules/")
    assert r.status_code == 200
    rules = r.json()
    assert len(rules) >= 12
    rule_ids = [r["id"] for r in rules]
    assert "DWW-CRED-001" in rule_ids

    # Test rule runner
    r = client.post(
        "/rules/test",
        json={
            "text": "alice@acme.example:SuperSecretP@ss123!",
            "source": "github_gist",
            "watched_domains": ["acme.example"],
        },
    )
    assert r.status_code == 200
    matches = r.json()
    assert any(m["rule_id"] == "DWW-CRED-001" for m in matches)


def test_audit_verify_endpoint(client):
    r = client.get("/audit/verify")
    assert r.status_code == 200
    data = r.json()
    assert "valid" in data
    assert data["valid"] is True


def test_canary_metrics_endpoint(client, session):
    c = Canary(
        type="gist",
        marker="CNRY-TEST1234",
        location_url="https://gist.github.com/test",
        detected_source="github_gist",
        time_to_detect_seconds=12.4,
    )
    session.add(c)
    session.commit()

    r = client.get("/canaries/metrics")
    assert r.status_code == 200
    metrics = r.json()
    assert metrics["total_planted"] >= 1
    assert metrics["total_detected"] >= 1
    assert "by_source" in metrics


def test_export_endpoints(client):
    r = client.get("/export/stix")
    assert r.status_code == 200
    assert r.json()["type"] == "bundle"

    r = client.get("/export/navigator")
    assert r.status_code == 200
    assert "techniques" in r.json()

    r = client.get("/export/pdf")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert len(r.content) > 100
