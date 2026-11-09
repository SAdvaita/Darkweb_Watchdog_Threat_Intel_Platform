"""
Milestone M5 Acceptance Tests:
1. Graph builds nodes for assets, findings, and persisted edges
2. Blast radius calculation computes criticality-weighted reach within 2 hops
3. Shortest path to crown jewel (criticality 5) is resolved
4. Clusters of connected findings and assets are identified
5. Graph API endpoint returns nodes, edges, blast-radius, and clusters
"""
import pytest
from sqlmodel import SQLModel, create_engine, Session
from sqlmodel.pool import StaticPool
from fastapi.testclient import TestClient

from app.models import Asset, Finding, GraphEdge
from app.graph.builder import build_graph, blast_radius
from app.graph.analysis import find_clusters, shortest_path_to_crown_jewel
from app.main import app
from app.database import get_session


@pytest.fixture(name="db_session")
def db_session_fixture():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_m5_graph_build_and_blast_radius(db_session: Session):
    # Create crown jewel asset
    cj = Asset(type="domain", value="core.internal.acme", criticality=5, owner="CTO")
    db_session.add(cj)

    # Create intermediate asset
    sub = Asset(type="subdomain", value="api.acme.example", criticality=3, owner="Eng")
    db_session.add(sub)
    db_session.commit()
    db_session.refresh(cj)
    db_session.refresh(sub)

    # Link assets with an edge
    edge = GraphEdge(
        src_type="asset",
        src_id=str(sub.id),
        relation="resolves_to",
        dst_type="asset",
        dst_id=str(cj.id),
    )
    db_session.add(edge)

    # Create a finding on the subdomain
    finding = Finding(
        title="API key exposed",
        severity="high",
        score=75,
        asset_id=sub.id,
    )
    db_session.add(finding)
    db_session.commit()

    # Build graph
    G = build_graph(db_session)
    assert len(G.nodes) >= 3

    # Calculate blast radius from the finding or the exposed asset
    radius = blast_radius(G, f"asset:{sub.id}", hops=2)
    assert radius > 0

    # Verify crown jewel path detection
    res = shortest_path_to_crown_jewel(G, f"finding:{finding.id}")
    assert res is not None
    assert res["target"] == f"asset:{cj.id}"
    assert res["hops"] == 2

    # Verify clusters
    clusters = find_clusters(G)
    assert len(clusters) >= 1


def test_m5_graph_api_endpoints(db_session: Session):
    asset = Asset(type="domain", value="test.example.com", criticality=4)
    db_session.add(asset)
    db_session.commit()
    db_session.refresh(asset)

    def get_session_override():
        yield db_session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)

    # GET /graph/
    resp = client.get("/graph/")
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert "edges" in data

    # GET /graph/blast-radius/{asset_id}
    resp2 = client.get(f"/graph/blast-radius/{asset.id}")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["asset_id"] == asset.id
    assert "blast_radius" in data2

    app.dependency_overrides.clear()
