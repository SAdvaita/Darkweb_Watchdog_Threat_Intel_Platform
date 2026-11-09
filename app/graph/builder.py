import networkx as nx
from sqlmodel import Session, select
from app.models import Finding, Asset, GraphEdge


def build_graph(session: Session) -> nx.DiGraph:
    G = nx.DiGraph()

    # Add assets as nodes
    assets = session.exec(select(Asset)).all()
    for asset in assets:
        G.add_node(
            f"asset:{asset.id}",
            type="asset",
            value=asset.value,
            criticality=asset.criticality,
        )

    # Add findings as nodes
    findings = session.exec(select(Finding)).all()
    for finding in findings:
        G.add_node(
            f"finding:{finding.id}",
            type="finding",
            severity=finding.severity,
            score=finding.score,
        )
        if finding.asset_id:
            G.add_edge(
                f"asset:{finding.asset_id}",
                f"finding:{finding.id}",
                relation="mentioned_in",
            )

    # Add persisted edges
    edges = session.exec(select(GraphEdge)).all()
    for edge in edges:
        src = f"{edge.src_type}:{edge.src_id}"
        dst = f"{edge.dst_type}:{edge.dst_id}"
        G.add_edge(src, dst, relation=edge.relation, weight=edge.weight)

    return G


def blast_radius(G: nx.DiGraph, node_id: str, hops: int = 2) -> float:
    """Criticality-weighted count of assets within N hops."""
    try:
        neighbors = nx.single_source_shortest_path_length(G, node_id, cutoff=hops)
        total = 0.0
        for n, dist in neighbors.items():
            if G.nodes[n].get("type") == "asset":
                criticality = G.nodes[n].get("criticality", 1)
                total += criticality / (dist + 1)
        return round(total, 2)
    except Exception:
        return 0.0
