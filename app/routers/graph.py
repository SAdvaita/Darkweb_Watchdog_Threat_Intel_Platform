from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlmodel import Session
from app.database import get_session
from app.graph.builder import build_graph, blast_radius as compute_blast_radius
from app.graph.analysis import find_clusters, shortest_path_to_crown_jewel, find_shortest_path

router = APIRouter()


@router.get("/")
async def get_graph(session: Session = Depends(get_session)):
    G = build_graph(session)
    nodes = [{"id": n, **G.nodes[n]} for n in G.nodes()]
    edges = [{"source": u, "target": v, **d} for u, v, d in G.edges(data=True)]
    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
    }


@router.get("/blast-radius/{asset_id}")
async def get_blast_radius(asset_id: int, session: Session = Depends(get_session)):
    G = build_graph(session)
    node_id = f"asset:{asset_id}"
    if node_id not in G:
        raise HTTPException(status_code=404, detail="Asset not found in graph")

    radius = compute_blast_radius(G, node_id)
    clusters = find_clusters(G)
    path_to_crown = shortest_path_to_crown_jewel(G, node_id)

    return {
        "asset_id": asset_id,
        "node_id": node_id,
        "blast_radius": radius,
        "cluster_count": len(clusters),
        "path_to_crown_jewel": path_to_crown,
    }


@router.get("/shortest-path")
async def get_shortest_path(
    source: str = Query(..., description="Source node id, e.g. finding:1"),
    target: str = Query(..., description="Target node id, e.g. asset:2"),
    session: Session = Depends(get_session),
):
    G = build_graph(session)
    path = find_shortest_path(G, source, target)
    return {"source": source, "target": target, "path": path, "hops": max(0, len(path) - 1)}


@router.get("/clusters")
async def get_clusters(session: Session = Depends(get_session)):
    G = build_graph(session)
    clusters = find_clusters(G)
    return {
        "total_clusters": len(clusters),
        "clusters": [{"size": len(c), "nodes": c} for c in clusters],
    }
