import networkx as nx
from typing import List, Dict, Any, Optional


def find_shortest_path(G: nx.DiGraph, source: str, target: str) -> List[str]:
    try:
        return nx.shortest_path(G, source, target)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []


def find_clusters(G: nx.DiGraph) -> List[List[str]]:
    """Find clusters of related findings and entities."""
    undirected = G.to_undirected()
    components = nx.connected_components(undirected)
    # Only return components with > 1 node as clusters
    return [list(c) for c in components if len(c) > 1]


def shortest_path_to_crown_jewel(G: nx.DiGraph, start_node: str) -> Optional[Dict[str, Any]]:
    """
    Find shortest path from an exposed node to any crown-jewel asset (criticality 5).
    Returns path and target asset if found.
    """
    crown_jewels = [
        n for n, d in G.nodes(data=True)
        if d.get("type") == "asset" and d.get("criticality") == 5
    ]

    shortest: Optional[List[str]] = None
    target_jewel: Optional[str] = None

    for cj in crown_jewels:
        try:
            # Check both directions or undirected for reachability
            path = nx.shortest_path(G.to_undirected(), start_node, cj)
            if shortest is None or len(path) < len(shortest):
                shortest = path
                target_jewel = cj
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue

    if shortest and target_jewel:
        return {
            "target": target_jewel,
            "target_value": G.nodes[target_jewel].get("value"),
            "hops": len(shortest) - 1,
            "path": shortest,
        }
    return None
