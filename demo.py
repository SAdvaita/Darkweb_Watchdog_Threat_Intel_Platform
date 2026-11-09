"""
DarkWeb Watchdog — Interactive Demo Script
Demonstrates end-to-end capabilities in under 60 seconds:
1. Plants a tracer canary
2. Ingests leak-site, certificate, infostealer, and code exposure data
3. Normalizes and redacts secrets before storage
4. Evaluates detection-as-code YAML rules (mapped to MITRE ATT&CK)
5. Correlates findings in the Knowledge Graph and computes blast radius
6. Calculates explainable severity + confidence scores
7. Automatically raises high/critical Cases with SLA timers
8. Verifies tamper-evident SHA-256 audit log integrity
"""
import asyncio
import json
from datetime import datetime, timezone

from sqlmodel import Session, select

from app.database import engine, create_db_and_tables
from app.models import Asset, RawItem, Finding, Case, Canary, GraphEdge
from app.collectors.base import RawItemData
from app.pipeline.processor import process_raw_item
from app.canary.planter import plant_snippet_canary
from app.cases.audit import verify_chain
from app.graph.builder import build_graph, blast_radius
from app.graph.analysis import shortest_path_to_crown_jewel
from app.config import settings


def print_banner():
    print(r"""
=======================================================================
   ____             _    __          __   _      _   _       _            
  |  _ \  __ _ _ __| | _ \ \        / /__| |__  | | | | __ _| |_ ___  
  | | | |/ _` | '__| |/ / \ \  /\  / / _ \ '_ \ | | | |/ _` | __/ __| 
  | |_| | (_| | |  |   <   \ \/  \/ /  __/ |_) || |_| | (_| | || (__  
  |____/ \__,_|_|  |_|\_\   \__/ \_/ \___|_.__/  \___/ \__,_|\__\___| 
                                                                       
        Canary-Validated External Exposure Intelligence Platform       
=======================================================================
""")


async def run_demo():
    print_banner()
    create_db_and_tables()

    # Step 1: Configure Watchlist
    print("[1/7] Initializing Watchlist and Crown-Jewel Assets...")
    settings.watched_domains = "acme.example,acmecorp.com"
    root_asset_id = None
    crown_asset_id = None

    with Session(engine) as session:
        # Seed core asset
        root_asset = session.exec(select(Asset).where(Asset.value == "acme.example")).first()
        if not root_asset:
            root_asset = Asset(type="domain", value="acme.example", criticality=4, owner="SecOps")
            session.add(root_asset)

        # Seed crown-jewel asset (criticality 5)
        crown_asset = session.exec(select(Asset).where(Asset.value == "vault.internal.acme")).first()
        if not crown_asset:
            crown_asset = Asset(type="domain", value="vault.internal.acme", criticality=5, owner="CISO")
            session.add(crown_asset)

        session.commit()
        session.refresh(root_asset)
        session.refresh(crown_asset)
        root_asset_id = root_asset.id
        crown_asset_id = crown_asset.id

        # Connect crown jewel in graph if edge doesn't exist
        existing_edge = session.exec(select(GraphEdge).where(
            GraphEdge.src_id == str(root_asset_id),
            GraphEdge.dst_id == str(crown_asset_id),
        )).first()
        if not existing_edge:
            edge = GraphEdge(
                src_type="asset",
                src_id=str(root_asset_id),
                relation="resolves_to",
                dst_type="asset",
                dst_id=str(crown_asset_id),
                weight=2.0,
            )
            session.add(edge)
            session.commit()

    print(f"      [OK] Root Perimeter: acme.example (Crit: 4)")
    print(f"      [OK] Crown Jewel:    vault.internal.acme (Crit: 5)\n")

    # Step 2: Plant Canary Tracer
    print("[2/7] Planting Harmless Canary Tracer Token...")
    canary_id = None
    canary_marker = None
    canary_url = None

    with Session(engine) as session:
        canary = plant_snippet_canary(
            session,
            canary_type="snippet",
            location_url="https://gist.github.com/decoy/config.env",
        )
        canary_id = canary.id
        canary_marker = canary.marker
        canary_url = canary.location_url

    print(f"      [OK] Tracer Marker:  {canary_marker}")
    print(f"      [OK] Location URL:   {canary_url}\n")

    # Step 3: Ingest Threat Intelligence Feeds
    print("[3/7] Ingesting Intelligence Feeds through Normalizer & Redaction Pipeline...")
    telemetry_items = [
        # Feed 1: Ransomware Leak Site listing
        RawItemData(
            source="ransomware_live",
            url=f"https://ransomware.live/#victim=acme.example",
            text="Victim: acme.example published by lockbit group. 850GB exfiltrated corporate records.",
            data_origin="replay",
        ),
        # Feed 2: Public GitHub Gist Credential Leak with Secret to Redact
        RawItemData(
            source="github_gist",
            url="https://gist.github.com/developer/server_backup.env",
            text="DB_HOST=prod.acme.example\nadmin_user=alice@acme.example:SuperSecretP@ssword2026!\nAWS_KEY=AKIAIOSFODNN7EXAMPLE",
            data_origin="live",
        ),
        # Feed 3: Lookalike Typosquat Certificate
        RawItemData(
            source="crt_sh",
            url="https://crt.sh/?id=987654321",
            text="Certificate Transparency entry\nDomain: acm3.example\nWatched domain: acme.example\nTag: lookalike\nlookalike domain acm3.example detected\nIssuer: Let's Encrypt",
            data_origin="live",
        ),
        # Feed 4: Canary Marker Detection (External Discovery)
        RawItemData(
            source="github_gist",
            url="https://gist.github.com/decoy/config.env",
            text=f"# Exposed config dump\nTOKEN={canary_marker}\nDB_PASS=ProductionPass123!",
            data_origin="canary",
        ),
    ]

    stored_findings = []
    with Session(engine) as session:
        for item in telemetry_items:
            res = await process_raw_item(session, item)
            if res:
                f_list = session.exec(select(Finding).where(Finding.raw_item_id == res.id)).all()
                stored_findings.extend(f_list)

    print(f"      [OK] Processed {len(telemetry_items)} external feeds.")
    print(f"      [OK] Generated {len(stored_findings)} correlation findings.\n")

    # Step 4: Verification of Privacy-by-Design Redaction
    print("[4/7] Verifying Privacy-by-Design Secret Redaction in Database...")
    with Session(engine) as session:
        leaked_item = session.exec(
            select(RawItem).where(RawItem.url == "https://gist.github.com/developer/server_backup.env")
        ).first()
        assert "SuperSecretP@ssword2026!" not in leaked_item.redacted_text
        assert "AKIAIOSFODNN7EXAMPLE" not in leaked_item.redacted_text
        print(f"      [OK] Plaintext password redacted: True")
        print(f"      [OK] Plaintext AWS key redacted:  True")
        print(f"      [OK] Redacted Evidence Sample:")
        print(f"           \"{leaked_item.redacted_text[:85]}...\"\n")

    # Step 5: Explainable Scoring & Case Management
    print("[5/7] Reviewing Explainable Scoring & Case SLA Timers...")
    with Session(engine) as session:
        cases = session.exec(select(Case)).all()
        for c in cases[:3]:
            print(f"      - Case #{c.id} [{c.severity.upper()}] - {c.title}")
            print(f"        SLA Acknowledge Due: {c.sla_ack_due.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print(f"        SLA Containment Due: {c.sla_contain_due.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # Step 6: Exposure Graph & Blast Radius
    print("\n[6/7] Computing Graph Topology & Crown-Jewel Blast Radius...")
    with Session(engine) as session:
        G = build_graph(session)
        rad = blast_radius(G, f"asset:{root_asset_id}", hops=2)
        crown_path = shortest_path_to_crown_jewel(G, f"asset:{root_asset_id}")
        print(f"      [OK] Total Graph Nodes: {len(G.nodes)}")
        print(f"      [OK] Total Graph Edges: {len(G.edges)}")
        print(f"      [OK] Perimeter Blast Radius Score: {rad}")
        if crown_path:
            print(f"      [OK] Critical Path to Crown Jewel ({crown_path['hops']} hops):")
            print(f"           {' -> '.join(crown_path['path'])}\n")

    # Step 7: Canary Latency & Audit Chain Integrity
    print("[7/7] Verifying Canary Time-to-Detect (TTD) and Audit Hash Chain...")
    with Session(engine) as session:
        canary = session.get(Canary, canary_id)
        print(f"      [OK] Canary Marker:            {canary.marker}")
        print(f"      [OK] Time to Detect (TTD):      {canary.time_to_detect_seconds}s")
        print(f"      [OK] Detected Source:          {canary.detected_source}")

        audit_res = verify_chain(session)
        print(f"      [OK] Tamper-Evident Hash Chain: {'VALID (0 Broken Links)' if audit_res['valid'] else 'COMPROMISED'}\n")

    print("=======================================================================")
    print("DEMO RUN COMPLETE: Platform is operational and ready for SOC triage!")
    print("Start the dashboard with: uvicorn app.main:app --port 8000")
    print("Open in your browser:     http://localhost:8000/dashboard")
    print("Interactive API Docs:     http://localhost:8000/docs")
    print("=======================================================================")


if __name__ == "__main__":
    asyncio.run(run_demo())
