# main.py
from scanner.nmap_scanner import run_scan
from cve_engine.cve_mapper import map_cves
from risk_scoring.scorer import score_risks
from attack_graph.graph_builder import build_graph

def run_scan_pipeline(target):
    scan = run_scan(target)
    scan = map_cves(scan)
    scan = score_risks(scan)
    
    # Build the NetworkX graph
    G = build_graph(scan)
    
    # Format for Vis.js
    graph_data = {
        "nodes": [{"id": n, **d} for n, d in G.nodes(data=True)],
        "edges": [{"from": u, "to": v} for u, v in G.edges()]
    }

    return graph_data # Return the formatted graph, not the raw scan