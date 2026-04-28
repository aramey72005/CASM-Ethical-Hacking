from scanner.nmap_scanner import run_scan
from cve_engine.cve_mapper import map_cves
from risk_scoring.scorer import score_risks
from attack_graph.graph_builder import build_graph


def run_scan_pipeline(target, scan_args="-sV"):
    # Pipeline order matters: Nmap discovers services, CVE mapping enriches
    # those services, scoring summarizes their risk, then graph_builder turns
    # the enriched scan into the node/edge format consumed by the dashboard.
    scan = run_scan(target, scan_args)
    scan = map_cves(scan)
    scan = score_risks(scan)

    graph = build_graph(scan)

    # Keep raw_scan in the response so the results/debug page can show exactly
    # what data produced the graph and risk scores.
    graph_data = {
        "nodes": [{"id": node_id, **attrs} for node_id, attrs in graph.nodes(data=True)],
        "edges": [{"from": src, "to": dst} for src, dst in graph.edges()],
        "raw_scan": scan
    }

    return graph_data
