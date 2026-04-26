from scanner.nmap_scanner import run_scan
from cve_engine.cve_mapper import map_cves
from risk_scoring.scorer import score_risks
from attack_graph.graph_builder import build_graph


def run_scan_pipeline(target, scan_args="-sV"):
    scan = run_scan(target, scan_args)
    scan = map_cves(scan)
    scan = score_risks(scan)

    graph = build_graph(scan)

    graph_data = {
        "nodes": [{"id": node_id, **attrs} for node_id, attrs in graph.nodes(data=True)],
        "edges": [{"from": src, "to": dst} for src, dst in graph.edges()],
        "raw_scan": scan
    }

    return graph_data
