import json

from scanner.nmap_scanner import run_scan
from parser.parse_results import parse_nmap
from cve_engine.cve_mapper import enrich_with_cves
from risk_scoring.scorer import score_risk
from attack_graph.graph_builder import build_graph
from attack_graph.path_analysis import find_most_critical

xml_file = run_scan("127.0.0.1")

data = parse_nmap(xml_file)
data = enrich_with_cves(data)
data = score_risk(data)

with open("scan_results/test_results.json", "w") as f:
    json.dump(data, f, indent=2)

G = build_graph(data)
critical = find_most_critical(G)

print("\n=== RESULTS ===")
print(data)

print("\n=== MOST CRITICAL ===")
print(critical)