from flask import Flask, jsonify, render_template, request
import json

from attack_graph.graph_builder import build_graph
from attack_graph.path_analysis import find_most_critical

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/graph")
def graph():
    with open("scan_results/test_results.json", "r") as f:
        data = json.load(f)

    G = build_graph(data)

    nodes = []
    edges = []

    for n, attr in G.nodes(data=True):
        nodes.append({
            "id": n,
            "label": n,
            "risk": attr.get("risk", 0)
        })

    for a, b in G.edges():
        edges.append({"from": a, "to": b})

    return jsonify({"nodes": nodes, "edges": edges})


@app.route("/api/node")
def node():
    target = request.args.get("node")

    with open("scan_results/test_results.json") as f:
        data = json.load(f)

    for ip in data:
        for svc in data[ip]["services"]:
            if f"{ip}:{svc['port']}" == target:
                return jsonify(svc)

    return jsonify({})


@app.route("/api/scan")
def scan():
    from scanner.nmap_scanner import run_scan
    from parser.parse_results import parse_nmap
    from cve_engine.cve_mapper import enrich_with_cves
    from risk_scoring.scorer import score_risk
    import json

    xml = run_scan("127.0.0.1")
    data = parse_nmap(xml)
    data = enrich_with_cves(data)
    data = score_risk(data)

    with open("scan_results/test_results.json", "w") as f:
        json.dump(data, f, indent=2)

    return {"status": "done"}


if __name__ == "__main__":
    app.run(debug=True)