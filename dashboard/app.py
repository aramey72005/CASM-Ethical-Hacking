from flask import Flask, jsonify, render_template, request
from main import run_scan_pipeline

app = Flask(__name__, template_folder="templates", static_folder="static")

LATEST_RESULTS = {"nodes": [], "edges": [], "raw_scan": {}}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/results")
def results():
    return render_template("results.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    global LATEST_RESULTS

    data = request.get_json(silent=True) or {}
    target = data.get("target", "127.0.0.1")
    scan_args = data.get("scan_args", "-sV")

    LATEST_RESULTS = run_scan_pipeline(target, scan_args)

    return jsonify({
        "status": "scan complete",
        "node_count": len(LATEST_RESULTS.get("nodes", [])),
        "edge_count": len(LATEST_RESULTS.get("edges", []))
    })


@app.route("/api/graph")
def graph():
    return jsonify(LATEST_RESULTS)


@app.route("/api/node")
def node():
    node_id = request.args.get("node", "")

    for node in LATEST_RESULTS.get("nodes", []):
        if str(node.get("id")) == node_id:
            return jsonify(node)

    return jsonify({"error": "node not found"}), 404


if __name__ == "__main__":
    app.run(debug=True)
