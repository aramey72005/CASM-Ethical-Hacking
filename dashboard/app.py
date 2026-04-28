from datetime import datetime, timezone
import traceback

from flask import Flask, jsonify, render_template, request
from main import run_scan_pipeline

app = Flask(__name__, template_folder="templates", static_folder="static")

# The app keeps the newest scan in memory so /api/graph, /api/node, and the
# results page can read it without a database. Restarting Flask clears it.
LATEST_RESULTS = {"nodes": [], "edges": [], "raw_scan": {}}
SCAN_DEBUG = {
    "status": "idle",
    "target": None,
    "scan_args": None,
    "started_at": None,
    "finished_at": None,
    "duration_seconds": None,
    "node_count": 0,
    "edge_count": 0,
    "host_count": 0,
    "hosts": [],
    "error": None,
    "traceback": None
}


def iso_now():
    return datetime.now(timezone.utc).isoformat()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/results")
def results():
    return render_template("results.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    global LATEST_RESULTS, SCAN_DEBUG

    # The frontend posts target/scan_args as JSON. Defaults keep the app usable
    # if a request is missing either field.
    data = request.get_json(silent=True) or {}
    target = data.get("target", "127.0.0.1")
    scan_args = data.get("scan_args", "-sV")
    started_at = datetime.now(timezone.utc)

    SCAN_DEBUG = {
        "status": "running",
        "target": target,
        "scan_args": scan_args,
        "started_at": started_at.isoformat(),
        "finished_at": None,
        "duration_seconds": None,
        "node_count": 0,
        "edge_count": 0,
        "host_count": 0,
        "hosts": [],
        "error": None,
        "traceback": None
    }

    try:
        # This is the expensive path: Nmap scan, NVD enrichment, risk scoring,
        # and graph construction all run before the response returns.
        LATEST_RESULTS = run_scan_pipeline(target, scan_args)
        raw_scan = LATEST_RESULTS.get("raw_scan", {})
        finished_at = datetime.now(timezone.utc)

        SCAN_DEBUG = {
            "status": "complete",
            "target": target,
            "scan_args": scan_args,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
            "node_count": len(LATEST_RESULTS.get("nodes", [])),
            "edge_count": len(LATEST_RESULTS.get("edges", [])),
            "host_count": len(raw_scan),
            "hosts": sorted(raw_scan.keys()),
            "error": None,
            "traceback": None
        }

        return jsonify(SCAN_DEBUG)
    except Exception as exc:
        # Return the traceback through /api/debug so UI testing can see backend
        # failures without needing to watch the terminal.
        finished_at = datetime.now(timezone.utc)
        error_message = str(exc) or exc.__class__.__name__
        SCAN_DEBUG = {
            "status": "error",
            "target": target,
            "scan_args": scan_args,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
            "node_count": len(LATEST_RESULTS.get("nodes", [])),
            "edge_count": len(LATEST_RESULTS.get("edges", [])),
            "host_count": 0,
            "hosts": [],
            "error": error_message,
            "traceback": traceback.format_exc()
        }
        return jsonify(SCAN_DEBUG), 500


@app.route("/api/graph")
def graph():
    # The graph endpoint is intentionally read-only and cheap; it simply returns
    # the last successful pipeline output.
    return jsonify(LATEST_RESULTS)


@app.route("/api/debug")
def debug():
    return jsonify({
        **SCAN_DEBUG,
        "server_time": iso_now()
    })


@app.route("/api/node")
def node():
    node_id = request.args.get("node", "")

    # Node lookup powers the "Selected Node" panel in the graph UI.
    for node in LATEST_RESULTS.get("nodes", []):
        if str(node.get("id")) == node_id:
            return jsonify(node)

    return jsonify({"error": "node not found"}), 404


if __name__ == "__main__":
    app.run(debug=True)
