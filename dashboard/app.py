#app.py
from flask import Flask, render_template, jsonify, request
from main import run_scan_pipeline

app = Flask(__name__, template_folder="templates", static_folder="static")

LATEST_RESULTS = {}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/results")
def results():
    return render_template("results.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    global LATEST_RESULTS

    data = request.get_json()
    target = data.get("target", "127.0.0.1")

    LATEST_RESULTS = run_scan_pipeline(target)

    return jsonify({"status": "scan complete"})

@app.route("/api/graph")
def graph():
    return jsonify(LATEST_RESULTS)

if __name__ == "__main__":
    app.run(debug=True)