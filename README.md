# CASM: Intelligent Attack Surface Mapper

CASM is a network vulnerability visualization tool built for security analysts. This version uses Nmap for service discovery, enriches open services with public Exploit-DB matches via `searchsploit`, scores service risk, and renders the findings as an interactive attack graph.

## What changed

- `scanner/nmap_scanner.py` now collects richer service details including protocol, state, product, version, extra info, and CPE.
- `cve_engine/exploit_db.py` now runs `searchsploit --json` using product/version/service fallback terms.
- `cve_engine/cve_mapper.py` enriches each open service with public exploit matches.
- `risk_scoring/scorer.py` uses exploit match count and confidence to raise service risk.
- `attack_graph/graph_builder.py` adds exploit nodes connected to service nodes.
- `dashboard/app.py` exposes `/api/node` so the UI can inspect selected nodes.
- `dashboard/static/app.js` and `dashboard/templates/index.html` render the graph correctly and show node details.

## Requirements

Install the system tools first:

```bash
sudo apt update
sudo apt install nmap exploitdb -y
```

Then create a virtual environment and install Python dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run the dashboard

From the project root:

```bash
python3 -m dashboard.app
```

Open `http://127.0.0.1:5000` and enter a target like:

- `127.0.0.1`
- `192.168.1.10`
- `192.168.1.0/24`

## Notes

- A service with no SearchSploit result is **not** automatically safe. It only means no public Exploit-DB match was found for the generated terms.
- Exact product/version matches are treated as higher confidence than protocol-only matches.
- This tool is for authorized testing and educational use only.
