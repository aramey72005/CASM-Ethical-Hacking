# CASM: Intelligent Attack Surface Mapper

**CASM** is a network vulnerability visualization tool built for security analysts. Rather than flooding a dashboard with every possible exploit, CASM filters and prioritizes the most relevant threats and renders them as an interactive, explorable attack graph — making risk immediately readable at a glance.

---

## 🚀 Key Features

* **Nmap-based Discovery:** Automated service and port discovery.
* **Automated Parsing:** Seamless conversion of XML scan results to structured JSON.
* **CVE Enrichment:** Integrated engine to map discovered services to known vulnerabilities.
* **Risk Scoring:** Proprietary system to calculate and prioritize threat levels.
* **Interactive Visualization:** Dynamic attack graphs powered by **Flask** and **Vis.js**.
* **Live Dashboard:** Trigger new scans and inspect nodes directly from your browser.

---

## 📂 Project Structure

```text
CASM-Ethical-Hacking/
├── main.py              # Main execution script
├── scanner/             # Nmap integration logic
├── parser/              # XML to JSON processing
├── cve_engine/          # Vulnerability enrichment
├── risk_scoring/        # Threat calculation logic
├── attack_graph/        # Graph generation scripts
├── dashboard/           # Flask web application
├── scan_results/        # Output directory for scan data
└── README.md

---
⚙️ Installation & Setup
1. System Dependencies
Ensure Nmap is installed on your host machine:

  sudo apt update && sudo apt install nmap -y

2. Python Environment

# Create and activate environment
python3 -m venv venv
source venv/bin/activate

# Install required packages
pip install -r requirements.txt

# Manual install if requirements.txt is missing
pip install flask networkx
---

▶️ How to Run
1. Run the Pipeline
  python main.py
  This will:
  
  Run an Nmap scan (Default: localhost).
  Parse and enrich results with CVE data.
  Compute risk scores and save the output to scan_results/test_results.json.

2. Launch the Dashboard
  Start the visualization server:
  
  python -m dashboard.app
  Then, navigate to: http://127.0.0.1:5000
---
🎯 Configuration & Output
Default Target: By default, CASM scans 127.0.0.1. To change the target range, modify the configuration in scanner/nmap_scanner.py.

Output Format Example
JSON
{
  "127.0.0.1": {
    "services": [
      {
        "port": 80,
        "service": "http",
        "version": "2.4.x",
        "cves": ["CVE-2021-XXXX"],
        "risk": 7
      }
    ]
  }
}
---
Disclaimer: This tool is for educational and authorized security testing purposes only.
