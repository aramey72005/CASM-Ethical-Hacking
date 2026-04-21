def map_cves(network):
    # Example vulnerability database (in real use, query a real DB or API)
    vuln_db = {
        "CVE-DEMO-HTTP-001": {
            "cve": "CVE-DEMO-HTTP-001",
            "severity": 8.5,
            "exploitable": True,
            "description": "Demo HTTP vulnerability allowing remote code execution."
        },
        "CVE-DEMO-SSH-001": {
            "cve": "CVE-DEMO-SSH-001",
            "severity": 9.0,
            "exploitable": True,
            "description": "Demo SSH vulnerability allowing privilege escalation."
        }
    }

    for host in network:
        for svc in network[host]["services"]:
            vulnerabilities = []
            if svc["service"] == "http":
                cves = ["CVE-DEMO-HTTP-001"]
            elif svc["service"] == "ssh":
                cves = ["CVE-DEMO-SSH-001"]
            else:
                cves = []
            for cve in cves:
                vuln = vuln_db.get(cve, {"cve": cve, "severity": 5.0, "exploitable": False, "description": "Unknown vulnerability."})
                vulnerabilities.append(vuln)
            svc["cves"] = cves
            svc["vulnerabilities"] = vulnerabilities
    return network