def enrich_with_cves(data):
    for ip in data:
        for svc in data[ip]["services"]:
            if svc["service"] == "http":
                svc["cves"] = ["CVE-2025-XXXX1", "CVE-2025-XXXX2"]
            elif svc["service"] == "ssh":
                svc["cves"] = ["CVE-2024-XXXX1"]
            else:
                svc["cves"] = []

    return data