def score_risk(data):
    for ip in data:
        for svc in data[ip]["services"]:
            base = len(svc["cves"]) * 3

            if svc["service"] == "http":
                base += 2
            if svc["service"] == "ssh":
                base += 1

            svc["risk"] = base

    return data