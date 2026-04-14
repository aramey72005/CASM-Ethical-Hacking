#scorer.py
def score_risks(network):

    for host in network:
        for svc in network[host]["services"]:

            base = 1

            cve_count = len(svc.get("cves", []))
            base += cve_count * 2

            if svc["service"] in ["http", "https"]:
                base += 2
            elif svc["service"] == "ssh":
                base += 1
            elif svc["service"] in ["ftp", "telnet"]:
                base += 3

            svc["risk"] = min(base, 10)

    return network