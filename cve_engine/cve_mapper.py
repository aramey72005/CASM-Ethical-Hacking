def map_cves(network):

    for host in network:
        for svc in network[host]["services"]:

            if svc["service"] == "http":
                svc["cves"] = ["CVE-DEMO-HTTP-001"]

            elif svc["service"] == "ssh":
                svc["cves"] = ["CVE-DEMO-SSH-001"]

            else:
                svc["cves"] = []

    return network