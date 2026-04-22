import nmap


def run_scan(target, scan_args="-sV"):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments=scan_args)

    results = {}

    for host in nm.all_hosts():
        results[host] = {
            "host_state": nm[host].state(),
            "services": []
        }

        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                svc = nm[host][proto][port]

                results[host]["services"].append({
                    "port": port,
                    "protocol": proto,
                    "state": svc.get("state", ""),
                    "service": svc.get("name", ""),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "extra_info": svc.get("extrainfo", ""),
                    "cpe": svc.get("cpe", ""),
                    "search_terms": [],
                    "cves": [],
                    "public_exploit_matches": [],
                    "match_count": 0,
                    "risk": 0
                })

    return results
