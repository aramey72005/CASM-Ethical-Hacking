#nmap_scanner.py
import nmap

def run_scan(target):

    nm = nmap.PortScanner()
    nm.scan(target, "1-1024")

    results = {}

    for host in nm.all_hosts():
        results[host] = {"services": []}

        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:

                svc = nm[host][proto][port]

                results[host]["services"].append({
                    "port": port,
                    "service": svc.get("name", ""),
                    "version": svc.get("version", ""),
                    "cves": [],
                    "risk": 0
                })

    return results