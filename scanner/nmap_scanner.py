import nmap
from scanner.ip_parser import normalize_target_spec


def run_scan(target, scan_args="-sV"):
    # Normalize user input before handing it to Nmap so CIDR ranges, single IPs,
    # hostnames, and comma-separated targets are handled consistently.
    target = normalize_target_spec(target)
    nm = nmap.PortScanner()

    # scan_args defaults to service/version detection because product and
    # version fields are what make the later NVD lookup specific enough.
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

                # This service dictionary is the shared record that each later
                # pipeline stage enriches with CVEs, exploit matches, and risk.
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
