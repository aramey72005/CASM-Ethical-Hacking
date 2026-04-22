'''
def score_risks(network):
    for host in network:
        for svc in network[host].get("services", []):
            base = 1

            match_count = len(svc.get("public_exploit_matches", []))
            base += min(match_count, 3) * 2

            service_name = str(svc.get("service", "")).lower()

            if service_name in ["http", "https"]:
                base += 2
            elif service_name == "ssh":
                base += 1
            elif service_name in ["ftp", "telnet", "smb", "microsoft-ds"]:
                base += 3
            elif service_name in ["rtsp", "rdp", "vnc"]:
                base += 2

            highest_confidence = ""
            for hit in svc.get("public_exploit_matches", []):
                confidence = str(hit.get("confidence", "")).lower()
                if confidence == "high":
                    highest_confidence = "high"
                    break
                if confidence == "medium" and highest_confidence != "high":
                    highest_confidence = "medium"
                elif confidence == "low" and highest_confidence not in ["high", "medium"]:
                    highest_confidence = "low"

            if highest_confidence == "high":
                base += 3
            elif highest_confidence == "medium":
                base += 2
            elif highest_confidence == "low":
                base += 1

            svc["risk"] = min(base, 10)

    return network
'''

def calculate_risk(service):
    if not isinstance(service, dict):
        return 0

    risk = 5

    for cve in service.get("cves", []):
        if not isinstance(cve, dict):
            continue

        cvss = cve.get("cvss", 0) or 0

        if cvss >= 9:
            risk += 10
        elif cvss >= 7:
            risk += 7
        elif cvss >= 4:
            risk += 4
        elif cvss > 0:
            risk += 2

    if service.get("public_exploit_matches"):
        risk += 5

    return min(risk, 100)


def score_risks(scan_results):
    if isinstance(scan_results, dict):
        for ip, host_data in scan_results.items():

            if isinstance(host_data, list):
                for service in host_data:
                    if not isinstance(service, dict):
                        continue
                    service["risk"] = calculate_risk(service)

            elif isinstance(host_data, dict):
                services = host_data.get("services", [])

                if isinstance(services, list):
                    for service in services:
                        if not isinstance(service, dict):
                            continue
                        service["risk"] = calculate_risk(service)

                elif "product" in host_data or "service" in host_data or "name" in host_data:
                    host_data["risk"] = calculate_risk(host_data)

        return scan_results

    if isinstance(scan_results, list):
        for service in scan_results:
            if not isinstance(service, dict):
                continue
            service["risk"] = calculate_risk(service)

    return scan_results