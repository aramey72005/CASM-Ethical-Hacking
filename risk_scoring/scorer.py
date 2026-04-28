

def calculate_risk(service):
    if not isinstance(service, dict):
        return 0.0

    # For now risk_score intentionally mirrors NVD CVSS on a 0-10 scale. When
    # multiple CVEs hit one service, the highest CVSS drives the service color.
    highest_cvss = 0.0

    for cve in service.get("cves", []):
        if not isinstance(cve, dict):
            continue

        # NVD scores should be numeric, but defensive parsing keeps malformed
        # or missing data from breaking the whole scan pipeline.
        try:
            cvss = float(cve.get("cvss", 0) or 0)
        except (TypeError, ValueError):
            cvss = 0.0

        highest_cvss = max(highest_cvss, cvss)

    if highest_cvss:
        return round(min(highest_cvss, 10.0), 1)

    # If exploit enrichment is re-enabled but no NVD CVSS is found, give the
    # service a visible medium fallback instead of treating it as zero risk.
    if service.get("public_exploit_matches"):
        return 5.0

    return 0.0


def debug_service_risk(ip, service):
    # Terminal logging mirrors the UI table so scan results can be verified
    # without opening the browser.
    service_name = service.get("service") or service.get("name") or "unknown"
    port = service.get("port", "unknown")
    risk = service.get("risk_score", service.get("risk", 0))
    cves = service.get("cves", [])

    if not cves:
        print(f"[DEBUG] Service {ip}:{port} {service_name} -> risk_score={risk}, cves=0")
        return

    for cve in cves:
        if not isinstance(cve, dict):
            continue

        print(
            "[DEBUG] Vulnerability "
            f"{cve.get('cve_id', 'unknown')} on {ip}:{port} {service_name} "
            f"-> cvss={cve.get('cvss', 0)}, severity={cve.get('severity', 'UNKNOWN')}, "
            f"risk_score={risk}"
        )


def score_risks(scan_results):
    # The scanner/tests may hand this function either host-keyed dictionaries
    # or plain service lists, so keep the traversal tolerant of both shapes.
    if isinstance(scan_results, dict):
        for ip, host_data in scan_results.items():

            if isinstance(host_data, list):
                for service in host_data:
                    if not isinstance(service, dict):
                        continue
                    risk = calculate_risk(service)
                    service["risk"] = risk
                    service["risk_score"] = risk
                    debug_service_risk(ip, service)

            elif isinstance(host_data, dict):
                services = host_data.get("services", [])

                if isinstance(services, list):
                    for service in services:
                        if not isinstance(service, dict):
                            continue
                        risk = calculate_risk(service)
                        service["risk"] = risk
                        service["risk_score"] = risk
                        debug_service_risk(ip, service)

                elif "product" in host_data or "service" in host_data or "name" in host_data:
                    risk = calculate_risk(host_data)
                    host_data["risk"] = risk
                    host_data["risk_score"] = risk
                    debug_service_risk(ip, host_data)

        return scan_results

    if isinstance(scan_results, list):
        for service in scan_results:
            if not isinstance(service, dict):
                continue
            risk = calculate_risk(service)
            service["risk"] = risk
            service["risk_score"] = risk
            debug_service_risk("list", service)

    return scan_results
