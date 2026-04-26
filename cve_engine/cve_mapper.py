from cve_engine.exploit_db import enrich_service_with_exploits
from cve_engine.nvd_lookup import lookup_cves

'''
Older version of the CVE mapping flow.
Kept here for reference while testing different pipeline structures.

def map_cves(network):
    for host in network:
        for svc in network[host].get("services", []):
            if str(svc.get("state", "open")).lower() == "open":
                enrich_service_with_exploits(svc)
            else:
                svc["search_terms"] = []
                svc["public_exploit_matches"] = []
                svc["match_count"] = 0
                svc["cves"] = []

    return network
'''


def map_cves(scan_results):
    """
    Main CVE mapping stage.

    This function walks through scan output, handles different possible
    data layouts, and sends each valid service into the CVE enrichment step.
    """

    # Handle scan results when they come in as a dictionary
    if isinstance(scan_results, dict):
        for ip, host_data in scan_results.items():

            # Case: host data is already a list of services
            if isinstance(host_data, list):
                for service in host_data:
                    if not isinstance(service, dict):
                        continue
                    add_cves(service)

            # Case: host data is a dictionary that may contain services
            elif isinstance(host_data, dict):
                services = host_data.get("services", [])

                # Standard case: "services" is a list
                if isinstance(services, list):
                    for service in services:
                        if not isinstance(service, dict):
                            continue
                        add_cves(service)

                # Fallback case: host_data itself looks like a service record
                elif "product" in host_data or "service" in host_data or "name" in host_data:
                    add_cves(host_data)

        return scan_results

    # Handle scan results when they come in directly as a list of services
    if isinstance(scan_results, list):
        for service in scan_results:
            if not isinstance(service, dict):
                continue
            add_cves(service)
        return scan_results

    # If the structure is unexpected, return it unchanged
    return scan_results

'''
Real lookup version.
Kept commented so test mode can be used without removing the production logic.
'''

def add_cves(service):
    product = service.get("product")
    version = service.get("version")
    name = service.get("service") or service.get("name")

    # Real CVE lookup against NVD
    service["cves"] = lookup_cves(name, product, version)

    # Temporary forced lookup used for validating graph behavior
    #service["cves"] = lookup_cves("apache", "apache http server", "2.4.49")
'''
def add_cves(service):
    service["cves"] = [
        {
            "cve_id": "CVE-1999-1122",
            "cvss": 4.6,
            "severity": "MEDIUM",
            "title": "Vulnerability in restore in SunOS 4.0.3 and earlier allows local users to gain privileges."
        }
    ]
    '''

'''
def add_cves(service):
    """
    Test CVE injection stage.

    Right now this uses simulated CVEs so the rest of the system
    can be tested easily, especially graph coloring and severity handling.
    """

    # Simulated CVEs used to test multiple severity levels in the graph
    service["cves"] = [
        {
            "cve_id": "CVE-CRITICAL-TEST",
            "cvss": 9.8,
            "severity": "CRITICAL"
        },
        {
            "cve_id": "CVE-HIGH-TEST",
            "cvss": 7.5,
            "severity": "HIGH"
        },
        {
            "cve_id": "CVE-MEDIUM-TEST",
            "cvss": 5.0,
            "severity": "MEDIUM"
        },
        {
            "cve_id": "CVE-LOW-TEST",
            "cvss": 2.5,
            "severity": "LOW"
        }
    ]
'''