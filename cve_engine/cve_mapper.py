from cve_engine.exploit_db import enrich_service_with_exploits
from cve_engine.nvd_lookup import lookup_cves



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
    # Prefer product/version from Nmap because those make NVD keyword searches
    # much more precise than using only a generic service name such as "http".
    product = service.get("product")
    version = service.get("version")
    name = service.get("service") or service.get("name")

    # Store CVEs directly on the service so risk scoring and graph building can
    # work from one enriched service object.
    service["cves"] = lookup_cves(name, product, version)

    # Temporary forced lookup used for validating graph behavior
    #service["cves"] = lookup_cves("apache", "apache http server", "2.4.49")
