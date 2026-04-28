

#Calculates the risk score for the service 
#calculate_risk() uses the highest CVSS score from the service’s CVEs as the service risk score, with a fallback of 
#5.0 if exploit matches exist but no CVSS score is available.
def calculate_risk(service):

    #Handles case of input not being a dictonary
    if not isinstance(service, dict):
        return 0.0

    # For now risk_score intentionally mirrors NVD CVSS on a 0-10 scale. When
    # multiple CVEs hit one service, the highest CVSS drives the service color.
    highest_cvss = 0.0

    #Loops through all the CVEs associated with the service 
    for cve in service.get("cves", []):
        if not isinstance(cve, dict):
            continue

        # NVD scores should be numeric but in the case of one that is not or is 
        #missing it is skipped and assigned a score of 0.0
        try:
            cvss = float(cve.get("cvss", 0) or 0)
        except (TypeError, ValueError):
            cvss = 0.0

        #Keep the highest CVSS score for the service 
        highest_cvss = max(highest_cvss, cvss)

    #If the score exists it is returned as a rounded number and prevents score passing 10
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
    cves = service.get("cves", []) #Get CVE list

    if not cves:
        print(f"[DEBUG] Service {ip}:{port} {service_name} -> risk_score={risk}, cves=0")
        return

    for cve in cves:
        if not isinstance(cve, dict): #Skips invalid entries
            continue

        print(
            "[DEBUG] Vulnerability "
            f"{cve.get('cve_id', 'unknown')} on {ip}:{port} {service_name} "
            f"-> cvss={cve.get('cvss', 0)}, severity={cve.get('severity', 'UNKNOWN')}, "
            f"risk_score={risk}"
        )


def score_risks(scan_results):

    # scan_results may come in different shapes:
    # 1. Dictionary keyed by IP
    # 2. Plain list of services
    # This function supports both formats.
    if isinstance(scan_results, dict):

        # Loop through each host entry
        # ip = host address
        # host_data = services or host object
        for ip, host_data in scan_results.items():

            # CASE 1:
            # Host directly contains a list of services
            # Example:
            # { "192.168.1.10": [ {...}, {...} ] }
            if isinstance(host_data, list):

                # Loop through each discovered service
                for service in host_data:

                    # Skip malformed entries
                    if not isinstance(service, dict):
                        continue

                    # Calculate service risk using CVEs
                    risk = calculate_risk(service)

                    # Store score under both names for compatibility
                    service["risk"] = risk
                    service["risk_score"] = risk

                    # Print terminal debug output
                    debug_service_risk(ip, service)

            # CASE 2:
            # Host contains metadata + "services" list
            # Example:
            # { "192.168.1.10": { "services": [...] } }
            elif isinstance(host_data, dict):

                # Try to get the services list
                services = host_data.get("services", [])

                # If services exists and is a list
                if isinstance(services, list):

                    # Score every service inside the host object
                    for service in services:

                        # Ignore invalid entries
                        if not isinstance(service, dict):
                            continue

                        # Compute risk score
                        risk = calculate_risk(service)

                        # Save risk values
                        service["risk"] = risk
                        service["risk_score"] = risk

                        # Show debug info in terminal
                        debug_service_risk(ip, service)

                # CASE 3:
                # host_data itself is actually one service object
                # Example:
                # { "192.168.1.10": { "port":22, "service":"ssh" } }
                elif (
                    "product" in host_data
                    or "service" in host_data
                    or "name" in host_data
                ):

                    # Calculate risk directly on host_data
                    risk = calculate_risk(host_data)

                    # Save score
                    host_data["risk"] = risk
                    host_data["risk_score"] = risk

                    # Print debug output
                    debug_service_risk(ip, host_data)

        # Return updated dictionary after scoring
        return scan_results

    # CASE 4:
    # scan_results is just a list of services
    # Example:
    # [ {...}, {...} ]
    if isinstance(scan_results, list):

        # Loop through each service
        for service in scan_results:

            # Skip bad entries
            if not isinstance(service, dict):
                continue

            # Compute service risk
            risk = calculate_risk(service)

            # Save risk score
            service["risk"] = risk
            service["risk_score"] = risk

            # Use "list" since no IP key exists
            debug_service_risk("list", service)

    # Return updated list or unchanged input
    return scan_results