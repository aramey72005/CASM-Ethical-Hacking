#Imports NetworkX which is used to creates graphs built with nodes and edges
import networkx as nx

#Takes scan result and turns it into the graph
def build_graph(data):

    #Creates a empty graph
    G = nx.Graph()

    #Loops through the hosts
    for ip, info in data.items():
        #Stars the hosts risk at 0
        host_risk = 0

        #Gets the services from the host
        services = info.get("services", [])
        #Checks if the host has a service
        if services:
            # Host risk is the highest service risk found on that host.
            host_risk = max(svc.get("risk_score", svc.get("risk", 0)) for svc in services)

        G.add_node(
            ip,
            type="host",
            label=ip,
            risk=host_risk,
            risk_score=host_risk,
            host_state=info.get("host_state", "")
        )

        #Loops through the services
        for svc in services:
            svc_node = f"{ip}:{svc['port']}/{svc.get('protocol', 'tcp')}" #Service nodes a granted a unique name 
            service_label = svc.get("service") or "unknown"
            product = svc.get("product") or ""
            version = svc.get("version") or ""

            # Service nodes keep the raw scan details so clicking a node in the
            # graph shows the same product/version data used for CVE lookup.
            G.add_node(
                svc_node,
                type="service",
                label=service_label,
                risk=svc.get("risk_score", svc.get("risk", 0)),
                risk_score=svc.get("risk_score", svc.get("risk", 0)),
                port=svc.get("port"),
                protocol=svc.get("protocol", ""),
                state=svc.get("state", ""),
                product=product,
                version=version,
                extra_info=svc.get("extra_info", ""),
                match_count=svc.get("match_count", 0),
                search_terms=svc.get("search_terms", []),
                public_exploit_matches=svc.get("public_exploit_matches", [])
            )

            #Connects node and service
            G.add_edge(ip, svc_node)

            #Loops over all CVEs
            for cve in svc.get("cves", []):
                cve_id = cve.get("cve_id", "unknown") #Gets the CVE id 

                cve_node = f"{cve_id}:{svc_node}" #Creates a unique node for the CVE

                # NVD does not provide a short marketing-style title. The CVE ID
                # is the stable vulnerability name, while title stores our short
                # trimmed NVD summary for debugging when available.
                G.add_node(
                    cve_node,
                    type="cve",
                    label=cve_id,
                    title=cve.get("title", ""), #Short description
                    cve_name=cve_id,
                    severity=cve.get("severity", "UNKNOWN"),
                    cvss=cve.get("cvss", 0),
                    risk_score=cve.get("cvss", 0)
                )
                G.add_edge(svc_node, cve_node) #Creates a relationship for the service and the CVE

            #Loops through public exploit matches for the service. Only taking the first 5 exploits
            for hit in svc.get("public_exploit_matches", [])[:5]:
                exploit_id = hit.get("edb_id") or hit.get("title") or "unknown"
                exploit_node = f"EDB:{exploit_id}:{svc_node}"
                # Exploit nodes inherit the parent service risk because they
                # represent exploit availability for that vulnerable service.
                G.add_node(
                    exploit_node,
                    type="exploit",
                    label=hit.get("title", "Exploit"),
                    risk=svc.get("risk_score", svc.get("risk", 0)),
                    risk_score=svc.get("risk_score", svc.get("risk", 0)),
                    confidence=hit.get("confidence", "low"),
                    edb_id=hit.get("edb_id", ""),
                    platform=hit.get("platform", ""),
                    exploit_type=hit.get("type", ""),
                    date=hit.get("date", ""),
                    path=hit.get("path", ""),
                    term_used=hit.get("term_used", "")
                )
                G.add_edge(svc_node, exploit_node)

    return G
