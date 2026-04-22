import networkx as nx


def build_graph(data):
    G = nx.Graph()

    for ip, info in data.items():
        host_risk = 0
        services = info.get("services", [])
        if services:
            host_risk = max(svc.get("risk", 0) for svc in services)

        G.add_node(
            ip,
            type="host",
            label=ip,
            risk=host_risk,
            host_state=info.get("host_state", "")
        )

        for svc in services:
            svc_node = f"{ip}:{svc['port']}/{svc.get('protocol', 'tcp')}"
            service_label = svc.get("service") or "unknown"
            product = svc.get("product") or ""
            version = svc.get("version") or ""

            G.add_node(
                svc_node,
                type="service",
                label=service_label,
                risk=svc.get("risk", 0),
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
            G.add_edge(ip, svc_node)

            for cve in svc.get("cves", []):
                cve_id = cve.get("cve_id", "unknown")

                cve_node = f"{cve_id}:{svc_node}"

                G.add_node(
                    cve_node,
                    type="cve",
                    label = cve_id,
                    severity = cve.get("severity", "UNKNOWN"),
                    cvss = cve.get("cvss",0)
                )
                G.add_edge(svc_node, cve_node)

            for hit in svc.get("public_exploit_matches", [])[:5]:
                exploit_id = hit.get("edb_id") or hit.get("title") or "unknown"
                exploit_node = f"EDB:{exploit_id}:{svc_node}"
                G.add_node(
                    exploit_node,
                    type="exploit",
                    label=hit.get("title", "Exploit"),
                    risk=svc.get("risk", 0),
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
