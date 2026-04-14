import xml.etree.ElementTree as ET

def parse_nmap(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    results = {}

    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None:
            continue

        ip = addr.get("addr")
        results[ip] = {"services": []}

        for port in host.findall(".//port"):
            portid = port.get("portid")

            service = port.find("service")
            name = service.get("name") if service is not None else "unknown"
            version = service.get("version") if service is not None else "unknown"

            results[ip]["services"].append({
                "port": int(portid),
                "service": name,
                "version": version,
                "cves": [],
                "risk": 0
            })

    return results