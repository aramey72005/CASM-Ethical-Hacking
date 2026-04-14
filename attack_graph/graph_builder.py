# graph_builder.py
import networkx as nx

def build_graph(data):
    G = nx.Graph()

    for ip, info in data.items():
        G.add_node(ip, type="host", risk=0)

        for svc in info.get("services", []):
            svc_node = f"{ip}:{svc['port']}"

            G.add_node(
                svc_node,
                type="service",
                label=svc.get("service", "unknown"),
                risk=svc.get("risk", 0)
            )

            G.add_edge(ip, svc_node)

    return G