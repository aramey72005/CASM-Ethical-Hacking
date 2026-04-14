import networkx as nx

def build_graph(data):
    G = nx.Graph()

    for ip in data:
        G.add_node(ip, type="host")

        for svc in data[ip]["services"]:
            node = f"{ip}:{svc['port']}"

            G.add_node(node,
                       service=svc["service"],
                       risk=svc["risk"])

            G.add_edge(ip, node)

    return G