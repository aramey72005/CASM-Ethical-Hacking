#graph_analysis.py
def find_most_critical(G):
    """
    Find highest risk node in NetworkX graph
    """

    best_node = None
    max_risk = -1

    for node, data in G.nodes(data=True):
        risk = data.get("risk", 0)

        if risk > max_risk:
            max_risk = risk
            best_node = (node, data)

    return best_node