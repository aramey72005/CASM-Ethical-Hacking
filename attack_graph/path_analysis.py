def find_most_critical(graph):
    max_risk = -1
    best_node = None

    for node, data in graph.nodes(data=True):
        risk = data.get("risk", 0)

        if risk > max_risk:
            max_risk = risk
            best_node = (node, data)

    return best_node
