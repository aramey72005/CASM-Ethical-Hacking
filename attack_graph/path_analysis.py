# graph_analysis.py

def find_most_critical(G):
    """
    Finds the single highest-risk node in the NetworkX graph.

    This can be used by the dashboard to highlight:
    - most dangerous host
    - most dangerous service
    - highest severity CVE
    - exploit node with highest inherited risk
    """

    # Stores the current best node found so far.
    # Format:
    # (node_id, node_data_dictionary)
    best_node = None

    # Start below any valid risk score.
    # Since risk scores are normally 0 to 10,
    # using -1 guarantees the first real node replaces it.
    max_risk = -1

    # Loop through every node in the graph.
    # G.nodes(data=True) returns:
    # node = node identifier
    # data = attributes dictionary
    for node, data in G.nodes(data=True):

        # Read the node's risk score.
        # If no risk field exists, default to 0.
        risk = data.get("risk", 0)

        # If this node has a higher risk than any previous node,
        # make it the new most critical node.
        if risk > max_risk:
            max_risk = risk
            best_node = (node, data)

    # Return the highest-risk node and its metadata.
    # Example:
    # ("192.168.1.145:8080/tcp", {...})
    return best_node