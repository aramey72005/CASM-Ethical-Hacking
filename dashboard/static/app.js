const graphState = {
  // The latest graph JSON from /api/graph. Keeping it here lets toolbar
  // actions redraw the graph without rerunning an Nmap/NVD scan.
  data: null,
  dataSignature: "",
  nodeDataSet: null,
  edgeDataSet: null,
  criticalPathEnabled: false,
  criticalPathMode: "risk",
  connectHostsEnabled: false,
  criticalPath: null
};
const CRITICAL_PATH_COLOR = "#0077ff";

// Applies the saved theme and updates vis-network label colors if the graph
// has already been rendered.
function setTheme(theme) {
  document.body.setAttribute("data-theme", theme);
  localStorage.setItem("theme", theme);

  let textColor = "#ffffff";
  if (theme === "light") {
    textColor = "#111111";
  } else if (theme === "hacker") {
    textColor = "#00ff66";
  }

  if (window.network) {
    window.network.setOptions({
      nodes: {
        font: { color: textColor }
      }
    });
  }
}

// Writes scan status JSON into the debug panel when that panel exists.
function setDebugText(value) {
  const debugBox = document.getElementById("scanDebug");
  if (debugBox) {
    debugBox.textContent = value;
  }
}

// Keeps debug rendering consistent for success and error responses.
function formatDebugState(data) {
  if (!data) {
    return "No debug data available.";
  }

  return JSON.stringify(data, null, 2);
}

// Converts a 0-10 risk/CVSS score into the colors shown in the legend.
function getRiskColor(score) {
  const risk = Number(score) || 0;

  if (risk >= 9) {
    return "#ff4d4d";
  }
  if (risk >= 7) {
    return "#ff8c1a";
  }
  if (risk >= 4) {
    return "#ffdf4d";
  }
  if (risk > 0) {
    return "#7bd88f";
  }
  return "#9aa0a6";
}

// Severity labels are useful for sorting, but the graph still displays the
// original NVD CVSS number so HIGH stays different from CRITICAL.
function getSeverityRank(severity) {
  const normalized = String(severity || "").toUpperCase();
  const ranks = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1
  };

  return ranks[normalized] || 0;
}

// Reads the risk value from any node shape: host, service, CVE, or exploit.
function getNodeRisk(node) {
  return Number(node?.risk_score ?? node?.risk ?? node?.cvss ?? 0) || 0;
}

// Severity mode favors category first, then uses the numeric score to break
// ties inside the same severity band.
function getNodeSeverityScore(node) {
  const risk = getNodeRisk(node);
  const rank = node?.severity ? getSeverityRank(node.severity) : getSeverityRankFromRisk(risk);

  return (rank * 10) + risk;
}

// Hosts and services do not have a direct NVD severity label, so infer their
// severity band from their score when severity-based path mode is selected.
function getSeverityRankFromRisk(risk) {
  if (risk >= 9) {
    return 4;
  }
  if (risk >= 7) {
    return 3;
  }
  if (risk >= 4) {
    return 2;
  }
  if (risk > 0) {
    return 1;
  }
  return 0;
}

// Chooses the scoring method used by the critical-path finder.
function getPathNodeScore(node) {
  if (graphState.criticalPathMode === "severity") {
    return getNodeSeverityScore(node);
  }

  return getNodeRisk(node);
}

// Edge keys are sorted because NetworkX/vis edges are undirected in this view.
function makeEdgeKey(from, to) {
  return [String(from), String(to)].sort().join("::");
}

// Starts the backend scan pipeline and refreshes the graph when it completes.
function runScan() {
  const target = document.getElementById("targetInput").value.trim() || "127.0.0.1";
  const scanButton = document.querySelector("button[onclick='runScan()']");
  const progressDiv = document.getElementById("scanProgress");

  // Disable button and show progress
  scanButton.disabled = true;
  scanButton.textContent = "Scanning...";
  progressDiv.style.display = "flex";

  setDebugText(formatDebugState({
    status: "starting",
    target,
    scan_args: "-sV",
    started_from_ui_at: new Date().toISOString()
  }));

  fetch("/api/scan", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ target, scan_args: "-sV" })
  })
    .then(async r => {
      const data = await r.json();
      if (!r.ok) {
        throw data;
      }
      return data;
    })
    .then(data => {
      console.log("Scan complete", data);
      setDebugText(formatDebugState(data));
      setTimeout(loadGraph, 300);
    })
    .catch(err => {
      console.error("Scan error:", err);
      setDebugText(formatDebugState(err));
    })
    .finally(() => {
      // Re-enable button and hide progress
      scanButton.disabled = false;
      scanButton.textContent = "Run Scan";
      progressDiv.style.display = "none";
    });
}

// Pulls the latest graph JSON from Flask and renders it into vis-network.
function loadGraph() {
  fetch("/api/graph")
    .then(r => r.json())
    .then(data => {
      console.log("GRAPH DATA:", data);
      const nextSignature = JSON.stringify({
        nodes: data?.nodes || [],
        edges: data?.edges || []
      });

      // A new scan should get a fresh layout. UI overlays should not.
      if (nextSignature !== graphState.dataSignature) {
        graphState.dataSignature = nextSignature;
        graphState.nodeDataSet = null;
        graphState.edgeDataSet = null;

        if (window.network) {
          window.network.destroy();
          window.network = null;
        }
      }

      graphState.data = data;
      renderGraph(data);
    })
    .catch(err => console.error("Graph load error:", err));
}

// Refreshes only the debug panel, which is useful while a scan is running.
function refreshDebug() {
  fetch("/api/debug")
    .then(r => r.json())
    .then(data => {
      console.log("SCAN DEBUG:", data);
      setDebugText(formatDebugState(data));
    })
    .catch(err => {
      console.error("Debug load error:", err);
      setDebugText(`Failed to load debug info: ${err}`);
    });
}

// Turns path highlighting on or off.
function toggleCriticalPath() {
  graphState.criticalPathEnabled = !graphState.criticalPathEnabled;
  renderGraph(graphState.data);
}

// Switches between pure risk-score path selection and severity-weighted path
// selection. The scan data does not change; only the frontend ranking changes.
function setCriticalPathMode(mode) {
  graphState.criticalPathMode = mode === "severity" ? "severity" : "risk";
  if (graphState.criticalPathEnabled) {
    renderGraph(graphState.data);
  }
}

// Adds or removes dashed host-to-host links that represent the scan scope.
function toggleHostLinks() {
  graphState.connectHostsEnabled = !graphState.connectHostsEnabled;
  renderGraph(graphState.data);
}

// Keeps button text, active states, and the mode dropdown aligned with state.
function updateToolbarState() {
  const pathButton = document.getElementById("criticalPathToggle");
  const hostButton = document.getElementById("hostLinksToggle");
  const modeSelect = document.getElementById("criticalPathMode");

  if (pathButton) {
    pathButton.textContent = graphState.criticalPathEnabled ? "Hide Critical Path" : "Show Critical Path";
    pathButton.classList.toggle("active", graphState.criticalPathEnabled);
  }

  if (hostButton) {
    hostButton.textContent = graphState.connectHostsEnabled ? "Hide Host Links" : "Connect Hosts";
    hostButton.classList.toggle("active", graphState.connectHostsEnabled);
  }

  if (modeSelect) {
    modeSelect.value = graphState.criticalPathMode;
  }
}

// Finds the highest scoring host -> service -> CVE path. If a service has no
// CVEs, host -> service can still win, which keeps the feature useful on sparse
// scans or while NVD rate limits are preventing CVE enrichment.
function findCriticalPath(data) {
  if (!data?.nodes?.length) {
    return null;
  }

  const nodesById = new Map(data.nodes.map(node => [String(node.id), node]));
  const neighborsById = new Map();

  // Build a small adjacency map so path finding does not depend on vis-network.
  (data.edges || []).forEach(edge => {
    const from = String(edge.from);
    const to = String(edge.to);

    if (!neighborsById.has(from)) {
      neighborsById.set(from, new Set());
    }
    if (!neighborsById.has(to)) {
      neighborsById.set(to, new Set());
    }

    neighborsById.get(from).add(to);
    neighborsById.get(to).add(from);
  });

  let bestPath = [];
  let bestScore = -Infinity

  data.nodes
    .filter(node => node.type === "service")
    .forEach(service => {
      const serviceId = String(service.id);
      const neighbors = Array.from(neighborsById.get(serviceId) || []);
      const hostIds = neighbors.filter(id => nodesById.get(id)?.type === "host");
      const cveIds = neighbors.filter(id => nodesById.get(id)?.type === "cve");

      hostIds.forEach(hostId => {
        const candidateCves = cveIds.length ? cveIds : [null];

        candidateCves.forEach(cveId => {
          const nodeIds = cveId ? [hostId, serviceId, cveId] : [hostId, serviceId];
          const score = nodeIds.reduce((sum, id) => sum + getPathNodeScore(nodesById.get(id)), 0);

            if (score > bestScore) {
              bestScore = score;
              bestPaths = [{ nodeIds, score }];
            } else if (score === bestScore) {
              bestPaths.push({ nodeIds, score });
            }
        });
      });
    });

return bestPaths.length ? bestPaths : null;
}

// Shows a compact text explanation of the currently highlighted path.
function renderCriticalPathSummary(paths, nodesById) {
  const summary = document.getElementById("criticalPathSummary");
  if (!summary) {
    return;
  }

  if (!graphState.criticalPathEnabled) {
    summary.textContent = "Critical path hidden.";
    return;
  }

  if (!paths || !paths.length) {
    summary.textContent = "No critical path found in the current graph.";
    return;
  }

  const mode = graphState.criticalPathMode === "severity" ? "severity-weighted" : "risk-score";
  const score = paths[0].score.toFixed(1);

  if (paths.length === 1) {
    const labels = paths[0].nodeIds.map(id => nodesById.get(id)?.label || id);
    summary.textContent = `${mode} path: ${labels.join(" -> ")} | total ${score}`;
    return;
  }

  summary.textContent = `${paths.length} tied ${mode} critical paths found | total ${score}`;
}

// Lists CVEs by their stable CVE name/ID. The browser tooltip keeps the short
// NVD summary available without filling the legend with long descriptions.
function renderCveLegend(data) {
  const legend = document.getElementById("cveLegend");
  if (!legend) {
    return;
  }

  const cvesByName = new Map();

  (data?.nodes || [])
    .filter(node => node.type === "cve")
    .forEach(node => {
      const name = node.cve_name || node.label || node.id;
      const existing = cvesByName.get(name);

      if (!existing || getNodeRisk(node) > getNodeRisk(existing)) {
        cvesByName.set(name, node);
      }
    });

  const cves = Array.from(cvesByName.values())
    .sort((a, b) => getNodeRisk(b) - getNodeRisk(a));

  legend.replaceChildren();

  if (!cves.length) {
    legend.textContent = "No CVEs loaded.";
    return;
  }

  cves.forEach(cve => {
    const row = document.createElement("div");
    const score = cve.cvss ?? cve.risk_score ?? 0;

    row.className = "cve-legend-row";
    row.textContent = `${cve.cve_name || cve.label || cve.id} (${score}, ${cve.severity || "UNKNOWN"})`;

    if (cve.title) {
      row.title = cve.title;
    }

    legend.appendChild(row);
  });
}

// Generates optional dashed links between discovered hosts so the scan can be
// viewed as one network. These are visual-only edges, not discovered routes.
function getHostLinkEdges(nodes) {
  const hosts = nodes.filter(node => node.type === "host");
  const edges = [];

  // Host-to-host links are a visual scan-scope aid. They do not claim that
  // Nmap proved direct lateral connectivity between those machines.
  for (let i = 0; i < hosts.length; i += 1) {
    for (let j = i + 1; j < hosts.length; j += 1) {
      edges.push({
        from: hosts[i].id,
        to: hosts[j].id,
        type: "host_link",
        physics: false
      });
    }
  }

  return edges;
}

// Builds vis-network nodes and edges from the backend JSON, then applies any
// optional UI overlays such as host links and critical-path highlighting.
function renderGraph(data) {
  const container = document.getElementById("graph");
  const infoBox = document.getElementById("info");

  updateToolbarState();
  renderCveLegend(data);

  if (!container) {
    console.error("Graph container missing");
    return;
  }

  if (!data || !data.nodes || data.nodes.length === 0) {
    container.innerHTML = "<div style='color:gray; padding:20px;'>No graph data found. Try running a scan.</div>";
    if (infoBox) {
      infoBox.textContent = "";
    }
    refreshDebug();
    return;
  }

  const nodesById = new Map(data.nodes.map(node => [String(node.id), node]));
  const criticalPaths = graphState.criticalPathEnabled ? findCriticalPath(data) : null;
  const criticalNodeIds = new Set();
  const criticalEdgeKeys = new Set();

  graphState.criticalPath = criticalPaths;
  renderCriticalPathSummary(criticalPaths, nodesById);

  if (criticalPaths) {
    criticalPaths.forEach(path => {
      path.nodeIds.forEach(id => criticalNodeIds.add(String(id)));

      for (let i = 0; i < path.nodeIds.length - 1; i += 1) {
        criticalEdgeKeys.add(makeEdgeKey(path.nodeIds[i], path.nodeIds[i + 1]));
      }
    });
  }
  const graphNodes = data.nodes.map(n => {
      let color = "#4da6ff";
      let label = n.label || n.id;
      let size = 16;

      if (n.type === "host") {
        color = getRiskColor(n.risk_score || n.risk);
        label = n.label || n.id;
        size = 22;
      } else if (n.type === "service") {
        color = getRiskColor(n.risk_score || n.risk);
        const port = n.port ? `:${n.port}` : "";
        const risk = n.risk_score ?? n.risk ?? 0;
        label = `${n.label || "service"}${port} (${risk})`;
      } else if (n.type === "exploit") {
        color = "#cc66ff";
        label = n.edb_id ? `EDB-${n.edb_id}` : (n.label || "Exploit");
      } else if (n.type === "cve") {
        color = getRiskColor(n.risk_score || n.cvss);
        const cvss = n.cvss ?? n.risk_score ?? 0;
        label = `${n.cve_name || n.label || n.id} (${cvss})`;
      }

      return {
        id: n.id,
        label,
        color: {
          background: color,
          border: criticalNodeIds.has(String(n.id)) ? CRITICAL_PATH_COLOR : color,
          highlight: {
            background: color,
            border: CRITICAL_PATH_COLOR
          },
          hover: {
            background: color,
            border: CRITICAL_PATH_COLOR
          }
        },
        borderWidth: criticalNodeIds.has(String(n.id)) ? 4 : 1,
        borderWidthSelected: 4,
        shadow: criticalNodeIds.has(String(n.id))
          ? { enabled: true, color: CRITICAL_PATH_COLOR, size: 18, x: 0, y: 0 }
          : false,
        size
      };
    });

  const graphEdges = [...(data.edges || [])];
  if (graphState.connectHostsEnabled) {
    graphEdges.push(...getHostLinkEdges(data.nodes));
  }

  const graphEdgeData = graphEdges.map(e => {
      const isCritical = criticalEdgeKeys.has(makeEdgeKey(e.from, e.to));
      const isHostLink = e.type === "host_link";

      return {
        from: e.from,
        to: e.to,
        dashes: isHostLink,
          physics: e.physics !== false,
        width: isCritical ? 5 : (isHostLink ? 2 : 1),
        color: isCritical ? CRITICAL_PATH_COLOR : (isHostLink ? "#4da6ff" : "#888")
      };
    });

  const currentTheme = localStorage.getItem("theme") || "dark";
  const fontColor = currentTheme === "light" ? "#111111" : (currentTheme === "hacker" ? "#00ff66" : "#ffffff");

  const options = {
    nodes: {
      shape: "dot",
      font: {
        color: fontColor,
        size: 14,
        face: "monospace"
      }
    },
    edges: {
      smooth: true
    },
    physics: {
      enabled: true,
      stabilization: {
        enabled: true,
        iterations: 1000
      },
      barnesHut: {
        gravitationalConstant: -2000
      }
    }
  };

  if (window.network && graphState.nodeDataSet && graphState.edgeDataSet) {
    // Overlay changes update the existing DataSets. This preserves node
    // positions instead of letting physics solve a brand-new layout.
    const nextNodeIds = new Set(graphNodes.map(node => String(node.id)));
    const staleNodeIds = graphState.nodeDataSet
      .getIds()
      .filter(id => !nextNodeIds.has(String(id)));

    if (staleNodeIds.length) {
      graphState.nodeDataSet.remove(staleNodeIds);
    }

    graphState.nodeDataSet.update(graphNodes);
    graphState.edgeDataSet.clear();
    graphState.edgeDataSet.add(graphEdgeData);
    return;
  }

  graphState.nodeDataSet = new vis.DataSet(graphNodes);
  graphState.edgeDataSet = new vis.DataSet(graphEdgeData);
  window.network = new vis.Network(container, {
    nodes: graphState.nodeDataSet,
    edges: graphState.edgeDataSet
  }, options);

  window.network.on("click", function(params) {
    if (!params.nodes.length || !infoBox) {
      return;
    }

    fetch(`/api/node?node=${encodeURIComponent(params.nodes[0])}`)
      .then(r => r.json())
      .then(node => {
        infoBox.textContent = JSON.stringify(node, null, 2);
      })
      .catch(err => {
        infoBox.textContent = `Failed to load node info: ${err}`;
      });
  });
}

window.onload = () => {
  const saved = localStorage.getItem("theme") || "dark";
  setTheme(saved);

  const sel = document.getElementById("themeSelect");
  if (sel) {
    sel.value = saved;
  }

  updateToolbarState();
  refreshDebug();
  loadGraph();
};
