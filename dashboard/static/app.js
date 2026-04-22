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

function runScan() {
  const target = document.getElementById("targetInput").value || "127.0.0.1";

  fetch("/api/scan", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ target, scan_args: "-sV" })
  })
    .then(r => r.json())
    .then(data => {
      console.log("Scan complete", data);
      setTimeout(loadGraph, 300);
    })
    .catch(err => console.error("Scan error:", err));
}

function loadGraph() {
  fetch("/api/graph")
    .then(r => r.json())
    .then(data => {
      console.log("GRAPH DATA:", data);
      renderGraph(data);
    })
    .catch(err => console.error("Graph load error:", err));
}

function renderGraph(data) {
  const container = document.getElementById("graph");
  const infoBox = document.getElementById("info");

  if (!container) {
    console.error("Graph container missing");
    return;
  }

  if (!data || !data.nodes || data.nodes.length === 0) {
    container.innerHTML = "<div style='color:gray; padding:20px;'>No graph data found. Try running a scan.</div>";
    if (infoBox) {
      infoBox.textContent = "";
    }
    return;
  }

  const nodes = new vis.DataSet(
    data.nodes.map(n => {
      let color = "#4da6ff";
      let label = n.label || n.id;

      if (n.type === "host") {
        color = "#00ff99";
        label = n.label || n.id;
      } else if (n.type === "service") {
        if ((n.risk || 0) >= 7) {
          color = "#ff4d4d";
        } else if ((n.risk || 0) >= 4) {
          color = "#ffb84d";
        }
        const port = n.port ? `:${n.port}` : "";
        label = `${n.label || 'service'}${port}`;
      } else if (n.type === "exploit") {
        color = "#cc66ff";
        label = n.edb_id ? `EDB-${n.edb_id}` : (n.label || "Exploit");
      } else if (n.type === "cve") {
        if (n.severity === "CRITICAL"){
          color = "red";
        } else if (n.severity === "HIGH"){
          color = "orange";
        } else if (n.severity === "MEDIUM"){
          color = "yellow";
        } else {
          color = "gray";
        }
        label = n.label || n.id;
      }

      return {
        id: n.id,
        label,
        color
      };
    })
  );

  const edges = new vis.DataSet(
    (data.edges || []).map(e => ({ from: e.from, to: e.to }))
  );

  const currentTheme = localStorage.getItem("theme") || "dark";
  const fontColor = currentTheme === "light" ? "#111111" : (currentTheme === "hacker" ? "#00ff66" : "#ffffff");

  const options = {
    nodes: {
      shape: "dot",
      size: 16,
      font: {
        color: fontColor,
        size: 14,
        face: "monospace"
      }
    },
    edges: {
      color: "#888"
    },
    physics: {
      enabled: true,
      barnesHut: {
        gravitationalConstant: -2000
      }
    }
  };

  window.network = new vis.Network(container, { nodes, edges }, options);

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

  loadGraph();
};
