// app.js
function setTheme(theme) {
  document.body.setAttribute("data-theme", theme);
  localStorage.setItem("theme", theme);

  // Determine the correct text color based on the theme
  let textColor = "#ffffff"; // Default for Dark/Hacker
  if (theme === "light") {
    textColor = "#111111"; // Dark text for Light theme
  }

  // Update the network font color if it has been initialized
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
    body: JSON.stringify({target})
  })
  .then(r => r.json())
  .then(() => {
    console.log("Scan complete → loading graph");
    setTimeout(loadGraph, 300); // IMPORTANT delay
  });
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

  if (!container) {
    console.error("Graph container missing!");
    return;
  }

  if (!data || !data.nodes || !data.edges || data.nodes.length === 0) {
    container.innerHTML = "<div style='color:gray; padding:20px;'>No graph data found. Try running a scan.</div>";
    return;
  }

  // 1. Prepare Data
  const nodes = new vis.DataSet(
    data.nodes.map(n => ({
      id: n.id,
      label: n.type === "host" ? n.id : `${n.label} (${n.id.split(':')[1]})`,
      color: n.type === "host" ? "#00ff99" : (n.risk >= 7 ? "#ff4d4d" : "#4da6ff")
    }))
  );

  const edges = new vis.DataSet(
    data.edges.map(e => ({
      from: e.from,
      to: e.to
    }))
  );

  // 2. Determine Theme Color (MUST BE BEFORE OPTIONS)
  const currentTheme = localStorage.getItem("theme") || "dark";
  const fontColor = currentTheme === "light" ? "#111111" : "#ffffff";

  // 3. Define Options
  const options = {
    nodes: {
      shape: "dot",
      size: 16,
      font: { 
        color: fontColor,
        size: 14,
        face: 'monospace' 
      }
    },
    physics: {
      enabled: true,
      barnesHut: {
        gravitationalConstant: -2000
      }
    }
  };

  // 4. Initialize Network (Now 'options' is defined)
  window.network = new vis.Network(container, { nodes, edges }, options);

  console.log("Graph rendered successfully");
}

window.onload = () => {
  const saved = localStorage.getItem("theme") || "dark";
  setTheme(saved);

  const sel = document.getElementById("themeSelect");
  if (sel) sel.value = saved;

  loadGraph();
};