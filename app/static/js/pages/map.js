import { get, post, patch, del, ApiError } from "../api.js";
import { h, clear, toast, typeBadge, statusDot, TYPE_LABELS } from "../util.js";

const PALETTE = {
  router: "#2563eb",
  switch: "#0891b2",
  ap: "#7c3aed",
  server: "#475569",
  pc: "#059669",
  phone: "#db2777",
  printer: "#ea580c",
  iot: "#ca8a04",
  camera: "#dc2626",
  nas: "#0d9488",
  vm: "#6366f1",
  unknown: "#94a3b8",
};

const EDGE_STYLES = {
  gateway: { color: "#64748b", width: 1.5, dashes: false },
  route: { color: "#2563eb", width: 1, dashes: [8, 6] },
  "host-of": { color: "#7c3aed", width: 1, dashes: [2, 5] },
  manual: { color: "#f59e0b", width: 3, dashes: false },
};

function loadVis() {
  if (window.vis) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const existing = document.querySelector('script[src="vendor/vis-network.min.js"]');
    if (existing) {
      existing.addEventListener("load", () => resolve());
      existing.addEventListener("error", () => reject(new Error("Failed to load vis-network")));
      return;
    }
    const script = document.createElement("script");
    script.src = "vendor/vis-network.min.js";
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Failed to load vis-network"));
    document.head.appendChild(script);
  });
}

function edgeTitle(edge) {
  const kind = edge.kind || "unknown";
  const source = edge.source || "";
  const conf = edge.confidence != null ? `${Math.round(edge.confidence * 100)}%` : "";
  return [kind, source, conf].filter(Boolean).join(" · ");
}

function nodeColor(type) {
  return PALETTE[type] || PALETTE.unknown;
}

function buildNodeData(node) {
  const color = nodeColor(node.type);
  const label = node.label && node.label !== node.ip ? `${node.label}\n${node.ip}` : node.ip;
  const data = {
    id: node.id,
    label,
    shape: "dot",
    size: 18,
    color: { background: color, border: color },
    opacity: node.online ? 1 : 0.4,
    hidden: false,
  };
  if (node.pos_x != null && node.pos_y != null) {
    data.x = node.pos_x;
    data.y = node.pos_y;
  }
  return data;
}

function buildEdgeData(edge) {
  const style = EDGE_STYLES[edge.kind] || EDGE_STYLES.gateway;
  return {
    id: edge.id,
    from: edge.from,
    to: edge.to,
    color: style.color,
    width: style.width,
    dashes: style.dashes,
    arrows: "to",
    smooth: { type: "continuous" },
    title: edgeTitle(edge),
    hidden: false,
  };
}

function applyFilters(nodesDS, edgesDS, nodes, edges, search, typeFilter, statusFilter) {
  const q = search.toLowerCase();
  const hiddenNodes = new Set();
  for (const node of nodes) {
    let hidden = false;
    if (q) {
      const label = (node.label || "").toLowerCase();
      const ip = (node.ip || "").toLowerCase();
      const mac = (node.mac || "").toLowerCase();
      const vendor = (node.vendor || "").toLowerCase();
      if (!label.includes(q) && !ip.includes(q) && !mac.includes(q) && !vendor.includes(q)) {
        hidden = true;
      }
    }
    if (typeFilter !== "All" && node.type !== typeFilter) hidden = true;
    if (statusFilter === "Online" && !node.online) hidden = true;
    if (statusFilter === "Offline" && node.online) hidden = true;
    if (hidden) hiddenNodes.add(node.id);
  }
  nodesDS.update(nodes.map((node) => ({ id: node.id, hidden: hiddenNodes.has(node.id) })));
  edgesDS.update(
    edges.map((edge) => ({
      id: edge.id,
      hidden: hiddenNodes.has(edge.from) || hiddenNodes.has(edge.to),
    }))
  );
}

export async function render(container, params) {
  await loadVis();

  const toolbar = h("div", { class: "toolbar" });
  const searchInput = h("input", { type: "text", placeholder: "Search label, IP, MAC, vendor" });
  const typeSelect = h("select", { class: "type-filter" });
  typeSelect.appendChild(h("option", { value: "All" }, "All"));
  for (const [key, label] of Object.entries(TYPE_LABELS)) {
    typeSelect.appendChild(h("option", { value: key }, label));
  }
  const statusSelect = h("select", { class: "status-filter" });
  statusSelect.appendChild(h("option", { value: "All" }, "All"));
  statusSelect.appendChild(h("option", { value: "Online" }, "Online"));
  statusSelect.appendChild(h("option", { value: "Offline" }, "Offline"));

  const addLinkBtn = h("button", { class: "btn" }, "Add link");
  const deleteLinkBtn = h("button", { class: "btn danger" }, "Delete link");
  deleteLinkBtn.disabled = true;
  const resetBtn = h("button", { class: "btn" }, "Reset layout");
  const exportBtn = h("button", { class: "btn" }, "Export PNG");

  const legend = h("div", { class: "legend" });
  const legendItems = [
    { kind: "gateway", label: "Gateway" },
    { kind: "route", label: "Route" },
    { kind: "host-of", label: "Host-of" },
    { kind: "manual", label: "Manual" },
  ];
  for (const item of legendItems) {
    const swatch = h("span", { class: "legend-swatch" });
    swatch.style.backgroundColor = EDGE_STYLES[item.kind].color;
    legend.appendChild(h("div", { class: "legend-item" }, swatch, h("span", {}, item.label)));
  }

  toolbar.appendChild(searchInput);
  toolbar.appendChild(typeSelect);
  toolbar.appendChild(statusSelect);
  toolbar.appendChild(addLinkBtn);
  toolbar.appendChild(deleteLinkBtn);
  toolbar.appendChild(resetBtn);
  toolbar.appendChild(exportBtn);
  toolbar.appendChild(legend);

  const mapWrap = h("div", { class: "map-wrap" });
  const canvasEl = h("div", { id: "map-canvas" });
  const panel = h("aside", { class: "map-panel" });
  mapWrap.appendChild(canvasEl);
  mapWrap.appendChild(panel);

  container.appendChild(toolbar);
  container.appendChild(mapWrap);

  const nodesDS = new vis.DataSet();
  const edgesDS = new vis.DataSet();

  let destroyed = false;

  const options = {
    nodes: {
      shape: "dot",
      size: 18,
      font: { size: 12 },
    },
    edges: {
      arrows: "to",
      smooth: { type: "continuous" },
    },
    physics: {
      enabled: true,
      barnesHut: {
        gravitationalConstant: -3000,
        centralGravity: 0.3,
        springLength: 95,
        springConstant: 0.04,
        damping: 0.09,
      },
      stabilization: { iterations: 200 },
    },
    manipulation: {
      enabled: false,
      addEdge: (data, callback) => {
        if (destroyed) return;
        post("/api/relations", { src_id: data.from, dst_id: data.to })
          .then(() => {
            if (destroyed) return;
            toast("Link added");
            callback(null);
            reload();
          })
          .catch((err) => {
            if (destroyed) return;
            toast(err.message || "Failed to add link");
          })
          .finally(() => {
            if (destroyed) return;
            network.disableEditMode();
            addLinkBtn.classList.remove("active");
          });
      },
    },
  };

  const network = new vis.Network(canvasEl, { nodes: nodesDS, edges: edgesDS }, options);

  let currentNodes = [];
  let currentEdges = [];
  let selectedEdgeId = null;
  let addMode = false;

  function fillPanel(node) {
    if (destroyed) return;
    clear(panel);
    panel.classList.add("open");

    const nameEl = h("h2", {}, node.label || node.ip);
    panel.appendChild(nameEl);

    const typeEl = typeBadge(node.type);
    panel.appendChild(typeEl);

    const statusEl = statusDot(node.online);
    panel.appendChild(statusEl);

    panel.appendChild(h("p", {}, `IP: ${node.ip}`));
    const macEl = h("p", { class: "mono" }, `MAC: ${node.mac}`);
    panel.appendChild(macEl);

    panel.appendChild(h("p", {}, `Vendor: ${node.vendor || "Unknown"}`));
    panel.appendChild(h("p", {}, `Open ports: ${node.open_ports}`));

    if (node.tags && node.tags.length) {
      const tagsDiv = h("div", { class: "tags" });
      for (const tag of node.tags) {
        tagsDiv.appendChild(h("span", { class: "tag" }, tag));
      }
      panel.appendChild(tagsDiv);
    }

    const link = h("a", { href: `#/device/${node.id}` }, "Open device page");
    panel.appendChild(link);
  }

  function closePanel() {
    if (destroyed) return;
    clear(panel);
    panel.classList.remove("open");
  }

  network.on("selectNode", (params) => {
    if (destroyed) return;
    // nodesDS only holds drawing attributes; the device details come from /api/map.
    const node = currentNodes.find((n) => n.id === params.nodes[0]);
    if (node) fillPanel(node);
  });

  network.on("deselectNode", () => {
    if (destroyed) return;
    closePanel();
  });

  network.on("selectEdge", (params) => {
    if (destroyed) return;
    selectedEdgeId = params.edges[0];
    deleteLinkBtn.disabled = false;
  });

  network.on("deselectEdge", () => {
    if (destroyed) return;
    selectedEdgeId = null;
    deleteLinkBtn.disabled = true;
  });

  network.on("dragEnd", (params) => {
    if (destroyed) return;
    if (params.nodes.length === 0) return;
    const positions = network.getPositions(params.nodes);
    for (const id of params.nodes) {
      const pos = positions[id];
      patch(`/api/devices/${id}`, { pos_x: pos.x, pos_y: pos.y }).catch((err) => {
        if (destroyed) return;
        toast(err.message || "Failed to save position");
      });
    }
  });

  network.on("stabilizationIterationsDone", () => {
    if (destroyed) return;
    const allHavePos = currentNodes.every((n) => n.pos_x != null && n.pos_y != null);
    if (allHavePos) {
      network.setOptions({ physics: false });
    }
  });

  addLinkBtn.addEventListener("click", () => {
    if (destroyed) return;
    if (addMode) {
      network.disableEditMode();
      addMode = false;
      addLinkBtn.classList.remove("active");
    } else {
      network.addEdgeMode();
      addMode = true;
      addLinkBtn.classList.add("active");
    }
  });

  deleteLinkBtn.addEventListener("click", () => {
    if (destroyed) return;
    if (!selectedEdgeId) return;
    del(`/api/relations/${selectedEdgeId}`)
      .then(() => {
        if (destroyed) return;
        toast("Link removed");
        reload();
      })
      .catch((err) => {
        if (destroyed) return;
        toast(err.message || "Failed to delete link");
      });
  });

  resetBtn.addEventListener("click", () => {
    if (destroyed) return;
    const ids = currentNodes.map((n) => n.id);
    Promise.all(ids.map((id) => patch(`/api/devices/${id}`, { pos_x: null, pos_y: null })))
      .then(() => {
        if (destroyed) return;
        network.setOptions({ physics: true });
        reload();
      })
      .catch((err) => {
        if (destroyed) return;
        toast(err.message || "Failed to reset layout");
      });
  });

  exportBtn.addEventListener("click", () => {
    if (destroyed) return;
    const canvas = container.querySelector("canvas");
    if (!canvas) return;
    const offscreen = document.createElement("canvas");
    offscreen.width = canvas.width;
    offscreen.height = canvas.height;
    const ctx = offscreen.getContext("2d");
    const bg = getComputedStyle(mapWrap).backgroundColor || "white";
    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, offscreen.width, offscreen.height);
    ctx.drawImage(canvas, 0, 0);
    offscreen.toBlob((blob) => {
      if (destroyed) return;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "netlens-map.png";
      a.click();
      URL.revokeObjectURL(url);
    });
  });

  searchInput.addEventListener("input", () => {
    if (destroyed) return;
    applyFilters(nodesDS, edgesDS, currentNodes, currentEdges, searchInput.value, typeSelect.value, statusSelect.value);
  });

  typeSelect.addEventListener("change", () => {
    if (destroyed) return;
    applyFilters(nodesDS, edgesDS, currentNodes, currentEdges, searchInput.value, typeSelect.value, statusSelect.value);
  });

  statusSelect.addEventListener("change", () => {
    if (destroyed) return;
    applyFilters(nodesDS, edgesDS, currentNodes, currentEdges, searchInput.value, typeSelect.value, statusSelect.value);
  });

  async function reload() {
    if (destroyed) return;
    try {
      const data = await get("/api/map");
      if (destroyed) return;
      const newNodes = data.nodes || [];
      const newEdges = data.edges || [];

      const existingNodeIds = new Set(nodesDS.getIds());
      const existingEdgeIds = new Set(edgesDS.getIds());

      const newNodeIds = new Set(newNodes.map((n) => n.id));
      const newEdgeIds = new Set(newEdges.map((e) => e.id));

      for (const id of existingNodeIds) {
        if (!newNodeIds.has(id)) {
          nodesDS.remove(id);
        }
      }
      for (const id of existingEdgeIds) {
        if (!newEdgeIds.has(id)) {
          edgesDS.remove(id);
        }
      }

      for (const node of newNodes) {
        const existing = nodesDS.get(node.id);
        const data = buildNodeData(node);
        if (existing) {
          nodesDS.update(data);
        } else {
          nodesDS.add(data);
        }
      }

      for (const edge of newEdges) {
        const existing = edgesDS.get(edge.id);
        const data = buildEdgeData(edge);
        if (existing) {
          edgesDS.update(data);
        } else {
          edgesDS.add(data);
        }
      }

      currentNodes = newNodes;
      currentEdges = newEdges;

      applyFilters(nodesDS, edgesDS, currentNodes, currentEdges, searchInput.value, typeSelect.value, statusSelect.value);

      if (currentNodes.length === 0) {
        clear(canvasEl);
        canvasEl.appendChild(h("div", { class: "empty" }, "No devices yet. Run a scan."));
      }
    } catch (err) {
      if (destroyed) return;
      toast(err.message || "Failed to load map");
    }
  }

  const interval = setInterval(() => {
    if (!destroyed) reload();
  }, 30000);

  function onScanFinished() {
    if (!destroyed) reload();
  }

  document.addEventListener("netlens:scan-finished", onScanFinished);

  reload();

  return () => {
    destroyed = true;
    network.destroy();
    clearInterval(interval);
    document.removeEventListener("netlens:scan-finished", onScanFinished);
  };
}