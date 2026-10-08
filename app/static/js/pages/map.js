import { cssVar, isDark } from "../theme.js";
import { get, post, patch, del, ApiError } from "../api.js";
import { h, clear, toast, typeBadge, statusDot, TYPE_LABELS } from "../util.js";
import { buildTree, defaultCollapsed, layoutHorizontal, leafIds } from "../layout_horizontal.js";

const LAYOUTS = ["free", "tree", "horizontal"];


// Colours of the devices and links, one set per theme. The dark set is brighter so everything keeps
// at least 3:1 contrast against the dark canvas (checked by the theme browser test).
const PALETTE_LIGHT = {
  router: "#2563eb",
  switch: "#0891b2",
  ap: "#7c3aed",
  server: "#475569",
  pc: "#059669",
  phone: "#db2777",
  printer: "#ea580c",
  iot: "#a16207",
  camera: "#dc2626",
  nas: "#0d9488",
  vm: "#6366f1",
  unknown: "#7b8aa0",
};

const PALETTE_DARK = {
  router: "#60a5fa",
  switch: "#22d3ee",
  ap: "#a78bfa",
  server: "#94a3b8",
  pc: "#34d399",
  phone: "#f472b6",
  printer: "#fb923c",
  iot: "#facc15",
  camera: "#f87171",
  nas: "#2dd4bf",
  vm: "#818cf8",
  unknown: "#cbd5e1",
};

const EDGES_LIGHT = {
  gateway: { color: "#64748b", width: 1.5, dashes: false },
  route: { color: "#2563eb", width: 1, dashes: [8, 6] },
  "host-of": { color: "#7c3aed", width: 1, dashes: [2, 5] },
  manual: { color: "#d97706", width: 3, dashes: false },
  parent: { color: "#334155", width: 2, dashes: false },
};

const EDGES_DARK = {
  gateway: { color: "#94a3b8", width: 2, dashes: false },
  route: { color: "#60a5fa", width: 1.5, dashes: [8, 6] },
  "host-of": { color: "#c4b5fd", width: 1.5, dashes: [2, 5] },
  manual: { color: "#fbbf24", width: 3, dashes: false },
  parent: { color: "#e2e8f0", width: 2.5, dashes: false },
};

export function mapPalette(dark) {
  return { nodes: dark ? PALETTE_DARK : PALETTE_LIGHT, edges: dark ? EDGES_DARK : EDGES_LIGHT };
}

function palette() {
  return mapPalette(isDark());
}

// Remembered view choices (the page is re-rendered when one changes).
function readPref(key, allowed, fallback) {
  try {
    const v = localStorage.getItem(key);
    return allowed.includes(v) ? v : fallback;
  } catch (e) {
    return fallback;
  }
}

function savePref(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch (e) {
    // storage unavailable: the choice just is not remembered
  }
}

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
  const nodes = palette().nodes;
  return nodes[type] || nodes.unknown;
}

function shorten(text, max) {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

// mode: "free" | "tree" | "horizontal"; extra.folded = number of hidden client devices below this one
function buildNodeData(node, mode = "free", extra = {}) {
  const treeLayout = mode !== "free";
  const color = nodeColor(node.type);
  const label = node.label && node.label !== node.ip ? `${node.label}\n${node.ip}` : node.ip;
  const dark = isDark();
  // dark mode: a light outline keeps every dot clear of the dark canvas; offline devices get a
  // dashed outline as well as the faded fill, so they are recognisable without relying on colour
  const outline = dark ? "#f1f5f9" : color;
  const picked = dark ? "#ffffff" : "#0f172a";
  const data = {
    id: node.id,
    label,
    shape: "dot",
    size: 18,
    color: {
      background: color,
      border: outline,
      highlight: { background: color, border: picked },
      hover: { background: color, border: picked },
    },
    borderWidth: dark ? 2 : 1,
    borderWidthSelected: 4,
    shapeProperties: { borderDashes: node.online ? false : [4, 3] },
    opacity: node.online ? 1 : dark ? 0.6 : 0.4,
    hidden: false,
  };
  if (!treeLayout && node.pos_x != null && node.pos_y != null) {
    data.x = node.pos_x;
    data.y = node.pos_y;
  }
  if (mode === "horizontal") {
    // a card per device (name and address inside it) so labels never run into each other
    const surface = cssVar("--surface", dark ? "#1b2230" : "#ffffff");
    const named = node.label && node.label !== node.ip;
    const lines = [named ? shorten(node.label, 24) : node.ip];
    if (named) lines.push(node.ip);
    if (extra.folded) lines.push(`▸ ${extra.folded} more`);
    Object.assign(data, {
      label: lines.join("\n"),
      shape: "box",
      margin: 8,
      widthConstraint: { minimum: 150, maximum: 190 },
      font: { size: 13, color: cssVar("--text", "#1c1f24"), strokeWidth: 0 },
      color: {
        background: surface,
        border: color,
        highlight: { background: surface, border: picked },
        hover: { background: surface, border: picked },
      },
      borderWidth: 3,
      borderWidthSelected: 4,
      shapeProperties: { borderDashes: node.online ? false : [4, 3], borderRadius: 8 },
      fixed: { x: true, y: true },
    });
    if (extra.pos) {
      data.x = extra.pos.x;
      data.y = extra.pos.y;
    }
  }
  return data;
}

function edgeStyle(kind) {
  const edges = palette().edges;
  return edges[kind] || edges.gateway;
}

function edgeColor(kind) {
  return edgeStyle(kind).color;
}

function buildEdgeData(edge, mode = "free") {
  const treeLayout = mode !== "free";
  const style = edgeStyle(edge.kind);
  return {
    id: edge.id,
    from: edge.from,
    to: edge.to,
    color: { color: edgeColor(edge.kind), highlight: isDark() ? "#ffffff" : "#0f172a", hover: isDark() ? "#ffffff" : "#0f172a" },
    width: style.width,
    dashes: style.dashes,
    arrows: mode === "horizontal" ? "" : "to",
    smooth: mode === "horizontal"
      ? { type: "cubicBezier", forceDirection: "horizontal", roundness: 0.5 }
      : treeLayout ? { type: "cubicBezier", forceDirection: "vertical", roundness: 0.5 } : { type: "continuous" },
    title: edge.kind === "parent" ? edge.reason : edgeTitle(edge),
    hidden: false,
  };
}

// folded: ids hidden because their parent is collapsed; ownEdges: parent links are drawn by the horizontal layout itself
function applyFilters(nodesDS, edgesDS, nodes, edges, search, typeFilter, statusFilter, folded = new Set(), ownEdges = false) {
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
    if (hidden || folded.has(node.id)) hiddenNodes.add(node.id);
  }
  nodesDS.update(nodes.map((node) => ({ id: node.id, hidden: hiddenNodes.has(node.id) })));
  edgesDS.update(
    edges.map((edge) => ({
      id: edge.id,
      hidden: hiddenNodes.has(edge.from) || hiddenNodes.has(edge.to) || (ownEdges && edge.kind === "parent"),
    }))
  );
}

export async function render(container, params) {
  await loadVis();
  let serverLayout = "free";
  try {
    serverLayout = (await get("/api/map-settings")).default_layout;
  } catch (e) {
    // the map still works with the built-in default
  }
  if (!LAYOUTS.includes(serverLayout)) serverLayout = "free";

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

  // a layout chosen in this browser wins over the default set under Settings -> Map
  const layoutMode = readPref("netlens.map.layout", LAYOUTS, serverLayout);
  const treeLayout = layoutMode !== "free"; // the layout arranges itself
  const horizontal = layoutMode === "horizontal";
  // the tree layout needs the parent -> child links, so it always shows the hierarchy
  const linksMode = treeLayout ? "hierarchy" : readPref("netlens.map.links", ["hierarchy", "all"], "hierarchy");
  const refreshView = () => window.dispatchEvent(new Event("hashchange"));

  const linksSelect = h("select", { class: "links-mode", title: "Which links to draw" });
  linksSelect.appendChild(h("option", { value: "hierarchy" }, "Hierarchy links"));
  linksSelect.appendChild(h("option", { value: "all" }, "All links"));
  linksSelect.value = linksMode;
  linksSelect.disabled = treeLayout;
  linksSelect.addEventListener("change", () => {
    savePref("netlens.map.links", linksSelect.value);
    refreshView();
  });
  const layoutSelect = h("select", { class: "layout-mode", title: "How the devices are arranged" });
  layoutSelect.appendChild(h("option", { value: "free" }, "Free layout"));
  layoutSelect.appendChild(h("option", { value: "tree" }, "Tree layout"));
  layoutSelect.appendChild(h("option", { value: "horizontal" }, "Horizontal layout"));
  layoutSelect.value = layoutMode;
  layoutSelect.addEventListener("change", () => {
    savePref("netlens.map.layout", layoutSelect.value);
    refreshView();
  });

  const addLinkBtn = h("button", { class: "btn" }, "Add link");
  const deleteLinkBtn = h("button", { class: "btn danger" }, "Delete link");
  deleteLinkBtn.disabled = true;
  const resetBtn = h("button", { class: "btn" }, "Reset layout");
  resetBtn.disabled = treeLayout; // the tree arranges itself
  const exportBtn = h("button", { class: "btn" }, "Export PNG");
  const collapseAllBtn = h("button", { class: "btn", title: "Fold the client devices of every branch" }, "Collapse clients");
  const expandAllBtn = h("button", { class: "btn", title: "Show every device" }, "Expand all");
  const fitBtn = h("button", { class: "btn", title: "Zoom to show the whole map" }, "Fit");

  const legend = h("div", { class: "legend" });
  const legendItems = [
    { kind: "parent", label: "Parent → child" },
    { kind: "gateway", label: "Gateway" },
    { kind: "route", label: "Route" },
    { kind: "host-of", label: "Host-of" },
    { kind: "manual", label: "Manual" },
  ];
  for (const item of legendItems) {
    const swatch = h("span", { class: "legend-swatch" });
    const style = edgeStyle(item.kind);
    swatch.style.borderTopColor = style.color;
    swatch.style.borderTopWidth = `${Math.max(2, Math.round(style.width))}px`;
    swatch.style.borderTopStyle = !style.dashes ? "solid" : style.dashes[0] <= 3 ? "dotted" : "dashed";
    legend.appendChild(h("div", { class: "legend-item" }, swatch, h("span", {}, item.label)));
  }

  toolbar.appendChild(searchInput);
  toolbar.appendChild(typeSelect);
  toolbar.appendChild(statusSelect);
  toolbar.appendChild(linksSelect);
  toolbar.appendChild(layoutSelect);
  toolbar.appendChild(addLinkBtn);
  toolbar.appendChild(deleteLinkBtn);
  toolbar.appendChild(resetBtn);
  if (horizontal) {
    toolbar.appendChild(collapseAllBtn);
    toolbar.appendChild(expandAllBtn);
    toolbar.appendChild(fitBtn);
  }
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
      font: { size: 13, color: cssVar("--text", "#1c1f24"), strokeWidth: 3, strokeColor: cssVar("--surface", "#ffffff") },
    },
    edges: {
      arrows: "to",
      smooth: { type: "continuous" },
    },
    layout: layoutMode === "tree"
      ? {
          hierarchical: {
            enabled: true,
            direction: "UD",
            sortMethod: "directed",
            levelSeparation: 120,
            nodeSpacing: 150,
            treeSpacing: 200,
          },
        }
      : {},
    physics: treeLayout ? { enabled: false } : {
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
  let tree = buildTree([]);
  let fitNext = true;
  let foldedIds = new Set(); // devices hidden because their branch is collapsed (horizontal layout)
  const collapseState = new Map(); // parent id -> true/false once the user folded or opened it
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

    if (node.parent_id != null) {
      const parent = currentNodes.find((n) => n.id === node.parent_id);
      const how = { manual: "set manually", hypervisor: "hypervisor host", route: "traceroute", gateway: "gateway", uplink: "uplink", guess: "guess" }[node.parent_source] || node.parent_source;
      panel.appendChild(h("p", {}, "Parent: ", h("a", { href: `#/device/${node.parent_id}` }, parent ? parent.label || parent.ip : `device ${node.parent_id}`), ` (${how})`));
    } else {
      panel.appendChild(h("p", {}, "Parent: none (top level)"));
    }
    panel.appendChild(h("p", {}, `Vendor: ${node.vendor || "Unknown"}`));
    panel.appendChild(h("p", {}, `Open ports: ${node.open_ports}`));

    if (node.tags && node.tags.length) {
      const tagsDiv = h("div", { class: "tags" });
      for (const tag of node.tags) {
        tagsDiv.appendChild(h("span", { class: "tag" }, tag));
      }
      panel.appendChild(tagsDiv);
    }

    const clients = horizontal ? leafIds(tree, node.id).length : 0;
    if (clients > 0) {
      const folded = isCollapsed(node.id);
      const toggle = h("button", { class: "btn" }, folded ? `Show ${clients} connected device(s)` : `Hide ${clients} connected device(s)`);
      toggle.addEventListener("click", () => toggleBranch(node.id));
      panel.appendChild(toggle);
    }

    const link = h("a", { href: `#/device/${node.id}` }, "Open device page");
    panel.appendChild(link);
  }

  function isCollapsed(id) {
    return collapseState.has(id) ? collapseState.get(id) : defaultCollapsed(tree).has(id);
  }

  async function toggleBranch(id) {
    if (destroyed) return;
    collapseState.set(id, !isCollapsed(id));
    fitNext = true;
    await reload();
    // keep the details of this device open (its button now says Show/Hide the other way round)
    const node = currentNodes.find((n) => n.id === id);
    if (!destroyed && node) fillPanel(node);
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

  // Dragging selects a node without a click, and clicking an already selected node does nothing:
  // open the details panel when a drag starts so it is not left closed.
  network.on("dragStart", (params) => {
    if (destroyed || params.nodes.length === 0) return;
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
    // parent links ("p<id>") are derived: change them on the device page instead
    deleteLinkBtn.disabled = typeof selectedEdgeId === "string";
  });

  network.on("deselectEdge", () => {
    if (destroyed) return;
    selectedEdgeId = null;
    deleteLinkBtn.disabled = true;
  });

  network.on("dragEnd", (params) => {
    if (destroyed || treeLayout) return;
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

  network.on("doubleClick", (params) => {
    if (destroyed || !horizontal || params.nodes.length === 0) return;
    if (leafIds(tree, params.nodes[0]).length > 0) toggleBranch(params.nodes[0]);
  });

  // Horizontal layout: parent -> child links as right-angle elbows (vis-network only draws curves and straight lines)
  network.on("beforeDrawing", (ctx) => {
    if (destroyed || !horizontal) return;
    const edges = palette().edges;
    const radius = 10;
    const trunkGap = 26;
    for (const edge of currentEdges) {
      if (edge.kind !== "parent") continue;
      const from = nodesDS.get(edge.from);
      const to = nodesDS.get(edge.to);
      if (!from || !to || from.hidden || to.hidden) continue;
      let a;
      let b;
      try {
        a = network.getBoundingBox(edge.from);
        b = network.getBoundingBox(edge.to);
      } catch (e) {
        continue;
      }
      if (!a || !b) continue;
      const x0 = a.right;
      const y0 = (a.top + a.bottom) / 2;
      const x1 = b.left;
      const y1 = (b.top + b.bottom) / 2;
      const trunk = Math.min(x0 + trunkGap, x1 - 4);
      const style = edge.source === "hypervisor" ? edges["host-of"] : edges.parent;
      ctx.save();
      ctx.beginPath();
      ctx.strokeStyle = style.color;
      ctx.lineWidth = edge.source === "hypervisor" ? 2 : style.width;
      ctx.setLineDash(edge.source === "hypervisor" ? [6, 4] : []);
      ctx.moveTo(x0, y0);
      if (Math.abs(y1 - y0) < 1) {
        ctx.lineTo(x1, y1);
      } else {
        const dir = y1 > y0 ? 1 : -1;
        const r = Math.min(radius, Math.abs(y1 - y0) / 2, Math.max(trunk - x0, 1));
        ctx.lineTo(trunk - r, y0);
        ctx.arcTo(trunk, y0, trunk, y0 + dir * r, r);
        ctx.lineTo(trunk, y1 - dir * r);
        ctx.arcTo(trunk, y1, trunk + r, y1, r);
        ctx.lineTo(x1, y1);
      }
      ctx.stroke();
      ctx.restore();
    }
  });

  collapseAllBtn.addEventListener("click", () => {
    if (destroyed) return;
    for (const id of tree.children.keys()) if (leafIds(tree, id).length > 0) collapseState.set(id, true);
    fitNext = true;
    reload();
  });
  expandAllBtn.addEventListener("click", () => {
    if (destroyed) return;
    for (const id of tree.children.keys()) collapseState.set(id, false);
    fitNext = true;
    reload();
  });
  fitBtn.addEventListener("click", () => {
    if (!destroyed) network.fit({ animation: { duration: 300 } });
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
    applyFilters(nodesDS, edgesDS, currentNodes, currentEdges, searchInput.value, typeSelect.value, statusSelect.value, foldedIds, horizontal);
  });

  typeSelect.addEventListener("change", () => {
    if (destroyed) return;
    applyFilters(nodesDS, edgesDS, currentNodes, currentEdges, searchInput.value, typeSelect.value, statusSelect.value, foldedIds, horizontal);
  });

  statusSelect.addEventListener("change", () => {
    if (destroyed) return;
    applyFilters(nodesDS, edgesDS, currentNodes, currentEdges, searchInput.value, typeSelect.value, statusSelect.value, foldedIds, horizontal);
  });

  async function reload() {
    if (destroyed) return;
    try {
      const data = await get("/api/map");
      if (destroyed) return;
      const newNodes = data.nodes || [];
      // "Hierarchy" draws each device's chosen parent link (plus links you drew by hand);
      // "All links" draws every inferred relation like before.
      const newEdges = (data.edges || []).filter((e) =>
        linksMode === "hierarchy" ? e.kind === "parent" || e.kind === "manual" : e.kind !== "parent"
      );

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

      let arranged = null;
      tree = buildTree(newNodes);
      if (horizontal) {
        const collapsed = new Set([...tree.children.keys()].filter(isCollapsed));
        arranged = layoutHorizontal(newNodes, collapsed);
        foldedIds = arranged.hidden;
      }

      for (const node of newNodes) {
        const existing = nodesDS.get(node.id);
        const data = buildNodeData(node, layoutMode, arranged ? { pos: arranged.positions.get(node.id), folded: arranged.folded.get(node.id) } : {});
        if (existing) {
          nodesDS.update(data);
        } else {
          nodesDS.add(data);
        }
      }

      for (const edge of newEdges) {
        const existing = edgesDS.get(edge.id);
        const data = buildEdgeData(edge, layoutMode);
        if (existing) {
          edgesDS.update(data);
        } else {
          edgesDS.add(data);
        }
      }

      currentNodes = newNodes;
      currentEdges = newEdges;

      applyFilters(nodesDS, edgesDS, currentNodes, currentEdges, searchInput.value, typeSelect.value, statusSelect.value, foldedIds, horizontal);

      if (horizontal && fitNext && currentNodes.length > 0) {
        fitNext = false;
        network.fit({ animation: { duration: 300 } });
      }

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
  // the canvas draws its own colours, so rebuild the map when the theme changes
  const onTheme = () => refreshView();
  document.addEventListener("netlens:theme", onTheme);

  reload();

  return () => {
    destroyed = true;
    network.destroy();
    clearInterval(interval);
    document.removeEventListener("netlens:scan-finished", onScanFinished);
    document.removeEventListener("netlens:theme", onTheme);
  };
}