// The public, read-only page behind a share link. Needs no login; the server decides what is in the data.
const root = document.getElementById("share-view");
const token = decodeURIComponent(location.pathname.split("/").filter(Boolean).pop() || "");

function el(tag, attrs = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return node;
}

function ago(iso) {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

function tile(num, label, cls = "") {
  return el("div", { class: "share-tile" }, el("div", { class: `num ${cls}` }, String(num)), el("div", { class: "label" }, label));
}

function drawMap(box, devices) {
  const nodes = devices.map((d) => ({
    id: d.id,
    label: d.ip ? `${d.name}\n${d.ip}` : d.name,
    shape: "dot",
    size: 14,
    color: d.online ? { background: "#16a34a", border: "#166534" } : { background: "#94a3b8", border: "#64748b" },
    font: { size: 12, color: getComputedStyle(document.body).color },
    title: `${d.name} · ${d.online ? "online" : "offline"}`,
  }));
  const ids = new Set(devices.map((d) => d.id));
  const edges = devices.filter((d) => d.parent_id != null && ids.has(d.parent_id)).map((d) => ({ from: d.parent_id, to: d.id, arrows: "to" }));
  new window.vis.Network(box, { nodes: new window.vis.DataSet(nodes), edges: new window.vis.DataSet(edges) }, {
    layout: { hierarchical: { enabled: true, direction: "UD", sortMethod: "directed", levelSeparation: 90, nodeSpacing: 110 } },
    physics: false,
    interaction: { dragNodes: false, hover: true },
    edges: { smooth: { type: "cubicBezier" }, color: { inherit: false, color: "#94a3b8" } },
  });
}

function drawTable(devices, data) {
  const search = el("input", { type: "search", placeholder: "Search", "aria-label": "Search devices" });
  const head = ["", "Name", "Type"];
  if (data.show_ips) head.push("IP");
  if (data.show_macs) head.push("MAC");
  head.push("Last seen");
  const tbody = el("tbody");
  const rows = devices.map((d) => {
    const cells = [el("td", {}, el("span", { class: `dot ${d.online ? "on" : "off"}`, title: d.online ? "online" : "offline" })), el("td", {}, d.name), el("td", {}, d.type)];
    if (data.show_ips) cells.push(el("td", {}, d.ip || ""));
    if (data.show_macs) cells.push(el("td", { class: "mono" }, d.mac || ""));
    cells.push(el("td", {}, d.online ? "now" : ago(d.last_seen)));
    return { d, tr: el("tr", {}, cells) };
  });
  rows.forEach((r) => tbody.append(r.tr));
  search.addEventListener("input", () => {
    const q = search.value.trim().toLowerCase();
    rows.forEach((r) => { r.tr.hidden = q && !`${r.d.name} ${r.d.type} ${r.d.ip || ""} ${r.d.mac || ""}`.toLowerCase().includes(q); });
  });
  return el("div", {}, search, el("table", { class: "data" }, el("thead", {}, el("tr", {}, head.map((t) => el("th", {}, t)))), tbody));
}

function render(data) {
  document.title = `${data.name} · network status`;
  document.getElementById("share-title").textContent = data.name;
  root.replaceChildren();
  root.append(el("p", { class: data.problem ? "share-bad" : "share-ok", id: "share-state" }, data.problem ? "Something needs attention." : "Everything looks fine."));
  const tiles = el("div", { class: "share-tiles" },
    tile(data.devices_online, "devices online", "share-ok"),
    tile(data.devices_offline, "devices offline", data.devices_offline ? "" : "share-ok"),
    tile(data.devices_total, "devices in total"));
  root.append(tiles);
  if (data.services.length) {
    root.append(el("h2", {}, "Services"), el("ul", { class: "share-services" },
      data.services.map((s) => el("li", { class: s.state === "down" ? "share-bad" : s.state === "up" ? "share-ok" : "" }, `${s.name}: ${s.state || "not checked yet"}`))));
  }
  if (data.mode === "view") {
    const box = el("div", { class: "share-map", id: "share-map", "aria-label": "Map of the network" });
    root.append(el("h2", {}, "Map"), box, el("h2", {}, "Devices"), drawTable(data.devices, data));
    if (window.vis) drawMap(box, data.devices);
    else box.append(el("p", { class: "hint" }, "The map could not be loaded."));
  }
  root.append(el("p", { class: "share-footer" }, `Read-only view. Last scan ${ago(data.last_scan)}.`));
}

async function load() {
  try {
    const res = await fetch(`/share-api/${encodeURIComponent(token)}`, { cache: "no-store" });
    if (!res.ok) throw new Error(res.status === 404 ? "This link does not exist or has expired." : "The page could not be loaded.");
    render(await res.json());
  } catch (err) {
    root.replaceChildren(el("p", { class: "error" }, err.message));
  }
}

load();
setInterval(load, 60000);
