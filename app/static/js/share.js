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
  const fields = data.fields || [];
  const search = el("input", { type: "search", placeholder: "Search", "aria-label": "Search devices" });
  const head = ["", "Name"];
  if (fields.includes("type")) head.push("Type");
  if (fields.includes("vendor")) head.push("Vendor");
  if (data.show_ips) head.push("IP");
  if (data.show_macs) head.push("MAC");
  if (fields.includes("last_seen")) head.push("Last seen");
  const tbody = el("tbody");
  const rows = devices.map((d) => {
    const cells = [el("td", {}, el("span", { class: `dot ${d.online ? "on" : "off"}`, title: d.maintenance ? "planned maintenance" : d.online ? "online" : "offline" })),
      el("td", {}, d.name, d.maintenance ? el("span", { class: "hint" }, " (maintenance)") : null)];
    if (fields.includes("type")) cells.push(el("td", {}, d.type || ""));
    if (fields.includes("vendor")) cells.push(el("td", {}, d.vendor || ""));
    if (data.show_ips) cells.push(el("td", {}, d.ip || ""));
    if (data.show_macs) cells.push(el("td", { class: "mono" }, d.mac || ""));
    if (fields.includes("last_seen")) cells.push(el("td", {}, d.online ? "now" : ago(d.last_seen)));
    return { d, tr: el("tr", {}, cells) };
  });
  rows.forEach((r) => tbody.append(r.tr));
  search.addEventListener("input", () => {
    const q = search.value.trim().toLowerCase();
    rows.forEach((r) => { r.tr.hidden = q && !`${r.d.name} ${r.d.type || ""} ${r.d.vendor || ""} ${r.d.ip || ""} ${r.d.mac || ""}`.toLowerCase().includes(q); });
  });
  return el("div", {}, search, el("table", { class: "data" }, el("thead", {}, el("tr", {}, head.map((t) => el("th", {}, t)))), tbody));
}

function drawUptime(u) {
  const bars = el("div", { class: "share-bars", role: "img", "aria-label": `Availability per day, last ${u.days} days` },
    u.daily.map((d) => {
      const level = d.percent === null ? "none" : d.percent >= 99.5 ? "good" : d.percent >= 95 ? "warn" : "bad";
      return el("i", { class: `share-bar ${level}`, title: `${d.day}: ${d.percent === null ? "no data" : d.percent + " %"}` });
    }));
  const box = el("div", {}, el("p", {}, u.percent === null ? "No history yet." : `Available ${u.percent} % over the last ${u.days} days.`), bars);
  if (u.services.length) box.append(el("ul", { class: "share-services" }, u.services.map((s) => el("li", {}, `${s.name}: ${s.percent} % (24 h)`))));
  return box;
}

function applyLook(data) {
  const root = document.documentElement;
  if (data.theme === "light" || data.theme === "dark") root.setAttribute("data-theme", data.theme);
  if (data.accent) root.style.setProperty("--accent", data.accent);
  if (data.brand !== undefined) {
    const brand = document.querySelector(".topbar .brand");
    if (data.brand) brand.replaceChildren(document.createTextNode(data.brand));
  }
}

function render(data) {
  applyLook(data);
  document.title = `${data.name} · network status`;
  document.getElementById("share-title").textContent = data.name;
  root.replaceChildren();
  const has = (name) => data.sections.includes(name);
  if (has("summary") || has("services")) {
    root.append(el("p", { class: data.problem ? "share-bad" : "share-ok", id: "share-state" }, data.problem ? "Something needs attention." : "Everything looks fine."));
  }
  if (data.message) root.append(el("p", { class: "share-message" }, data.message));
  if (data.maintenance) root.append(el("p", { class: "share-maint" }, `Planned maintenance affects ${data.maintenance} ${data.maintenance === 1 ? "device" : "devices"} right now.`));
  if (has("summary")) {
    root.append(el("div", { class: "share-tiles" },
      tile(data.devices_online, "devices online", "share-ok"),
      tile(data.devices_offline, "devices offline", data.devices_offline ? "" : "share-ok"),
      tile(data.devices_total, "devices in total")));
  }
  if (has("services") && data.services.length) {
    root.append(el("h2", {}, "Services"), el("ul", { class: "share-services" },
      data.services.map((s) => el("li", { class: s.state === "down" ? "share-bad" : s.state === "up" ? "share-ok" : "" }, `${s.name}: ${s.state || "not checked yet"}`))));
  }
  if (has("uptime") && data.uptime) root.append(el("h2", {}, "Availability"), drawUptime(data.uptime));
  if (has("map")) {
    const box = el("div", { class: "share-map", id: "share-map", "aria-label": "Map of the network" });
    root.append(el("h2", {}, "Map"), box);
    if (window.vis) drawMap(box, data.devices);
    else box.append(el("p", { class: "hint" }, "The map could not be loaded."));
  }
  if (has("devices")) root.append(el("h2", {}, "Devices"), drawTable(data.devices, data));
  if (has("events") && data.events) {
    root.append(el("h2", {}, "Recent events"), data.events.length
      ? el("ul", { class: "share-events" }, data.events.map((e) => el("li", {}, el("span", { class: "hint" }, `${ago(e.ts)} · `), e.text)))
      : el("p", { class: "hint" }, "Nothing has happened lately."));
  }
  root.append(el("p", { class: "share-footer" }, `Read-only view. Last scan ${ago(data.last_scan)}.`));
}

function keyOf() {
  try { return sessionStorage.getItem(`netlens.share.${token}`) || ""; } catch (e) { return ""; }
}

function askPin(info, message = "") {
  applyLook(info);
  document.title = `${info.name} · network status`;
  document.getElementById("share-title").textContent = info.name;
  const pin = el("input", { type: "password", name: "pin", autocomplete: "off", required: true, "aria-label": "PIN", inputmode: "text" });
  const form = el("form", { class: "share-pin" }, el("p", {}, "This page is protected. Enter the PIN you were given."), pin, " ", el("button", { type: "submit", class: "btn" }, "Open"),
    el("p", { class: "error", role: "alert" }, message));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const res = await fetch(`/share-api/${encodeURIComponent(token)}/unlock`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ pin: pin.value }) });
    if (res.ok) {
      try { sessionStorage.setItem(`netlens.share.${token}`, (await res.json()).key); } catch (err) { /* the PIN is then asked again after a reload */ }
      load();
    } else {
      askPin(info, res.status === 429 ? "Too many wrong PINs. Try again in a few minutes." : "That PIN is not right.");
    }
  });
  root.replaceChildren(form);
  pin.focus();
}

async function load() {
  try {
    const res = await fetch(`/share-api/${encodeURIComponent(token)}`, { cache: "no-store", headers: { "X-Share-Key": keyOf() } });
    if (res.status === 401) {
      const info = await res.json();
      if (info.locked) return askPin(info);
    }
    if (!res.ok) throw new Error(res.status === 404 ? "This link does not exist or has expired." : "The page could not be loaded.");
    render(await res.json());
  } catch (err) {
    root.replaceChildren(el("p", { class: "error" }, err.message));
  }
}

load();
setInterval(() => { if (!root.querySelector(".share-pin")) load(); }, 60000);
