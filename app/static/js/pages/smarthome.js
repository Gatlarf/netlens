import { get } from "../api.js";
import { h, clear, timeAgo } from "../util.js";

function battery(d) {
  if (d.battery === null || d.battery === undefined) return d.battery_low ? h("span", { class: "warn-text" }, "low") : h("span", { class: "hint" }, "");
  return h("span", { class: d.battery_low ? "warn-text" : "" }, `${d.battery}%`);
}

export async function render(container) {
  let destroyed = false;
  const body = h("div", {}, h("p", { class: "hint" }, "Loading..."));
  container.append(h("div", { class: "toolbar" }, h("strong", {}, "Smart home"), h("span", { class: "hint" }, "The devices of your smart-home hub, with what Netlens cannot see on the network. It comes from a plugin (Home Assistant).")), body);
  let filter = "", area = "", only = "";

  async function load() {
    let data;
    try {
      data = await get("/api/inventory");
    } catch (err) {
      if (!destroyed) { clear(body); body.appendChild(h("p", { class: "error" }, err.message || "Could not load the devices.")); }
      return;
    }
    if (destroyed) return;
    clear(body);
    if (!data.servers.length) {
      body.appendChild(h("div", { class: "card" }, h("p", {}, "No smart-home hub is connected yet."),
        h("p", { class: "hint" }, "Install the ", h("a", { href: "#/settings/plugin-browse" }, "Home Assistant plugin"), " from the Plugin store and turn it on. Netlens then lists your devices with manufacturer, model, area and battery, ties the ones that are on the network to their device page, and warns when a device becomes unavailable or a battery runs low.")));
      return;
    }
    const s = data.summary;
    const tiles = h("div", { class: "card-row" });
    const tile = (label, value, tone) => h("div", { class: `card tile ${tone || ""}` }, h("div", { class: "tile-value" }, String(value)), h("div", { class: "hint" }, label));
    tiles.append(tile("devices", s.devices), tile("unavailable", s.unavailable, s.unavailable ? "warn" : ""), tile("low batteries", s.battery_low, s.battery_low ? "warn" : ""),
      tile("seen on the network", s.matched), tile("updates waiting", s.updates, s.updates ? "warn" : ""));
    body.appendChild(tiles);
    for (const v of data.servers) for (const w of v.warnings) body.appendChild(h("p", { class: "warn-text" }, `${v.name}: ${w}`));

    const areas = [...new Set(data.devices.map((d) => d.area).filter(Boolean))].sort();
    const search = h("input", { type: "search", placeholder: "Search", value: filter });
    const areaSel = h("select", {}, h("option", { value: "" }, "All areas"), ...areas.map((a) => h("option", { value: a, selected: a === area }, a)));
    const onlySel = h("select", {}, ...[["", "All devices"], ["unavailable", "Unavailable"], ["battery", "Low battery"], ["network", "On the network"], ["update", "Update waiting"]].map(([v, l]) => h("option", { value: v, selected: v === only }, l)));
    const tbody = h("tbody");
    const table = h("table", { class: "data" });
    table.appendChild(h("thead", {}, h("tr", {}, ...["Device", "Model", "Area", "Protocol", "State", "Battery", "Paired through", "On the network"].map((c) => h("th", {}, c)))));
    table.appendChild(tbody);
    function draw() {
      clear(tbody);
      const q = filter.toLowerCase();
      const rows = data.devices.filter((d) => (!q || `${d.name} ${d.manufacturer || ""} ${d.model || ""} ${d.area || ""}`.toLowerCase().includes(q)) && (!area || d.area === area)
        && (only === "" || (only === "unavailable" && !d.available) || (only === "battery" && d.battery_low) || (only === "network" && d.device_id) || (only === "update" && d.update)));
      for (const d of rows.sort((a, b) => (a.available - b.available) || a.name.localeCompare(b.name))) {
        tbody.appendChild(h("tr", {}, h("td", {}, d.url ? h("a", { href: d.url, target: "_blank", rel: "noopener" }, d.name) : d.name),
          h("td", {}, [d.manufacturer, d.model].filter(Boolean).join(" ")), h("td", {}, d.area || ""), h("td", {}, d.protocol || ""),
          h("td", { title: d.unavailable_since || "" }, d.available ? h("span", { class: "run-ok" }, "available") : h("span", { class: "error" }, `unavailable${d.unavailable_since ? ` · ${timeAgo(d.unavailable_since)}` : ""}`), d.update ? h("span", { class: "warn-text" }, " · update") : ""),
          h("td", {}, battery(d)), h("td", {}, d.via || ""), h("td", {}, d.device_id ? h("a", { href: `#/device/${d.device_id}` }, d.device || "device") : "")));
      }
      if (!rows.length) tbody.appendChild(h("tr", {}, h("td", { colspan: 8, class: "hint" }, "Nothing matches.")));
    }
    search.addEventListener("input", () => { filter = search.value; draw(); });
    areaSel.addEventListener("change", () => { area = areaSel.value; draw(); });
    onlySel.addEventListener("change", () => { only = onlySel.value; draw(); });
    draw();
    body.appendChild(h("div", { class: "card" }, h("div", { class: "form-actions" }, search, areaSel, onlySel), h("div", { class: "table-wrap" }, table)));
  }

  await load();
  const timer = setInterval(() => { if (!document.hidden && !filter) load(); }, 60000);
  return () => { destroyed = true; clearInterval(timer); };
}
