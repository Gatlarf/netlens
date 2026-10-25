import { get, put, post } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

const GB = 1024 ** 3;
const size = (n) => (n >= GB ? `${(n / GB).toFixed(1)} GB` : n >= 1024 ** 2 ? `${Math.round(n / 1024 ** 2)} MB` : `${Math.round(n / 1024)} kB`);
const SOURCES = [["static", "The login of the health monitor"], ["netlens_ca", "A certificate from the Netlens CA (valid for minutes)"], ["vault_ssh", "A certificate from Vault / OpenBao"]];
const INTERVALS = [[1, "every hour"], [3, "every 3 hours"], [6, "every 6 hours"], [12, "every 12 hours"], [24, "every day"]];

// "What uses the storage of this host": snapshots of the biggest directories, files and Docker logs, and what grew between two of them.
export async function buildDeviceProbeCard(device) {
  const card = h("div", { class: "card admin-only probe-card" });
  let info = null;

  async function load() {
    info = await get(`/api/devices/${device.id}/hostprobe`);
    draw();
  }

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Storage inspection"));
    if (!info.monitor || !["ssh", "winrm"].includes(info.monitor)) {
      card.appendChild(h("p", { class: "hint" }, "Finds out what fills the disks of this host: the biggest folders and files, Docker logs and images, and what grew since the last look. It reads only. It needs health monitoring over SSH or WinRM first (the card above), which supplies the address and the login."));
      return;
    }
    const cfg = info.config;
    const on = h("input", { type: "checkbox", checked: cfg.enabled });
    const every = h("select", {}, INTERVALS.map(([v, t]) => h("option", { value: v, selected: v === cfg.interval_h }, t)));
    const source = h("select", {}, SOURCES.map(([v, t]) => h("option", { value: v, selected: v === cfg.provider }, t)));
    const user = h("input", { type: "text", value: cfg.username, placeholder: "netlens-ro", autocomplete: "off" });
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      try {
        info = await put(`/api/devices/${device.id}/hostprobe`, { enabled: on.checked, interval_h: Number(every.value), provider: source.value, username: user.value });
        toast("Saved", "success");
        draw();
      } catch (err) { toast(err.message || "Could not save", "error"); }
    });
    card.append(
      h("div", { class: "field" }, h("label", { class: "check-row" }, on, " Look at what uses the storage of this host"), h("p", { class: "hint" }, "A look is taken now and then, and at once when a disk goes over its limit, so a sudden jump can be traced afterwards.")),
      h("div", { class: "field" }, h("label", {}, "How often"), every),
      h("div", { class: "field" }, h("label", {}, "Log in with"), source, h("p", { class: "hint" }, "A certificate is made for each look and stops working after a few minutes; the host only has to trust the Netlens CA. Set it up under Settings → Host probes.")),
      h("div", { class: "field" }, h("label", {}, "User name on the host (certificates)"), user),
      h("div", { class: "form-actions" }, save));
    const last = info.snapshots[0];
    const run = h("button", { class: "btn", type: "button" }, "Inspect now");
    run.addEventListener("click", async () => {
      run.disabled = true;
      run.textContent = "Inspecting… (a big disk can take a minute or two)";
      try {
        const r = await post(`/api/devices/${device.id}/hostprobe/run`, {});
        info = r;
        toast(r.ok ? "Done" : r.error, r.ok ? "success" : "error");
      } catch (err) { toast(err.message || "Could not inspect", "error"); }
      draw();
    });
    if (last) {
      card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, "Last look"),
        last.ok ? h("span", {}, `${timeAgo(last.taken)}, ${info.snapshots.length} kept`) : h("span", { class: "error" }, `${timeAgo(last.taken)} failed: ${last.error}`)));
      if (info.latest && info.latest.mode === "locked" && info.latest.data.script_version && info.latest.data.script_version < info.script_version) {
        card.appendChild(h("p", { class: "hint" }, "The script installed on the host is older than this Netlens expects. Install the new one: Settings → Host probes → Prepare a host."));
      }
      if (info.latest && info.latest.mode === "direct") {
        card.appendChild(h("p", { class: "hint" }, "The host runs the script it was sent. Lock it down so it can run nothing else: Settings → Host probes → Prepare a host."));
      }
    }
    card.appendChild(h("div", { class: "form-actions" }, run));
    const data = info.latest && info.latest.data;
    if (!data) return;
    if (data.partial) card.appendChild(h("p", { class: "hint" }, "The disk is so big that the look stopped after its time limit: the list is partial."));
    const grown = info.growth_since_previous && info.growth_since_previous.growth;
    if (grown && grown.length) {
      card.appendChild(h("h3", {}, "Grew since the look before"));
      card.appendChild(h("ul", { class: "plain" }, grown.map((g) => h("li", {}, h("strong", {}, `+${size(g.bytes)} `), g.path, g.new && g.kind === "file" ? " (new file)" : ""))));
    }
    for (const m of data.mounts.slice(0, 3)) {
      const pct = m.size ? Math.round((100 * m.used) / m.size) : null;
      card.appendChild(h("h3", {}, `${m.mount}${pct !== null ? ` ${pct}% full (${size(m.used)} of ${size(m.size)})` : ""}`));
      const rows = m.dirs.filter((d) => d.path !== m.mount).slice(0, 8);
      card.appendChild(h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, rows.map((d) => h("tr", {}, h("td", {}, d.path), h("td", { class: "num" }, size(d.bytes))))))));
      if (m.files.length) card.appendChild(h("p", { class: "hint" }, "Big files: " + m.files.slice(0, 4).map((f) => `${f.path} (${size(f.bytes)})`).join(", ")));
    }
    const boxes = data.docker.containers.filter((c) => c.log_bytes > 100 * 1024 ** 2 || c.layer_bytes > GB).sort((a, b) => b.log_bytes + b.layer_bytes - (a.log_bytes + a.layer_bytes)).slice(0, 5);
    if (boxes.length) card.appendChild(h("p", { class: "hint" }, "Docker: " + boxes.map((c) => `${c.name} (log ${size(c.log_bytes)}, data ${size(c.layer_bytes)})`).join(", ")));
    if (data.deleted.length) card.appendChild(h("p", { class: "hint" }, "Deleted but still held open: " + data.deleted.slice(0, 3).map((d) => `${d.path} ${size(d.bytes)} (${d.process})`).join(", ")));
  }

  try { await load(); } catch (err) { card.appendChild(h("p", { class: "error" }, err.message || "Could not load")); }
  return card;
}
