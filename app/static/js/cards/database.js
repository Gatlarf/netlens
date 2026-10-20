import { get, put, post } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

const fmtSize = (b) => (b >= 1073741824 ? `${(b / 1073741824).toFixed(1)} GB` : b >= 1048576 ? `${(b / 1048576).toFixed(1)} MB` : `${Math.max(0, Math.round(b / 1024))} KB`);
const num = (n) => Number(n).toLocaleString();
const NAMES = { events: "events", scans: "finished scans", checks: "presence checks", service_results: "service check results", audit: "audit log lines", sessions: "expired sign-ins",
  metric_state: "health states", port_baselines: "port baselines", wifi_samples: "Wi-Fi samples", checks_hourly: "hourly roll-ups", remote_devices: "remote devices", remote_services: "remote checks",
  settings: "left-over settings", site_points: "graph points of sites with their own retention", site_events: "alerts of sites with their own retention", graph_series: "graph series of things that are gone" };
const sentence = (counts) => {
  const parts = Object.entries(counts).filter(([, n]) => n).map(([k, n]) => `${num(n)} ${NAMES[k] || k.replace(/_/g, " ")}`);
  return parts.length ? parts.join(", ") : "nothing";
};

// Settings → Database: what the data takes, how long it is kept, and the tools to tidy it.
export async function buildDatabaseCard() {
  const card = h("div", { class: "card" });
  const out = h("div", { class: "db-out" });
  let info;

  async function run(btn, label, path, body, say) {
    const all = card.querySelectorAll("button");
    all.forEach((b) => (b.disabled = true));
    out.replaceChildren(h("p", { class: "hint" }, `${label}…`));
    try {
      const r = await post(`/api/database/${path}`, body || {});
      const text = say(r);
      out.replaceChildren(h("p", {}, text));
      toast(text.length > 90 ? "Done" : text, "success");
      if (!(body && body.dry_run)) await load();
    } catch (err) {
      out.replaceChildren(h("p", { class: "error" }, err.message || "That did not work"));
      toast(err.message || "That did not work", "error");
    } finally {
      card.querySelectorAll("button").forEach((b) => (b.disabled = false));
    }
  }

  function tools() {
    const box = h("div", {});
    const row = (title, text, ...buttons) => h("div", { class: "db-tool" }, h("div", { class: "db-tool-text" }, h("strong", {}, title), h("div", { class: "hint" }, text)), h("div", { class: "db-tool-buttons" }, ...buttons));
    const btn = (label, fn, cls = "btn") => { const b = h("button", { class: cls, type: "button" }, label); b.addEventListener("click", () => fn(b)); return b; };
    box.append(
      row("Remove old data", "Applies the retention above now. The weekly run does this by itself.",
        btn("Preview", (b) => run(b, "Counting", "purge", { dry_run: true }, (r) => `Would remove ${sentence(r.removed)}.`)),
        btn("Remove now", (b) => { if (window.confirm("Remove the data that is older than the retention?")) run(b, "Removing", "purge", {}, (r) => `Removed ${sentence(r.removed)}.`); }, "btn")),
      row("Clean up leftovers", "Rows and graph series that belong to devices, checks or remote sites that no longer exist.",
        btn("Preview", (b) => run(b, "Looking", "orphans", { dry_run: true }, (r) => `Found ${sentence(r.removed)}.`)),
        btn("Clean up", (b) => run(b, "Cleaning", "orphans", {}, (r) => `Removed ${sentence(r.removed)}.`))),
      row("Optimize", "Refreshes the statistics the database uses to choose the fastest way to answer. Quick and safe.",
        btn("Optimize", (b) => run(b, "Optimizing", "optimize", {}, (r) => `Optimized in ${r.seconds} s.`))),
      row("Rebuild indexes", "Rebuilds every index from scratch. Only needed after a crash or if the integrity check complains.",
        btn("Rebuild", (b) => run(b, "Rebuilding", "reindex", {}, (r) => `Rebuilt in ${r.seconds} s.`))),
      row("Compact", `Gives freed space back to the disk (VACUUM). Needs free disk space of about the size of the larger file, and writes wait for a moment.${info.main.reclaimable_bytes > 0 ? ` About ${fmtSize(info.main.reclaimable_bytes)} can be reclaimed in the main file.` : ""}`,
        btn("Compact", (b) => { if (window.confirm("Compact the databases now? Scans and checks pause for a moment.")) run(b, "Compacting", "compact", {}, (r) => `Compacted from ${fmtSize(r.before_bytes)} to ${fmtSize(r.after_bytes)} in ${r.seconds} s.`); })),
      row("Check integrity", "Asks SQLite to check both files for damage and for rows that point at nothing.",
        btn("Check", (b) => run(b, "Checking", "integrity", {}, (r) => (r.ok ? "Both databases are healthy." : `Problems found: ${[...r.main, ...r.metrics].filter((x) => x !== "ok").join("; ")}${r.foreign_key_problems ? `; ${r.foreign_key_problems} rows point at something that is gone (run “Clean up leftovers”)` : ""}`)))),
      row("Everything safe, now", "Remove old data, clean up leftovers, optimize and checkpoint: what the weekly run does (Sunday night).",
        btn("Run it now", (b) => run(b, "Working", "tidy", {}, (r) => `Removed ${sentence(r.purged)}; cleaned up ${sentence(r.orphans)}; optimized in ${r.optimize.seconds} s.`), "btn primary")));
    return box;
  }

  function retention() {
    const form = h("form", { class: "db-retention" });
    const inputs = {};
    const oldestKey = { events_days: "events", scans_days: "scans", checks_days: "checks", service_results_days: "service_results", audit_days: "audit" };
    const body = h("tbody");
    for (const [key, spec] of Object.entries(info.retention_info)) {
      inputs[key] = h("input", { type: "number", min: spec.forever ? "0" : String(spec.min), max: String(spec.max), value: String(info.retention[key]), "aria-label": `${spec.label}: days to keep`, style: "width:5.5rem" });
      const old = info.oldest[oldestKey[key]];
      body.appendChild(h("tr", {}, h("td", {}, spec.label), h("td", { style: "white-space:nowrap" }, inputs[key], " days"),
        h("td", { class: "hint" }, `${spec.forever ? "0 keeps everything. " : ""}Default ${spec.default}.${old ? ` Oldest now: ${old.slice(0, 10)}.` : ""}`)));
    }
    const save = h("button", { class: "btn primary", type: "submit" }, "Save retention");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      save.disabled = true;
      try {
        await put("/api/database/retention", Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, Number(i.value)])));
        toast("Saved. It applies at the next weekly run, or press “Remove now”.", "success");
        await load();
      } catch (err) {
        toast(err.message || "Could not save", "error");
        save.disabled = false;
      }
    });
    form.append(h("table", { class: "data no-resize" }, h("tbody", {}, ...body.children)), h("div", { class: "form-actions" }, save));
    return form;
  }

  function draw() {
    clear(card);
    const m = info.main, g = info.metrics;
    const last = info.last && info.last.tidy;
    const tile = (title, value, sub) => h("div", { class: "db-tile" }, h("div", { class: "db-tile-title" }, title), h("div", { class: "db-tile-value" }, value), h("div", { class: "hint" }, sub || "\u00a0"));
    card.appendChild(h("h2", {}, "Database"));
    card.appendChild(h("p", { class: "hint" }, "Netlens keeps two files: the main database (devices, events, scans, settings) and the graph store (measurements, which prunes itself: 7 days in full detail, 90 days at 5 minutes, 2 years per hour)."));
    card.appendChild(h("div", { class: "db-tiles" },
      tile("Main database", fmtSize(m.bytes), `${m.wal_bytes > 1048576 ? `+ ${fmtSize(m.wal_bytes)} write-ahead log` : "write-ahead log is small"}${m.reclaimable_bytes > 1048576 ? ` · ${fmtSize(m.reclaimable_bytes)} can be reclaimed` : ""}`),
      tile("Graph store", fmtSize(g.bytes), g.series !== undefined ? `${num(g.series)} series · ${num(g.raw)} raw, ${num(g.m5)} five-minute, ${num(g.h1)} hourly points` : ""),
      tile("Free disk space", info.disk ? fmtSize(info.disk.free_bytes) : "–", info.disk ? `of ${fmtSize(info.disk.total_bytes)}` : ""),
      tile("Weekly upkeep", last ? timeAgo(last.ts) : "not yet", last ? "removes old data, cleans up, optimizes" : "runs on Sunday night")));

    const left = h("section", { class: "db-panel" }, h("h3", {}, "How long data is kept"), retention());
    const right = h("section", { class: "db-panel" }, h("h3", {}, "Maintenance"), tools(), out);
    card.appendChild(h("div", { class: "db-grid" }, left, right));

    card.appendChild(h("h3", {}, `Tables (${info.tables.length})`));
    card.appendChild(h("div", { class: "table-wrap db-tables" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["Table", "Rows", "Size"].map((t) => h("th", {}, t)))),
      h("tbody", {}, info.tables.map((t) => h("tr", {}, h("td", { class: "mono" }, t.name), h("td", {}, num(t.rows)), h("td", {}, t.bytes === null ? "–" : fmtSize(t.bytes))))))));
  }

  async function load() {
    info = await get("/api/database");
    draw();
  }
  await load();
  return card;
}
