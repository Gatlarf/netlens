import { get } from "../api.js";
import { h, clear, fmtTime } from "../util.js";

// Settings → Audit log: who changed what, and when (kept for a year; request bodies, passwords and tokens are never stored).
export async function buildAuditCard() {
  const card = h("div", { class: "card" });
  const body = h("tbody", {});
  const more = h("button", { class: "btn", type: "button", hidden: true }, "Show older entries");
  const note = h("p", { class: "hint" });
  const userSelect = h("select", { "aria-label": "User" }, h("option", { value: "" }, "Everybody"));
  const search = h("input", { type: "search", placeholder: "Search what was done", "aria-label": "Search" });
  let last = null;

  async function load(append) {
    const params = new URLSearchParams({ limit: "100" });
    if (append && last) params.set("before", String(last));
    if (userSelect.value) params.set("user", userSelect.value);
    if (search.value.trim()) params.set("q", search.value.trim());
    let data;
    try {
      data = await get(`/api/audit?${params}`);
    } catch (err) {
      note.textContent = err.message || "The log could not be loaded";
      return;
    }
    if (!append) clear(body);
    for (const e of data.entries) {
      body.appendChild(h("tr", { class: e.status >= 400 ? "audit-bad" : "" },
        h("td", {}, fmtTime(e.ts)), h("td", {}, e.user || "—"), h("td", {}, e.action), h("td", { class: "hint" }, e.ip || "")));
    }
    if (data.entries.length) last = data.entries[data.entries.length - 1].id;
    more.hidden = !data.more;
    note.textContent = body.children.length ? "" : "Nothing recorded yet. Changes made from now on appear here.";
    if (!append && userSelect.options.length === 1) for (const u of data.users) userSelect.appendChild(h("option", { value: u }, u));
  }

  userSelect.addEventListener("change", () => load(false));
  let timer = null;
  search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => load(false), 300); });
  more.addEventListener("click", () => load(true));
  card.append(h("h2", {}, "Audit log"),
    h("p", { class: "hint" }, "Who changed what, and when: settings, devices, users, monitors, backups and sign-ins. Kept for a year. Passwords and request contents are never stored."),
    h("div", { class: "rep-tools" }, userSelect, search, h("a", { class: "btn", href: "/api/audit.csv", download: "" }, "Download as CSV")),
    h("div", { class: "rep-scroll" }, h("table", { class: "rep-table" }, h("thead", {}, h("tr", {}, ...["When", "Who", "What", "From"].map((t) => h("th", {}, t)))), body)),
    note, more);
  await load(false);
  return card;
}
