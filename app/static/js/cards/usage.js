import { get, put, post, del } from "../api.js";
import { longHint } from "../ui.js";
import { h, clear, toast } from "../util.js";
import { fmtNumber } from "../charts.js";

// The one switch for application statistics (which application and which device used how much traffic).
export async function buildUsageCard() {
  const card = h("div", { class: "card usage-card" });
  async function draw() {
    const state = await get("/api/usage");
    clear(card);
    card.appendChild(h("h2", {}, "Traffic statistics"));
    card.appendChild(h("p", {}, "Some routers can tell which application (YouTube, Netflix, a game...) each device used how much traffic for: the ASUS Traffic Analyzer, and the application statistics (DPI) of an Omada gateway. Netlens shows this in Statistics > Network > Applications and on the Network tab of each device."));
    card.appendChild(longHint("This is data about what people do online. In some countries it may not be collected at all, or only with the knowledge or consent of the people concerned (a home, a company and a guest network are not the same). It is switched off until you turn it on, and switching it off again deletes everything stored. Only administrators can see it."));
    const box = h("input", { type: "checkbox" });
    box.checked = state.enabled;
    card.appendChild(h("label", { class: "check-row" }, box, " Collect and keep application statistics"));
    card.appendChild(h("p", { class: "hint" }, state.enabled
      ? `${fmtNumber(state.stored_rows)} rows are stored. A router plugin must also have it enabled: ASUS under "Read the Traffic Analyzer statistics", Omada by entering an Open API client.`
      : "Nothing is read from the routers and nothing is stored."));
    box.addEventListener("change", async () => {
      const turnOff = !box.checked;
      if (turnOff && state.stored_rows && !confirm(`Switch it off and delete the ${fmtNumber(state.stored_rows)} stored rows?`)) {
        box.checked = true;
        return;
      }
      box.disabled = true;
      try {
        const done = await put("/api/usage", { enabled: box.checked });
        toast(done.enabled ? "Application statistics are on. The next sync of the router plugin fills them." : `Application statistics are off${done.removed_rows ? " and what was stored is deleted" : ""}.`, "success");
      } catch (err) {
        toast(err.message || "Could not save", "error");
      }
      draw();
    });
    if (state.enabled) card.appendChild(privacy(state, draw));
  }
  await draw();
  return card;
}

const WARNING = "This rewrites what is already stored and cannot be undone: the application names are gone for good. Continue?";

async function run(call, ok, draw) {
  try {
    const out = await call();
    toast(out.rewritten_rows ? `${ok} ${fmtNumber(out.rewritten_rows)} stored rows were rewritten.` : ok, "success");
  } catch (err) {
    toast(err.message || "Could not save", "error");
  }
  draw();
}

// What is kept (names with a category, or categories only), categories shown under another label, and your own category rules.
function privacy(state, draw) {
  const box = h("div", { class: "usage-privacy" });
  box.appendChild(h("h3", {}, "What is kept"));
  const rows = h("div", { class: "radio-col" });
  for (const [value, text, tip] of [["names", "Application names with their category", "The name the router reports (often a domain) is stored; its category is added when you look at the statistics."], ["categories", "Categories only", "Only the category is stored: no application or domain name ever reaches the database."]]) {
    const radio = h("input", { type: "radio", name: "usage-detail", value });
    radio.checked = state.detail === value;
    radio.addEventListener("change", async () => {
      if (value === "categories" && state.stored_rows && !confirm(WARNING)) { draw(); return; }
      await run(() => put("/api/usage/detail", { detail: value }), "Saved.", draw);
    });
    rows.appendChild(h("label", { class: "check-row", title: tip }, radio, ` ${text}`));
  }
  box.appendChild(rows);

  box.appendChild(h("h3", {}, "Show a category as"));
  const redirects = Object.fromEntries(state.redirects.map((r) => [r.category, r.label]));
  const list = h("datalist", { id: "usage-labels" }, h("option", { value: "Others" }));
  const table = h("table", { class: "table compact" });
  for (const category of state.categories) {
    const input = h("input", { type: "text", maxlength: "40", list: "usage-labels", placeholder: category, value: redirects[category] || "", "aria-label": `Show ${category} as`, title: "Leave empty to show the category itself; \"Others\" or any name hides it among the rest." });
    input.addEventListener("change", async () => {
      const label = input.value.trim();
      if (!label) { await run(() => del(`/api/usage/redirects/${encodeURIComponent(category)}`), "Saved.", draw); return; }
      if (state.stored_rows && !confirm(WARNING)) { input.value = redirects[category] || ""; return; }
      await run(() => put(`/api/usage/redirects/${encodeURIComponent(category)}`, { label }), "Saved.", draw);
    });
    table.appendChild(h("tr", {}, h("td", {}, category), h("td", {}, input)));
  }
  box.append(list, table);

  box.appendChild(h("h3", {}, "Your own rules"));
  const pattern = h("input", { type: "text", maxlength: "80", placeholder: "*.example.com or a word", "aria-label": "Pattern", title: "A domain ending (*.example.com) or a word found anywhere in the name." });
  const pick = h("select", { "aria-label": "Category" }, ...state.categories.map((c) => h("option", { value: c }, c)));
  const add = h("button", { class: "btn", type: "button" }, "Add rule");
  add.addEventListener("click", async () => {
    if (!pattern.value.trim()) return;
    if (state.stored_rows && !confirm(WARNING)) return;
    await run(() => post("/api/usage/rules", { pattern: pattern.value, category: pick.value }), "Rule added.", draw);
  });
  box.appendChild(h("div", { class: "btn-row" }, pattern, pick, add));
  if (state.rules.length) {
    const t = h("table", { class: "table compact" });
    for (const r of state.rules) {
      const x = h("button", { class: "btn", type: "button" }, "Remove");
      x.addEventListener("click", () => run(() => del(`/api/usage/rules/${r.id}`), "Rule removed.", draw));
      t.appendChild(h("tr", {}, h("td", {}, r.pattern), h("td", {}, r.category), h("td", {}, x)));
    }
    box.appendChild(t);
  }
  if (state.uncategorised.length) {
    box.appendChild(h("h3", {}, "Not categorised yet"));
    const t = h("table", { class: "table compact" });
    for (const u of state.uncategorised) {
      const sel = h("select", { "aria-label": `Category of ${u.name}` }, h("option", { value: "" }, "…"), ...state.categories.filter((c) => c !== "Uncategorised").map((c) => h("option", { value: c }, c)));
      sel.addEventListener("change", async () => {
        if (!sel.value) return;
        if (state.stored_rows && !confirm(WARNING)) { sel.value = ""; return; }
        await run(() => post("/api/usage/rules", { pattern: u.name, category: sel.value }), "Rule added.", draw);
      });
      t.appendChild(h("tr", {}, h("td", {}, u.name), h("td", {}, sel)));
    }
    box.appendChild(t);
  }
  return box;
}
