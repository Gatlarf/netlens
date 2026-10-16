import { get, post, put } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";
import { groupByCategory, openSet, remember } from "./plugin_groups.js";

const LEVEL_TEXT = { verified: "Verified", reviewed: "Reviewed", community: "Community" };

function badge(level) {
  return h("span", { class: `level-badge level-${level}`, title: level }, LEVEL_TEXT[level] || level);
}

function confirmText(p, release) {
  const level = release.review.level;
  if (level === "verified") {
    return `Install ${p.name} ${release.version}?\n\nVerified: a trusted reviewer read this code and tested it on ${release.review.tested_on.join(", ") || "real hardware"}.`;
  }
  if (level === "reviewed") {
    return `Install ${p.name} ${release.version}?\n\nReviewed: a trusted reviewer read this code, but nobody tested it on real hardware.\nA plugin is code that runs inside Netlens.`;
  }
  return `WARNING: ${p.name} ${release.version} has NOT been reviewed.\n\nA plugin is Python code that runs inside Netlens with its rights and can read its data, including saved credentials. It passed only automatic checks.\n\nInstall it only if you trust its author (${p.author || "unknown"}).\n\nInstall anyway?`;
}

// the first sentence, kept short: the rest of the description goes under "Details"
function shortText(text) {
  const first = (text || "").split(/(?<=\.)\s/)[0];
  if (first.length <= 150) return first;
  return first.slice(0, 150).replace(/\s+\S*$/, "") + "…";
}

// One plugin as a compact row. The first line is a summary (name, badge, a short sentence, state); everything else opens under it.
function entryRow(p, reload) {
  const latest = p.latest;
  const level = p.builtin ? "verified" : latest ? latest.review.level : "community";
  const state = p.builtin ? h("span", { class: "tag" }, "built in")
    : p.update_available ? h("span", { class: "tag unknown-tag" }, `update ${latest.version}`)
    : p.installed ? h("span", { class: "tag" }, `installed ${p.installed_version}`)
    : latest ? h("span", { class: "hint" }, `v${latest.version}`) : null;
  const row = h("details", { class: "prow", "data-plugin": p.id });
  row.appendChild(h("summary", { class: "prow-sum" },
    h("strong", { class: "prow-name" }, p.name),
    p.builtin ? null : badge(level),
    h("span", { class: "prow-desc" }, shortText(p.description)),
    h("span", { class: "prow-state" }, state)));
  const body = h("div", { class: "prow-body" });
  if (p.description) body.appendChild(h("p", {}, p.description));
  if (p.incompatible) body.appendChild(h("p", { class: "error" }, `Cannot be installed here: ${p.incompatible}`));
  const meta = [];
  if (p.author) meta.push(`by ${p.author}`);
  if (p.license) meta.push(p.license);
  if (latest && !p.builtin) meta.push(`latest ${latest.version}`);
  if (p.installed && !p.builtin) meta.push(`installed ${p.installed_version}`);
  body.appendChild(h("p", { class: "hint" }, meta.join(" · "), p.homepage ? [" · ", h("a", { href: p.homepage, target: "_blank", rel: "noopener noreferrer" }, "homepage")] : null));
  if (p.supports.length) body.appendChild(h("div", { class: "hint" }, "Works with:", h("ul", {}, ...p.supports.map((t) => h("li", {}, t)))));
  if (latest && !p.builtin && latest.review.level !== "community") {
    const r = latest.review;
    body.appendChild(h("p", { class: "hint" }, `Reviewed by ${r.reviewer}${r.date ? ` on ${r.date}` : ""}${r.tested_on.length ? `; tested on ${r.tested_on.join(", ")}` : "; not tested on real hardware"}${r.notes ? `. ${r.notes}` : ""}`));
  }
  if (latest && latest.changelog && !p.builtin) body.appendChild(h("p", { class: "hint" }, `What's new: ${latest.changelog}`));
  if (!p.builtin && latest && latest.review.level === "community") {
    body.appendChild(h("p", { class: "warn-note" }, "Not reviewed: only automatic checks were done. It is code that runs inside Netlens."));
  }

  const actions = h("div", { class: "browse-actions" });
  if (p.builtin) {
    actions.appendChild(h("a", { href: `#/settings/plugin-${p.id}` }, "Open settings"));
  } else {
    if (p.installed) actions.appendChild(h("a", { href: `#/settings/plugin-${p.id}` }, "Open settings"));
    const label = p.update_available ? `Update to ${latest.version}` : p.installed ? "Reinstall" : "Install";
    if (!p.installed || p.update_available || latest) {
      const btn = h("button", { class: `btn${p.update_available ? " primary" : ""}`, type: "button" }, label);
      btn.disabled = Boolean(p.incompatible) || !latest || (p.installed && !p.update_available);
      btn.addEventListener("click", async () => {
        if (!window.confirm(confirmText(p, latest))) return;
        btn.disabled = true;
        try {
          const res = await post(`/api/plugin-index/${p.id}/install`, { version: latest.version, accept_risk: latest.review.level === "community" });
          toast(`${p.name} ${res.version} ${res.replaced ? "updated" : "installed"}${res.replaced ? "" : " (it is off until you turn it on)"}`, "success");
          document.dispatchEvent(new CustomEvent("netlens:plugins-changed"));
        } catch (err) {
          toast(err.message || "Install failed", "error");
        }
        reload();
      });
      actions.appendChild(btn);
    }
    if (p.can_rollback) {
      const back = h("button", { class: "btn", type: "button" }, "Go back to the previous version");
      back.addEventListener("click", async () => {
        if (!window.confirm(`Go back to the previous version of ${p.name}? Its settings are kept.`)) return;
        try {
          const res = await post(`/api/plugin-index/${p.id}/rollback`, {});
          toast(`${p.name} is back at ${res.version}`, "success");
          document.dispatchEvent(new CustomEvent("netlens:plugins-changed"));
        } catch (err) {
          toast(err.message || "Rollback failed", "error");
        }
        reload();
      });
      actions.appendChild(back);
    }
  }
  body.appendChild(actions);
  row.appendChild(body);
  return row;
}

export async function buildBrowseCard() {
  const wrap = h("div", {});
  const state = { q: "", category: "", onlyInstalled: false, onlyUpdates: false, onlyVerified: false };

  async function load(refresh = false) {
    const data = await get(`/api/plugin-index${refresh ? "?refresh=true" : ""}`);
    document.dispatchEvent(new CustomEvent("netlens:plugins-changed")); // the menu shows how many updates there are
    clear(wrap);
    const card = h("div", { class: "card" }, h("h2", {}, "Browse plugins"));
    card.appendChild(h("p", { class: "hint" }, "Plugins from the community. Every download is checked against the checksum in the index."));
    card.appendChild(h("details", { class: "browse-more browse-intro" }, h("summary", {}, "What the badges mean"),
      h("p", { class: "hint" }, "Verified: a trusted reviewer read the code and tested it on real hardware. Reviewed: a trusted reviewer read the code. " +
        "Community: only automatic checks were done, so install it only if you trust its author. A plugin is code that runs inside Netlens.")));
    const idx = data.index;
    if (!idx.enabled) {
      card.appendChild(h("p", { class: "warn-note" }, "The plugin index is switched off (see the settings below)."));
    } else {
      const line = idx.fetched ? `Index updated ${timeAgo(idx.fetched)}${idx.stale ? " (could not be refreshed, showing the last copy)" : ""}.` : "Index not loaded.";
      card.appendChild(h("p", { class: idx.error ? "error" : "hint" }, idx.error ? `${line} ${idx.error}` : line));
    }
    const search = h("input", { type: "search", placeholder: "Search by name, device or author", value: state.q, "aria-label": "Search plugins" });
    const category = h("select", { "aria-label": "Category" });
    category.appendChild(h("option", { value: "" }, "All categories"));
    for (const c of data.categories || []) category.appendChild(h("option", { value: c.id }, c.label));
    category.value = state.category;
    const chip = (key, text) => {
      const box = h("input", { type: "checkbox", checked: state[key] });
      box.addEventListener("change", () => { state[key] = box.checked; render(); });
      return h("label", { class: "chip" }, box, " ", text);
    };
    const refreshBtn = h("button", { class: "btn", type: "button" }, "Refresh");
    refreshBtn.addEventListener("click", () => load(true));
    card.appendChild(h("div", { class: "toolbar" }, search, category, chip("onlyInstalled", "Installed"), chip("onlyUpdates", "Updates"), chip("onlyVerified", "Verified"), refreshBtn));
    const summary = h("p", { class: "hint" });
    const list = h("div", { class: "browse-list" });
    card.append(summary, list);
    const open = openSet("browse");

    function render() {
      clear(list);
      const q = state.q.toLowerCase();
      const labels = new Map((data.categories || []).map((c) => [c.id, c.label]));
      const items = data.plugins.filter((p) => (p.installed || !/^example-/.test(p.id)) && (!state.category || p.category === state.category) &&
        (!state.onlyInstalled || p.installed) && (!state.onlyUpdates || p.update_available) &&
        (!state.onlyVerified || p.builtin || (p.latest && p.latest.review.level === "verified")) &&
        (!q || [p.name, p.description, p.author, labels.get(p.category), ...p.supports].join(" ").toLowerCase().includes(q)));
      const filtering = Boolean(q || state.category || state.onlyInstalled || state.onlyUpdates || state.onlyVerified);
      const installed = data.plugins.filter((p) => p.installed && !p.builtin).length;
      summary.textContent = idx.enabled ? `${items.length} of ${data.plugins.length} plugins${installed ? ` · ${installed} installed` : ""}${data.updates ? ` · ${data.updates} update${data.updates === 1 ? "" : "s"} available` : ""}` : "";
      if (!items.length) list.appendChild(h("p", { class: "hint" }, idx.enabled ? "No plugins match." : ""));
      for (const group of groupByCategory(items, data.categories)) {
        const ups = group.items.filter((p) => p.update_available).length;
        const have = group.items.filter((p) => p.installed && !p.builtin).length;
        const note = [have ? `${have} installed` : "", ups ? `${ups} update${ups === 1 ? "" : "s"}` : ""].filter(Boolean).join(" · ");
        const section = h("details", { class: "pcat", "data-category": group.id });
        section.open = filtering || ups > 0 || open.has(group.id);
        // closed, the heading still tells what is inside: the names of the plugins
        section.appendChild(h("summary", { class: "pcat-head" }, h("span", { class: "pcat-name" }, group.label), h("span", { class: "pcat-count" }, String(group.items.length)),
          h("span", { class: "pcat-names" }, group.items.map((p) => p.name).join(", ")),
          note ? h("span", { class: `pcat-note${ups ? " warn" : ""}` }, note) : null));
        if (!filtering) remember(section, open, group.id);
        const rows = h("div", { class: "prow-list" });
        for (const p of group.items) rows.appendChild(entryRow(p, () => load()));
        section.appendChild(rows);
        list.appendChild(section);
      }
    }
    search.addEventListener("input", () => { state.q = search.value; render(); });
    category.addEventListener("change", () => { state.category = category.value; render(); });
    render();
    wrap.appendChild(card);
    wrap.appendChild(await settingsCard(load));
  }

  async function settingsCard(reload) {
    const s = await get("/api/plugin-index/settings");
    const card = h("div", { class: "card" }, h("h2", {}, "Plugin index settings"));
    const form = h("form", { class: "edit-form" });
    const enabled = h("input", { type: "checkbox", name: "enabled", checked: s.enabled });
    const url = h("input", { type: "text", name: "url", value: s.url === s.official_url ? "" : s.url, placeholder: s.official_url });
    form.append(h("div", { class: "field" }, h("label", {}, enabled, " Use the plugin index")),
      h("div", { class: "field" }, h("label", {}, "Index address"), url, h("p", { class: "hint" }, "Leave empty for the official index. A custom address (https only) can point to your own or a mirrored index.")));
    const save = h("button", { class: "btn", type: "submit" }, "Save");
    form.appendChild(save);
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await put("/api/plugin-index/settings", { enabled: enabled.checked, url: url.value });
        toast("Index settings saved", "success");
        reload(true);
      } catch (err) {
        toast(err.message || "Could not save", "error");
      }
    });
    card.appendChild(form);
    return card;
  }

  await load();
  return wrap;
}
