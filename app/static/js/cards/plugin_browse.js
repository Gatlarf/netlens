import { get, post, put } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

const KIND = { hypervisor: "Hypervisor", topology: "Network topology" };
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

function entryCard(p, reload) {
  const card = h("div", { class: "browse-item" });
  const latest = p.latest;
  const level = p.builtin ? "verified" : latest ? latest.review.level : "community";
  const title = h("div", { class: "browse-title" }, h("strong", {}, p.name), " ", h("span", { class: "tag" }, KIND[p.kind] || p.kind), " ", p.builtin ? h("span", { class: "tag" }, "built in") : badge(level));
  card.appendChild(title);
  if (p.description) card.appendChild(h("p", {}, p.description));
  const meta = [];
  if (p.author) meta.push(`by ${p.author}`);
  if (p.license) meta.push(p.license);
  if (latest && !p.builtin) meta.push(`latest ${latest.version}`);
  if (p.installed && !p.builtin) meta.push(`installed ${p.installed_version}`);
  card.appendChild(h("p", { class: "hint" }, meta.join(" · "), p.homepage ? [" · ", h("a", { href: p.homepage, target: "_blank", rel: "noopener noreferrer" }, "homepage")] : null));
  if (p.supports.length) card.appendChild(h("p", { class: "hint" }, "Works with: " + p.supports.join(", ")));
  if (latest && !p.builtin && latest.review.level !== "community") {
    const r = latest.review;
    card.appendChild(h("p", { class: "hint" }, `Reviewed by ${r.reviewer}${r.date ? ` on ${r.date}` : ""}${r.tested_on.length ? `; tested on ${r.tested_on.join(", ")}` : "; not tested on real hardware"}${r.notes ? `. ${r.notes}` : ""}`));
  }
  if (latest && latest.changelog && !p.builtin) card.appendChild(h("p", { class: "hint" }, `What's new: ${latest.changelog}`));
  if (!p.builtin && latest && latest.review.level === "community") {
    card.appendChild(h("p", { class: "warn-note" }, "Not reviewed: only automatic checks were done. It is code that runs inside Netlens."));
  }
  if (p.incompatible) card.appendChild(h("p", { class: "error" }, `Cannot be installed here: ${p.incompatible}`));

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
  card.appendChild(actions);
  return card;
}

export async function buildBrowseCard() {
  const wrap = h("div", {});
  const state = { q: "", kind: "", onlyUpdates: false };

  async function load(refresh = false) {
    const data = await get(`/api/plugin-index${refresh ? "?refresh=true" : ""}`);
    clear(wrap);
    const card = h("div", { class: "card" }, h("h2", {}, "Browse plugins"));
    card.appendChild(h("p", { class: "hint" },
      "The plugin index lists plugins written by the community. Netlens checks every download against the checksum in the index. " +
      "Verified and Reviewed plugins were read by trusted reviewers; Community plugins only passed automatic checks."));
    const idx = data.index;
    if (!idx.enabled) {
      card.appendChild(h("p", { class: "warn-note" }, "The plugin index is switched off (see the settings below)."));
    } else {
      const line = idx.fetched ? `Index updated ${timeAgo(idx.fetched)}${idx.stale ? " (could not be refreshed, showing the last copy)" : ""}.` : "Index not loaded.";
      card.appendChild(h("p", { class: idx.error ? "error" : "hint" }, idx.error ? `${line} ${idx.error}` : line));
    }
    const search = h("input", { type: "search", placeholder: "Search by name, device or author", value: state.q, "aria-label": "Search plugins" });
    const kind = h("select", { "aria-label": "Type" });
    kind.appendChild(h("option", { value: "" }, "All types"));
    for (const [k, v] of Object.entries(KIND)) kind.appendChild(h("option", { value: k }, v));
    kind.value = state.kind;
    const refreshBtn = h("button", { class: "btn", type: "button" }, "Refresh");
    refreshBtn.addEventListener("click", () => load(true));
    card.appendChild(h("div", { class: "toolbar" }, search, kind, refreshBtn));
    const list = h("div", { class: "browse-list" });
    card.appendChild(list);

    function render() {
      clear(list);
      const q = state.q.toLowerCase();
      const items = data.plugins.filter((p) => (!state.kind || p.kind === state.kind) &&
        (!q || [p.name, p.description, p.author, ...p.supports].join(" ").toLowerCase().includes(q)));
      if (!items.length) list.appendChild(h("p", { class: "hint" }, idx.enabled ? "No plugins match." : ""));
      for (const p of items) list.appendChild(entryCard(p, () => load()));
    }
    search.addEventListener("input", () => { state.q = search.value; render(); });
    kind.addEventListener("change", () => { state.kind = kind.value; render(); });
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
