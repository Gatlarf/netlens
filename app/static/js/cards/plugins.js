import { get, post, put, upload } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";
import { groupByCategory, openSet, remember } from "./plugin_groups.js";


// one coloured dot and a short text: green synced, red failed or in trouble, grey off or waiting
function health(p) {
  if (p.problem && !p.status) return "bad";
  if (p.status && !p.status.ok) return "bad";
  if (p.status && p.status.ok) return p.enabled ? "ok" : "off";
  return "off";
}

function statusCell(p) {
  const dot = h("span", { class: `sdot ${health(p)}`, "aria-hidden": "true" });
  if (p.problem && !p.status) return h("td", { class: "error" }, dot, p.problem);
  if (!p.status) return h("td", { class: "hint" }, dot, p.enabled ? "waiting for the first sync" : "");
  if (p.status.ok) return h("td", { class: "hint" }, dot, `synced ${timeAgo(p.status.ts)}`);
  return h("td", { class: "error" }, dot, `failed ${timeAgo(p.status.ts)}: ${p.status.error}`);
}

function fillPluginsCard(card, data, notice = null) {
  clear(card);
  card.appendChild(h("h2", {}, "Plugins"));
  card.appendChild(h("p", { class: "hint" },
    "Plugins connect Netlens to routers and hypervisors. Each one reports what is connected to what, and Netlens shows it on the map and in the hierarchy. " +
    "Turn a plugin on or off here; its own settings are on its page in the menu."));

  if ((data.missing || []).length) {
    // settings that came back with a restore, for plugins whose files are not here (a new data folder): installing keeps them
    const box = h("div", { class: "baseline-box" });
    box.appendChild(h("p", { class: "error" }, "Not installed here, but their settings are saved (for example after a restore). Install them again and the settings come back."));
    for (const m of data.missing) {
      const row = h("p", {}, h("strong", {}, m.id), m.version ? ` ${m.version} ` : " ");
      if (m.source === "index") {
        const btn = h("button", { type: "button", class: "btn admin-only" }, "Install again from the index");
        btn.addEventListener("click", async () => {
          btn.disabled = true;
          try {
            let result;
            try {
              result = await post(`/api/plugin-index/${m.id}/install`, {});
            } catch (err) {
              if (err.status !== 409 || !window.confirm(`${err.message}\n\nInstall it anyway?`)) throw err;
              result = await post(`/api/plugin-index/${m.id}/install`, { accept_risk: true });
            }
            toast(`${m.id} ${result.version} installed with its saved settings`, "success");
            document.dispatchEvent(new CustomEvent("netlens:plugins-changed"));
            fillPluginsCard(card, await get("/api/plugins"));
          } catch (err) {
            toast(err.message || "Could not install it", "error");
            btn.disabled = false;
          }
        });
        row.appendChild(btn);
      } else {
        row.appendChild(h("span", { class: "hint" }, "was uploaded as a file: upload the .zip again below"));
      }
      box.appendChild(row);
    }
    card.appendChild(box);
  }

  // one collapsible table per category; a category with a failing plugin opens by itself, and with few plugins everything is open
  const open = openSet("installed");
  const groups = groupByCategory([...data.plugins].sort((a, b) => a.name.localeCompare(b.name)), data.categories);
  const roomy = data.plugins.length <= 8;
  if (data.plugins.length > 8) {
    const all = h("button", { type: "button", class: "btn linklike" }, "Open all");
    const none = h("button", { type: "button", class: "btn linklike" }, "Close all");
    const set = (state) => () => card.querySelectorAll("details.pcat").forEach((d) => { d.open = state; });
    all.addEventListener("click", set(true));
    none.addEventListener("click", set(false));
    card.appendChild(h("p", { class: "hint" }, `${data.plugins.length} plugins · ${data.plugins.filter((p) => p.enabled).length} on `, all, " ", none));
  }
  for (const group of groups) {
    const failing = group.items.filter((p) => health(p) === "bad").length;
    const on = group.items.filter((p) => p.enabled).length;
    const section = h("details", { class: "pcat", "data-category": group.id });
    section.open = roomy || failing > 0 || open.has(group.id);
    section.appendChild(h("summary", { class: "pcat-head" }, h("span", { class: "pcat-name" }, group.label), h("span", { class: "pcat-count" }, String(group.items.length)),
      h("span", { class: "pcat-names" }, group.items.map((p) => p.name).join(", ")),
      h("span", { class: `pcat-note${failing ? " bad" : ""}` }, failing ? `${failing} failing` : `${on} on`)));
    remember(section, open, group.id);
    const table = h("table", { class: "data plist" });          // no header: name, version, status and the switch speak for themselves
    const body = h("tbody");
    for (const p of group.items) {
      const toggle = h("button", { type: "button", class: "btn" }, p.enabled ? "Turn off" : "Turn on");
      toggle.disabled = !p.version;
      toggle.addEventListener("click", async () => {
        toggle.disabled = true;
        try {
          await put(`/api/plugins/${p.id}`, { enabled: !p.enabled });
          toast(p.enabled ? `${p.name} turned off` : `${p.name} turned on`, "success");
        } catch (err) {
          toast(err.message || "Could not change the plugin", "error");
        }
        document.dispatchEvent(new CustomEvent("netlens:plugins-changed"));
        try {
          fillPluginsCard(card, await get("/api/plugins"));
        } catch (err) {
          toast(err.message || "Could not refresh the list", "error");
        }
      });
      body.appendChild(h("tr", {},
        h("td", {}, h("a", { href: `#/settings/plugin-${p.id}` }, p.name), h("span", { class: p.enabled ? "tag" : "tag off" }, p.enabled ? "on" : "off"),
          p.builtin ? h("span", { class: "tag" }, "built in") : null),
        h("td", {}, p.version || ""),
        statusCell(p),
        h("td", {}, toggle)));
    }
    table.appendChild(body);
    section.appendChild(h("div", { class: "table-wrap" }, table));
    card.appendChild(section);
  }

  card.appendChild(h("h3", {}, "Install a plugin"));
  if (notice) card.appendChild(h("p", { class: notice.error ? "error" : "hint" }, notice.text));
  card.appendChild(h("p", { class: "hint" },
    "Upload a plugin as a .zip file. Warning: a plugin is Python code that runs inside Netlens with its rights. It is isolated in its own process " +
    "but that is not a sandbox, so only install plugins from sources you trust and read the code first. A new plugin stays off until you turn it on."));
  const fileInput = h("input", { type: "file", accept: ".zip,application/zip", name: "plugin_file" });
  const uploadBtn = h("button", { type: "button", class: "btn" }, "Upload plugin");
  const resultEl = h("p", { class: "hint" }, "");
  card.appendChild(h("div", { class: "field" }, fileInput));
  card.appendChild(h("div", { class: "button-row" }, uploadBtn, h("a", { class: "btn", href: "#/settings/plugin-browse" }, "Browse plugins")));
  card.appendChild(resultEl);

  uploadBtn.addEventListener("click", async () => {
    const file = fileInput.files && fileInput.files[0];
    if (!file) {
      resultEl.textContent = "Choose a .zip file first.";
      resultEl.className = "error";
      return;
    }
    uploadBtn.disabled = true;
    resultEl.textContent = "";
    try {
      let result;
      try {
        result = await upload("/api/plugins", file);
      } catch (err) {
        if (err.status === 422 && /already installed/.test(err.message || "")) {
          if (!window.confirm(`${err.message}\n\nReplace it? Its settings are kept.`)) throw err;
          result = await upload("/api/plugins?replace=true", file);
        } else {
          throw err;
        }
      }
      toast(`${result.name} ${result.replaced ? "replaced" : "installed"}`, "success");
      document.dispatchEvent(new CustomEvent("netlens:plugins-changed"));
      fillPluginsCard(card, await get("/api/plugins"), {
        text: `${result.name} ${result.version} is installed (SHA-256 ${result.sha256}). It is off until you turn it on.`,
      });
      return;
    } catch (err) {
      resultEl.textContent = err.message || "Upload failed";
      resultEl.className = "error";
    }
    uploadBtn.disabled = false;
  });

  card.appendChild(h("h3", {}, "Write your own"));
  card.appendChild(h("p", {}, h("a", { href: "/api/plugins/example.zip", download: "" }, "Download example plugin"), " · ", h("a", { href: "#/settings/plugin-guide" }, "Read the plugin guide")));
}

export async function buildPluginsCard() {
  const card = h("div", { class: "card" });
  fillPluginsCard(card, await get("/api/plugins"));
  return card;
}
