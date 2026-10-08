import { get, put, upload } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

const KIND_LABEL = { hypervisor: "Hypervisor", topology: "Network topology" };

function statusCell(p) {
  if (p.problem && !p.status) return h("td", { class: "error" }, p.problem);
  if (!p.status) return h("td", { class: "hint" }, p.enabled ? "waiting for the first sync" : "");
  if (p.status.ok) return h("td", { class: "hint" }, `synced ${timeAgo(p.status.ts)}`);
  return h("td", { class: "error" }, `failed ${timeAgo(p.status.ts)}: ${p.status.error}`);
}

function fillPluginsCard(card, data, notice = null) {
  clear(card);
  card.appendChild(h("h2", {}, "Plugins"));
  card.appendChild(h("p", { class: "hint" },
    "Plugins connect Netlens to routers and hypervisors. Each one reports what is connected to what, and Netlens shows it on the map and in the hierarchy. " +
    "Turn a plugin on or off here; its own settings are on its page in the menu."));

  const table = h("table", { class: "data" });
  const head = h("tr");
  ["Plugin", "Type", "Version", "Source", "Status", ""].forEach((t) => head.appendChild(h("th", {}, t)));
  table.appendChild(h("thead", {}, head));
  const body = h("tbody");
  for (const p of data.plugins) {
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
      h("td", {}, h("a", { href: `#/settings/plugin-${p.id}` }, p.name), p.enabled ? h("span", { class: "tag" }, "on") : null),
      h("td", {}, KIND_LABEL[p.kind] || p.kind || ""),
      h("td", {}, p.version || ""),
      h("td", {}, p.builtin ? "built in" : "uploaded"),
      statusCell(p),
      h("td", {}, toggle)));
  }
  table.appendChild(body);
  card.appendChild(h("div", { class: "table-wrap" }, table));

  card.appendChild(h("h3", {}, "Install a plugin"));
  if (notice) card.appendChild(h("p", { class: notice.error ? "error" : "hint" }, notice.text));
  card.appendChild(h("p", { class: "hint" },
    "Upload a plugin as a .zip file. Warning: a plugin is Python code that runs inside Netlens with its rights. It is isolated in its own process " +
    "but that is not a sandbox, so only install plugins from sources you trust and read the code first. A new plugin stays off until you turn it on."));
  const fileInput = h("input", { type: "file", accept: ".zip,application/zip", name: "plugin_file" });
  const uploadBtn = h("button", { type: "button", class: "btn" }, "Upload plugin");
  const resultEl = h("p", { class: "hint" }, "");
  card.appendChild(h("div", { class: "field" }, fileInput));
  card.appendChild(uploadBtn);
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
