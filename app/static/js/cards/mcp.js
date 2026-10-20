import { get, post, put } from "../api.js";
import { h, clear, toast } from "../util.js";

const TOKEN_MODES = { read: "Read only: look, explain, diagnose", change: "Read and change (needs a licence or the free trial)" };

function copyBox(value, label, rows = 3) {
  const box = rows === 1 ? h("input", { type: "text", readonly: true, "aria-label": label, class: "mcp-snippet", value }) : h("textarea", { rows: String(rows), readonly: true, "aria-label": label, class: "mcp-snippet" }, value);
  const btn = h("button", { class: "btn", type: "button" }, "Copy");
  btn.addEventListener("click", async () => { try { await navigator.clipboard.writeText(box.value); toast("Copied", "success"); } catch { box.select(); } });
  return h("div", { class: "mcp-copy" }, box, btn);
}

// What the person pastes into the agent's configuration. `token` is the real secret right after it is made, a placeholder otherwise.
function connectSnippets(url, token) {
  const t = token || "<your assistant token>";
  const json = JSON.stringify({ mcpServers: { netlens: { type: "http", url, headers: { Authorization: `Bearer ${t}` } } } }, null, 2);
  return h("div", { class: "mcp-connect" },
    h("h4", {}, "Claude Code"), copyBox(`claude mcp add --transport http netlens ${url} --header "Authorization: Bearer ${t}"`, "Claude Code command", 2),
    h("h4", {}, "Agents that take a JSON configuration (Claude Desktop, Cursor, OpenClaw and others)"), copyBox(json, "JSON configuration", 9),
    h("h4", {}, "Agents that only start local programs"), copyBox(`npx mcp-remote ${url} --header "Authorization: Bearer ${t}"`, "mcp-remote command", 2),
    h("p", { class: "hint" }, "The exact place for the configuration differs per agent; the address, the Bearer header and the token are always the same."));
}

function fill(card, info) {
  clear(card);
  card.appendChild(h("h3", {}, "MCP server"));
  card.appendChild(h("p", { class: "hint" },
    "The Model Context Protocol lets an AI agent (Claude, OpenClaw, Cursor and others) use Netlens as a tool: ask what changed, check a site, start a scan, snooze an alert, plan maintenance. " +
    "It is the same access as an assistant token on the API, only easier for an agent to use, so the same limits hold: no users, stored passwords, backups, sharing links, single sign-on, remote sessions or licence, and a read-only token only looks. " +
    "Every change is in the audit log under the token's name."));

  const enabled = h("input", { type: "checkbox", checked: info.enabled });
  const allow = h("input", { type: "checkbox", checked: info.allow_changes });
  const rate = h("input", { type: "number", min: "0", max: "10000", value: String(info.rate_per_minute), style: "width:7em" });
  const off = new Set(info.disabled_groups);

  card.appendChild(h("label", { class: "check" }, enabled, h("strong", {}, "Switch the MCP server on"), h("span", { class: "hint" }, " (off by default; while off, /mcp answers that it is switched off)")));
  card.appendChild(h("div", { class: "field" }, h("label", {}, "Address"), copyBox(info.url, "MCP address", 1)));
  card.appendChild(h("label", { class: "check" }, allow, h("span", {}, "Allow changes through MCP "), h("span", { class: "hint" }, "(off: every agent can only look, whatever its token may do)")));
  card.appendChild(h("div", { class: "field" }, h("label", {}, "Calls per minute and token (0 = no limit)"), rate));

  const groupBoxes = [];
  const section = (title, changes) => {
    const wrap = h("div", { class: "mcp-groups" }, h("h4", {}, title));
    for (const g of info.groups.filter((x) => x.changes === changes)) {
      const box = h("input", { type: "checkbox", checked: !off.has(g.id) });
      groupBoxes.push([g.id, box]);
      wrap.appendChild(h("details", { class: "mcp-group" },
        h("summary", {}, h("label", { class: "check", onclick: (e) => e.stopPropagation() }, box, h("strong", {}, g.title)), h("span", { class: "hint" }, " " + g.about)),
        h("p", { class: "mcp-tools" }, g.tools.join(", "))));
    }
    return wrap;
  };
  card.append(h("h4", {}, "Tools the agent can use"), section("Looking", false), section("Changing", true));
  if (!info.change_allowed) card.appendChild(h("p", { class: "hint" }, "A token that may change things needs a licence or the free trial (Settings → Licence); until then every token can only look."));

  const save = h("button", { class: "btn primary", type: "button" }, "Save MCP settings");
  save.addEventListener("click", async () => {
    try {
      const disabled = groupBoxes.filter(([, box]) => !box.checked).map(([id]) => id);
      const next = await put("/api/mcp", { enabled: enabled.checked, allow_changes: allow.checked, disabled_groups: disabled, rate_per_minute: Number(rate.value || 0) });
      toast(next.enabled ? "MCP server is on" : "MCP server is off", "success");
      fill(card, await get("/api/mcp"));
    } catch (err) { toast(err.message || "Could not save", "error"); }
  });
  card.appendChild(h("div", { class: "btn-row" }, save));

  card.appendChild(h("h4", {}, "Connect an agent"));
  card.appendChild(h("p", { class: "hint" }, "An agent signs in with an assistant token. Make one here (the same kind as under AI assistant above); the token is shown once."));
  const form = h("form", { class: "edit-form" });
  const name = h("input", { type: "text", maxlength: "60", value: "MCP agent", required: true });
  const mode = h("select", {}, h("option", { value: "read" }, TOKEN_MODES.read), h("option", { value: "change", disabled: !info.change_allowed }, TOKEN_MODES.change));
  const result = h("div", {});
  form.append(h("div", { class: "field" }, h("label", {}, "Name of the agent"), name), h("div", { class: "field" }, h("label", {}, "What it may do"), mode),
    h("button", { class: "btn", type: "submit" }, "Make a token and show the settings"), result);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const r = await post("/api/assistant/token", { name: name.value, mode: mode.value });
      clear(result);
      result.append(h("p", { class: "warn-text" }, "Copy this now: the token is shown only once. If you lose it, delete it under AI assistant and make a new one."), connectSnippets(info.url, r.token));
    } catch (err) { toast(err.message || "Could not make the token", "error"); }
  });
  card.append(form, h("details", {}, h("summary", {}, "Show the settings without a token"), connectSnippets(info.url, "")));
}

export async function buildMcpCard() {
  const card = h("div", { class: "card" });
  fill(card, await get("/api/mcp"));
  return card;
}
