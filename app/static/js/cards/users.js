import { api, get } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";

const ROLE_TEXT = { admin: "Administrator (everything)", operator: "Operator (looks and acts, no settings) - business feature", viewer: "Viewer (read-only)" };

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    return false;
  }
}

// A viewer can be limited to some groups (a customer view). Returns the box and a function that gives the chosen group ids (null = all).
function groupPicker(groups, chosen) {
  const box = h("div", { class: "scope-picker" });
  const boxes = groups.map((g) => {
    const input = h("input", { type: "checkbox", value: String(g.id) });
    input.checked = (chosen || []).includes(g.id);
    box.appendChild(h("label", { class: "check" }, input, ` ${g.name}`));
    return input;
  });
  if (!groups.length) box.appendChild(h("p", { class: "hint" }, "No groups yet. Create groups under Settings → Groups and put devices in them."));
  return { box, value: () => { const ids = boxes.filter((b) => b.checked).map((b) => Number(b.value)); return ids.length ? ids : null; } };
}

// The same for remote sites: a customer who sees its own sites only.
function sitePicker(sites, chosen) {
  const box = h("div", { class: "scope-picker" });
  const boxes = sites.map((s) => {
    const input = h("input", { type: "checkbox", value: String(s.id) });
    input.checked = (chosen || []).includes(s.id);
    box.appendChild(h("label", { class: "check" }, input, ` ${s.customer ? `${s.customer} / ` : ""}${s.name}`));
    return input;
  });
  if (!sites.length) box.appendChild(h("p", { class: "hint" }, "No remote sites yet (Monitoring → Remote sites)."));
  return { box, value: () => { const ids = boxes.filter((b) => b.checked).map((b) => Number(b.value)); return ids.length ? ids : null; } };
}

function newUserForm(data, refresh) {
  const form = h("form", { class: "edit-form", id: "new-user-form" });
  const name = h("input", { type: "text", name: "username", required: true, autocomplete: "off", maxlength: "32" });
  const password = h("input", { type: "password", name: "password", required: true, autocomplete: "new-password" });
  const role = h("select", { name: "role" });
  for (const r of data.roles) role.appendChild(h("option", { value: r }, ROLE_TEXT[r] || r));
  role.value = "viewer";
  form.appendChild(h("h3", {}, "Add a user"));
  form.appendChild(h("div", { class: "field" }, h("label", {}, "User name"), name));
  form.appendChild(h("div", { class: "field" }, h("label", {}, `Password (at least ${data.min_password} characters)`), password));
  form.appendChild(h("div", { class: "field" }, h("label", {}, "Role"), role));
  const picker = groupPicker(data.groups || [], null);
  const scopeField = h("div", { class: "field" }, h("label", {}, "Only these groups (optional: a customer view that sees nothing else)"), picker.box);
  const sitesPick = sitePicker(data.sites || [], null);
  const siteField = h("div", { class: "field" }, h("label", {}, "Only these remote sites (optional: a customer who sees its own sites and nothing else)"), sitesPick.box);
  const showScope = () => { scopeField.hidden = role.value !== "viewer"; siteField.hidden = role.value !== "viewer" || !(data.sites || []).length; };
  role.addEventListener("change", showScope);
  showScope();
  form.appendChild(scopeField);
  form.appendChild(siteField);
  form.appendChild(h("button", { type: "submit", class: "btn" }, "Add user"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const res = await api("/api/users", { method: "POST", body: { username: name.value, password: password.value, role: role.value, scope: role.value === "viewer" ? picker.value() : null, sites: role.value === "viewer" ? sitesPick.value() : null } });
      toast("User added", "success");
      refresh(res.users);
    } catch (err) {
      toast(err.message || "Could not add the user", "error");
    }
  });
  return form;
}

function userRow(user, data, refresh, shown) {
  const row = h("tr", { class: user.disabled ? "disabled-user" : "" });
  const role = h("select", { "aria-label": `Role of ${user.username}` });
  for (const r of data.roles) role.appendChild(h("option", { value: r }, ROLE_TEXT[r] || r));
  role.value = user.role;
  if (user.last_admin) { role.disabled = true; role.title = "This is the last administrator: make another user an administrator first"; }
  const call = async (request, done) => {
    try {
      const res = await request();
      if (done) toast(done, "success");
      refresh(res.users, res);
    } catch (err) {
      toast(err.message || "Failed", "error");
    }
  };
  role.addEventListener("change", () => call(() => api(`/api/users/${user.id}`, { method: "PATCH", body: { role: role.value } }), "Role changed"));

  const actions = h("td", {});
  const pw = h("button", { type: "button", class: "btn" }, "New password");
  pw.addEventListener("click", () => {
    const value = window.prompt(`New password for ${user.username} (at least ${data.min_password} characters). Their logins end.`);
    if (value) call(() => api(`/api/users/${user.id}`, { method: "PATCH", body: { password: value } }), "Password changed");
  });
  const toggle = h("button", { type: "button", class: "btn" }, user.disabled ? "Enable" : "Disable");
  toggle.addEventListener("click", () => call(() => api(`/api/users/${user.id}`, { method: "PATCH", body: { disabled: !user.disabled } }), user.disabled ? "User enabled" : "User disabled"));
  const del = h("button", { type: "button", class: "btn danger" }, "Delete");
  del.addEventListener("click", () => {
    if (window.confirm(`Delete ${user.username}? Their logins and API tokens stop working.`)) call(() => api(`/api/users/${user.id}`, { method: "DELETE" }), "User deleted");
  });
  const tok = h("button", { type: "button", class: "btn" }, "New API token");
  tok.addEventListener("click", () => {
    const name = window.prompt("What is the token for? (for example Home Assistant)");
    if (!name) return;
    const readonly = window.confirm("Make it read-only?\n\nOK: the token can only read (right for Prometheus, Grafana and dashboards).\nCancel: it acts with the role of its user.");
    call(() => api(`/api/users/${user.id}/tokens`, { method: "POST", body: { name, readonly } }), null);
  });
  if (user.last_admin) for (const b of [toggle, del]) { b.disabled = true; b.title = "This is the last administrator: make another user an administrator first"; }
  const parts = [pw, " ", toggle, " ", tok, " "];
  if (user.role === "viewer") {
    const lim = h("button", { type: "button", class: "btn" }, user.scope ? "Change groups" : "Limit to groups");
    lim.addEventListener("click", () => {
      const picker = groupPicker(data.groups || [], user.scope);
      const save = h("button", { type: "button", class: "btn primary" }, "Save groups");
      save.addEventListener("click", () => call(() => api(`/api/users/${user.id}`, { method: "PATCH", body: { scope: picker.value() } }), picker.value() ? "Limited to those groups" : "No limit"));
      actions.append(h("div", { class: "scope-edit" }, h("p", { class: "hint" }, "Tick the groups this viewer may see. None ticked: everything."), picker.box, save));
      lim.disabled = true;
    });
    parts.push(lim, " ");
    if ((data.sites || []).length) {
      const limSites = h("button", { type: "button", class: "btn" }, user.sites ? "Change sites" : "Limit to sites");
      limSites.addEventListener("click", () => {
        const picker = sitePicker(data.sites || [], user.sites);
        const save = h("button", { type: "button", class: "btn primary" }, "Save sites");
        save.addEventListener("click", () => call(() => api(`/api/users/${user.id}`, { method: "PATCH", body: { sites: picker.value() } }), picker.value() ? "Limited to those sites" : "No site limit"));
        actions.append(h("div", { class: "scope-edit" }, h("p", { class: "hint" }, "Tick the remote sites this viewer may see (a customer view). None ticked: no site limit."), picker.box, save));
        limSites.disabled = true;
      });
      parts.push(limSites, " ");
    }
  }
  parts.push(del);
  actions.append(...parts);

  row.appendChild(h("td", {}, h("strong", {}, user.username), user.disabled ? h("span", { class: "tag" }, "disabled") : null));
  row.appendChild(h("td", {}, role, user.sites ? h("span", { class: "tag", title: "Sees only these remote sites" }, `${user.sites.length} site${user.sites.length === 1 ? "" : "s"}`) : null, user.scope ? h("span", { class: "tag", title: "Sees only the devices of these groups" }, `${user.scope.length} group${user.scope.length === 1 ? "" : "s"}`) : null));
  row.appendChild(h("td", {}, user.last_login ? fmtTime(user.last_login) : "never"));
  row.appendChild(actions);

  const rows = [row];
  for (const t of user.tokens) {
    const remove = h("button", { type: "button", class: "btn danger" }, "Revoke");
    remove.addEventListener("click", () => call(() => api(`/api/users/${user.id}/tokens/${t.id}`, { method: "DELETE" }), "Token revoked"));
    rows.push(h("tr", { class: "token-row" },
      h("td", { colspan: "2" }, `API token "${t.name}"`, t.readonly ? h("span", { class: "tag" }, "read-only") : null),
      h("td", {}, t.last_used ? `used ${fmtTime(t.last_used)}` : "never used"),
      h("td", {}, remove)));
  }
  if (shown && shown.userId === user.id) {
    const box = h("td", { colspan: "4" });
    box.appendChild(h("p", { class: "hint" }, `Token "${shown.name}" — copy it now, it is not shown again:`));
    const code = h("code", { class: "mono new-token" }, shown.token);
    const copy = h("button", { type: "button", class: "btn" }, "Copy");
    copy.addEventListener("click", async () => toast((await copyText(shown.token)) ? "Copied" : "Select the token and copy it by hand", "info"));
    box.append(code, " ", copy);
    rows.push(h("tr", { class: "token-new" }, box));
  }
  return rows;
}

function fill(card, data, shown) {
  clear(card);
  card.appendChild(h("h2", {}, "Users & tokens"));
  card.appendChild(h("p", { class: "hint" },
    "Administrators can change everything. Viewers can look at the map, devices, statistics and services but change nothing and see no settings. " +
    "The NETLENS_TOKEN access token always works as an administrator, so you cannot lock yourself out. " +
    "API tokens are for scripts, Home Assistant and Prometheus. A token acts with the role of its user, unless you make it read-only: then it can only read, whoever owns it."));
  card.appendChild(h("p", { class: data.teams_allowed === false ? "warn-text" : "hint" },
    data.teams_allowed === false
      ? "Operators and customer views (a viewer limited to some groups) are business features: they are part of the Small business and Enterprise editions and the free trial (Settings → Licence). Existing ones keep their limits; an operator acts as a viewer until a licence is applied."
      : "Operators (look and act, no settings) and customer views (a viewer limited to some groups) are business features, part of the Small business and Enterprise editions and the free trial."));
  if (data.token_configured) {
    const haveAdmin = data.users.some((u) => u.role === "admin" && !u.disabled);
    card.appendChild(h("p", { class: "hint", id: "token-note" }, haveAdmin
      ? "NETLENS_TOKEN is still set in your container settings. Now that you have an administrator account you can remove it (and sign in with your user name); it keeps working until you do."
      : "NETLENS_TOKEN is set in your container settings. Create an administrator below and sign in with it; after that you can remove NETLENS_TOKEN, which is no longer needed. Nothing changes until you do."));
  }
  const refresh = (users, res) => {
    const newToken = res && res.token ? { token: res.token, name: users.flatMap((u) => u.tokens).find((t) => t.id === res.id)?.name || "", userId: users.find((u) => u.tokens.some((t) => t.id === res.id))?.id } : null;
    fill(card, { ...data, users }, newToken);
  };
  if (!data.users.length) {
    card.appendChild(h("p", { class: "hint" }, "No users yet. You are using the access token."));
  } else {
    const table = h("table", { class: "table users" });
    table.appendChild(h("thead", {}, h("tr", {}, h("th", {}, "User"), h("th", {}, "Role"), h("th", {}, "Last login"), h("th", {}, ""))));
    const body = h("tbody");
    for (const user of data.users) for (const r of userRow(user, data, refresh, shown)) body.appendChild(r);
    table.appendChild(body);
    card.appendChild(table);
  }
  card.appendChild(newUserForm(data, refresh));
}

export async function buildUsersCard() {
  const card = h("div", { class: "card" });
  const data = await get("/api/users");
  try { data.groups = (await get("/api/groups")).groups; } catch (e) { data.groups = []; }
  data.sites = data.sites || [];
  fill(card, data);
  return card;
}
