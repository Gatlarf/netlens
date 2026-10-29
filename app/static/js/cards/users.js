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
  const customs = (data.custom_roles || []).filter((c) => !user.scope && !user.sites);          // a customer view cannot have a custom role
  if (user.role !== "admin") for (const c of customs) role.appendChild(h("option", { value: `custom:${c.id}` }, `${c.name} (custom, based on ${c.base})`));
  role.value = user.custom_role && customs.some((c) => c.id === user.custom_role) ? `custom:${user.custom_role}` : user.role;
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
  role.addEventListener("change", () => call(() => api(`/api/users/${user.id}`, { method: "PATCH", body: role.value.startsWith("custom:") ? { custom_role: role.value.slice(7) } : { role: role.value, custom_role: "" } }), "Role changed"));

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
    const body = { name, readonly };
    const policy = data.token_policy || {};
    if (policy.max_days || policy.may_restrict) {
      const days = window.prompt(`How many days may the token be used?${policy.max_days ? ` (at most ${policy.max_days})` : " Leave empty for no end."}`, policy.max_days ? String(policy.max_days) : "");
      if (days === null) return;
      if (days.trim()) body.expires_days = Number(days);
      if (policy.may_restrict) {
        const where = window.prompt("Only from these addresses or networks (comma separated, for example 10.0.0.0/24). Leave empty for anywhere.", "");
        if (where === null) return;
        if (where.trim()) body.allowed_ips = where.split(",").map((x) => x.trim()).filter(Boolean);
      }
    }
    call(() => api(`/api/users/${user.id}/tokens`, { method: "POST", body }), null);
  });
  if (user.last_admin) for (const b of [toggle, del]) { b.disabled = true; b.title = "This is the last administrator: make another user an administrator first"; }
  const parts = [pw, " ", toggle, " ", tok, " "];
  if (user.totp) {
    const reset = h("button", { type: "button", class: "btn", title: "For a user who lost the authenticator and the recovery codes" }, "Reset 2FA");
    reset.addEventListener("click", async () => {
      let mine = { enabled: false };
      try { mine = await api("/api/me/totp"); } catch { /* the access token has no second factor: the server explains */ }
      const proof = window.prompt(mine.enabled ? `Reset the second factor of ${user.username}? Enter a code from your own authenticator to confirm.` : `Reset the second factor of ${user.username}? Enter your own password to confirm.`);
      if (!proof) return;
      call(() => api(`/api/users/${user.id}/totp/reset`, { method: "POST", body: mine.enabled ? { code: proof } : { password: proof } }), "Second factor reset: their sessions ended");
    });
    parts.push(reset, " ");
  }
  if (user.role === "admin" && data.privileged_allowed !== false) {
    const bg = h("button", { type: "button", class: "btn", title: "A local administrator who may still sign in with a password when password sign-in is limited to break-glass accounts. Needs a second factor; every use raises a critical event." }, user.break_glass ? "Not break-glass" : "Make break-glass");
    bg.addEventListener("click", () => call(() => api(`/api/users/${user.id}`, { method: "PATCH", body: { break_glass: !user.break_glass } }), user.break_glass ? "No longer a break-glass account" : "Marked as a break-glass account"));
    parts.push(bg, " ");
  }
  const sess = h("button", { type: "button", class: "btn", title: "Enterprise: see and end the sessions of this user" }, "Sessions");
  sess.addEventListener("click", async () => {
    try {
      const r = await api(`/api/users/${user.id}/sessions`);
      const list = r.sessions.map((x) => `${x.ip || "?"} · ${x.method || "-"} · last used ${x.last_seen}`).join("\n") || "No active sessions.";
      if (r.sessions.length && window.confirm(`${user.username} is signed in:\n\n${list}\n\nEnd all of these sessions?`)) call(() => api(`/api/users/${user.id}/sessions/end`, { method: "POST", body: {} }), "Sessions ended");
      else if (!r.sessions.length) window.alert(list);
    } catch (err) { toast(err.message || "Failed", "error"); }
  });
  parts.push(sess, " ");
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

  row.appendChild(h("td", {}, h("strong", {}, user.username), user.disabled ? h("span", { class: "tag" }, "disabled") : null, user.totp ? h("span", { class: "tag ok", title: "Signs in with a code from an authenticator app" }, "2FA") : null, user.break_glass ? h("span", { class: "tag warn", title: "Break-glass account: may sign in with a password when that is limited; each use raises a critical event" }, "break-glass") : null));
  row.appendChild(h("td", {}, role, user.sites ? h("span", { class: "tag", title: "Sees only these remote sites" }, `${user.sites.length} site${user.sites.length === 1 ? "" : "s"}`) : null, user.scope ? h("span", { class: "tag", title: "Sees only the devices of these groups" }, `${user.scope.length} group${user.scope.length === 1 ? "" : "s"}`) : null));
  row.appendChild(h("td", {}, user.last_login ? fmtTime(user.last_login) : "never"));
  row.appendChild(actions);

  const rows = [row];
  for (const t of user.tokens) {
    const remove = h("button", { type: "button", class: "btn danger" }, "Revoke");
    remove.addEventListener("click", () => call(() => api(`/api/users/${user.id}/tokens/${t.id}`, { method: "DELETE" }), "Token revoked"));
    rows.push(h("tr", { class: "token-row" },
      h("td", { colspan: "2" }, `API token "${t.name}"`, t.readonly ? h("span", { class: "tag" }, "read-only") : null, t.expires ? h("span", { class: "tag", title: "The token stops working then" }, `ends ${t.expires.slice(0, 10)}`) : null, t.allowed_ips ? h("span", { class: "tag", title: "Only usable from these addresses" }, t.allowed_ips) : null),
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
