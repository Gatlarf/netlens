import { api, get } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";

const ROLE_TEXT = { admin: "Administrator (everything)", viewer: "Viewer (read-only)" };

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    return false;
  }
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
  form.appendChild(h("button", { type: "submit", class: "btn" }, "Add user"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const res = await api("/api/users", { method: "POST", body: { username: name.value, password: password.value, role: role.value } });
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
    if (name) call(() => api(`/api/users/${user.id}/tokens`, { method: "POST", body: { name } }), null);
  });
  actions.append(pw, " ", toggle, " ", tok, " ", del);

  row.appendChild(h("td", {}, h("strong", {}, user.username), user.disabled ? h("span", { class: "tag" }, "disabled") : null));
  row.appendChild(h("td", {}, role));
  row.appendChild(h("td", {}, user.last_login ? fmtTime(user.last_login) : "never"));
  row.appendChild(actions);

  const rows = [row];
  for (const t of user.tokens) {
    const remove = h("button", { type: "button", class: "btn danger" }, "Revoke");
    remove.addEventListener("click", () => call(() => api(`/api/users/${user.id}/tokens/${t.id}`, { method: "DELETE" }), "Token revoked"));
    rows.push(h("tr", { class: "token-row" },
      h("td", { colspan: "2" }, `API token "${t.name}"`),
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
    "API tokens are for scripts, Home Assistant and Prometheus and act with the role of their user: give Home Assistant a viewer's token."));
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
  fill(card, await get("/api/users"));
  return card;
}
