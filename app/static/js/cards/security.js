import { get, put } from "../api.js";
import { h, clear, toast } from "../util.js";

// Settings → Sign-in security: who must have a second factor (Small business and Enterprise) and how long a session may live (Enterprise).
export async function buildSecurityCard() {
  const card = h("div", { class: "card admin-only" });
  async function draw(info) {
    clear(card);
    const p = info.policy;
    card.appendChild(h("h2", {}, "Sign-in security"));
    card.appendChild(h("p", { class: "hint" },
      "A second factor (a code from an authenticator app) is free for every user to set up under Settings → Account. Here an administrator can require it, and limit how long a sign-in lasts. A setting stays in force when a licence ends; only changing it needs the edition."));

    // ---- requiring a second factor ------------------------------------------------------------------------------------------------------
    card.appendChild(h("h3", {}, "Require a second factor"));
    if (!info.allowed.mfa_policy) card.appendChild(h("p", { class: "warn-text" }, "Part of the Small business and Enterprise editions, and the free trial (Settings → Licence)."));
    const require = h("select", { "aria-label": "Who must use a second factor" },
      ...[["off", "Nobody (each user decides)"], ["admins", "Administrators"], ["operators", "Administrators and operators"], ["everyone", "Everyone"]].map(([v, t]) => h("option", { value: v, selected: v === p.require_totp }, t)));
    const grace = h("input", { type: "number", min: "0", max: "365", value: String(p.grace_days), style: "width:6em", "aria-label": "Days to set it up" });
    card.append(h("div", { class: "field" }, h("label", {}, "Who"), require,
        h("div", { class: "hint" }, "Users who sign in through single sign-on are not asked: their identity provider does that. API tokens are not interactive and have no second factor.")),
      h("div", { class: "field" }, h("label", {}, "Days to set it up"), grace,
        h("div", { class: "hint" }, "After the policy is switched on (or the account is made) a user may still sign in without one for this long. After that only the page that sets it up opens, until it is set up.")));
    if (info.without_second_factor.length) card.appendChild(h("p", { class: "hint" }, `Not set up yet (${info.without_second_factor.length}): ${info.without_second_factor.join(", ")}`));
    else if (p.require_totp !== "off") card.appendChild(h("p", { class: "hint" }, "Everybody the policy applies to has a second factor."));
    card.appendChild(h("p", { class: "hint" }, `${info.users.with_second_factor} of ${info.users.total} users have a second factor.`));

    // ---- sessions ------------------------------------------------------------------------------------------------------------------------
    card.appendChild(h("h3", {}, "Sessions"));
    if (!info.allowed.privileged) card.appendChild(h("p", { class: "warn-text" }, "Session limits are part of the Enterprise edition and the free trial (Settings → Licence)."));
    const num = (value, max, label) => h("input", { type: "number", min: "0", max: String(max), value: String(value), style: "width:6em", "aria-label": label });
    const idle = num(p.idle_minutes, 1440, "Minutes without activity");
    const absolute = num(p.absolute_hours, 720, "Hours in all");
    const most = num(p.max_sessions, 50, "Most sessions per user");
    card.append(h("div", { class: "field" }, h("label", {}, "Sign out after this many minutes without activity"), idle, h("div", { class: "hint" }, "0 = never. 30 is a common choice.")),
      h("div", { class: "field" }, h("label", {}, "Sign out this many hours after signing in"), absolute, h("div", { class: "hint" }, "0 = the default of 30 days. 12 is a common choice.")),
      h("div", { class: "field" }, h("label", {}, "Most sessions per user"), most, h("div", { class: "hint" }, "0 = no limit. A new sign-in ends the oldest ones beyond this number.")));

    // ---- privileged actions ---------------------------------------------------------------------------------------------------------------
    card.appendChild(h("h3", {}, "Privileged actions"));
    if (!info.allowed.privileged) card.appendChild(h("p", { class: "warn-text" }, "Part of the Enterprise edition and the free trial (Settings → Licence)."));
    const stepUp = h("input", { type: "checkbox" });
    stepUp.checked = p.step_up;
    const stepMinutes = num(p.step_up_minutes, 120, "Minutes a confirmation lasts");
    stepMinutes.min = "1";
    card.append(h("label", { class: "check" }, stepUp, " Ask for a fresh confirmation before a privileged action"),
      h("div", { class: "hint" }, "Opening a terminal or remote session, changing the credential store, users, tokens, single sign-on, plugins, host set-up, backups and restore, and reading the master key. A person confirms with a code from their authenticator (or their password if they have none, or the identity provider for single sign-on). The access token and API tokens cannot confirm, so with this on they are refused for these actions."),
      h("div", { class: "field" }, h("label", {}, "A confirmation lasts (minutes)"), stepMinutes, h("div", { class: "hint" }, "10 is a common choice.")));

    // ---- the access token, password sign-in, API tokens ---------------------------------------------------------------------------------
    const sel = (value, options, label) => h("select", { "aria-label": label }, ...options.map(([v, t]) => h("option", { value: v, selected: v === value }, t)));
    const staticToken = sel(p.static_token, [["allowed", "Allowed"], ["lan", "Only from the local network"], ["off", "Switched off"]], "Access token");
    const localLogin = sel(p.local_login, [["allowed", "Allowed for everyone"], ["break_glass_only", "Only break-glass accounts (everyone else uses single sign-on)"]], "Password sign-in");
    const tokenDays = num(p.api_token_max_days, 3650, "Longest life of an API token (days)");
    const minPassword = num(p.min_password, 64, "Shortest new password");
    minPassword.min = "8";
    card.append(h("h3", {}, "Standing logins"),
      h("div", { class: "field" }, h("label", {}, "Access token (NETLENS_TOKEN)"), staticToken,
        h("div", { class: "hint" }, info.token_configured ? "This install has an access token in its environment. It signs in as administrator without a user name or a second factor. Better: remove it from the container's environment; here you can switch it off or limit it to the local network." : "This install has no access token; nothing to limit.")),
      h("div", { class: "field" }, h("label", {}, "Password sign-in"), localLogin,
        h("div", { class: "hint" }, "Needs single sign-on to be set up, and at least one administrator marked break-glass (Users & tokens) who has a second factor: that account stays the way in when single sign-on fails. Each use of it raises a critical event.")),
      h("div", { class: "field" }, h("label", {}, "Shortest new password (characters)"), minPassword, h("div", { class: "hint" }, "The built-in minimum is 8. The most used passwords and trivial patterns are always refused. 12 or more is a common choice.")),
      h("div", { class: "field" }, h("label", {}, "Longest life of a new API token (days)"), tokenDays, h("div", { class: "hint" }, "0 = no limit. A token made later gets this life unless a shorter one is chosen; it can also be limited to some addresses (Users & tokens).")));

    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      save.disabled = true;
      try {
        const body = { require_totp: require.value, grace_days: Number(grace.value), idle_minutes: Number(idle.value), absolute_hours: Number(absolute.value), max_sessions: Number(most.value),
          step_up: stepUp.checked, step_up_minutes: Number(stepMinutes.value), static_token: staticToken.value, local_login: localLogin.value, api_token_max_days: Number(tokenDays.value), min_password: Number(minPassword.value) };
        draw(await put("/api/security-policy", body));
        toast("Saved", "success");
      } catch (err) { toast(err.message || "Could not save", "error"); save.disabled = false; }
    });
    card.appendChild(h("div", { class: "form-actions" }, save));
  }
  await draw(await get("/api/security-policy"));
  return card;
}
