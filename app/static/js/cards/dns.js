import { get, post, put } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

const STATE_LABEL = {
  add: "To add", update: "To update", delete: "To remove", conflict: "Conflict", wait: "Waiting", self: "Registers itself",
  ok: "Registered", skip: "Skipped", orphan: "Left over",
};
const STATE_HELP = {
  add: "Netlens would create this record.",
  update: "Netlens would change a record it created.",
  delete: "Netlens would remove a record it created.",
  conflict: "Another record uses this name or address. Netlens leaves it alone.",
  wait: "Missing from DNS, but Netlens waits in case the device registers itself.",
  self: "The device (or something else) registered this address itself.",
  ok: "Already correct.",
  skip: "Not registered, see the reason.",
  orphan: "A record Netlens made that no device wants any more.",
};
const ORDER = ["conflict", "add", "update", "delete", "wait", "orphan", "skip", "self", "ok"];
const ACTIONABLE = new Set(["add", "update", "delete"]);

function field(label, input, hint) {
  return h("div", { class: "field" }, h("label", {}, label), input, hint ? h("p", { class: "hint" }, hint) : null);
}

function checkbox(name, checked, label, hint) {
  const input = h("input", { type: "checkbox", name, checked });
  return h("div", { class: "field" }, h("label", { class: "check" }, input, ` ${label}`), hint ? h("p", { class: "hint" }, hint) : null);
}

function describeChange(c) {
  const verb = { add: "add", update: "change", delete: "remove" }[c.action];
  const what = c.type === "PTR" ? `reverse record ${c.name.split(".").slice(0, 4).join(".")}…` : `${c.type} record`;
  return `${verb} ${what}${c.old_value ? ` (${c.old_value} → ${c.value})` : c.type === "PTR" ? "" : ` → ${c.value}`}`;
}

// mode "page": the preview of what would be registered (the DNS page); mode "settings": the rules for registering (Settings -> DNS registration)
export async function buildDnsCard(mode = "page") {
  const card = h("div", { class: "card", id: "dns-card" });
  const state = await get("/api/dns");
  render(card, state, mode);
  return card;
}

function render(card, state, mode = "page") {
  clear(card);
  if (mode === "settings") card.appendChild(h("h2", {}, "DNS registration"));
  card.appendChild(h("p", { class: "hint" },
    mode === "settings"
      ? "Netlens can register the devices it knows in your DNS server, and keep the address right when a device gets a new one from DHCP. It only ever changes records it created itself (marked with a comment) and never touches records that something else made, such as a Windows machine that registers itself."
      : "It only ever changes records it created itself (marked with a comment) and never touches records that something else made. Nothing is written before you approve it here. The rules (networks, zones, what to register) are under ",
    mode === "settings" ? null : h("a", { href: "#/settings/dns" }, "Settings → DNS registration"), mode === "settings" ? null : "."));

  if (!state.plugins.length) {
    card.appendChild(h("p", {}, "No DNS plugin is installed yet. Install one under ", h("a", { href: "#/settings/plugin-browse" }, "Settings → Plugin store"), " (for example Technitium DNS)."));
    return;
  }
  const active = state.plugins.find((p) => p.id === state.plugin);
  if (!active || !active.enabled) {
    card.appendChild(h("p", { class: "error" }, "The DNS plugin is not turned on. Open its page under Integrations, enter the server and token, and turn it on."));
  }

  // ---- settings
  const form = h("form", { class: "edit-form", id: "dns-settings" });
  const s = state.settings;
  const networks = h("textarea", { name: "networks", rows: "3", placeholder: "192.168.0.0/24 = home.example.com", id: "dns-networks" });
  networks.value = s.networks || "";
  form.appendChild(field("Networks and zones", networks, "One line per network: the network, an equals sign and the DNS zone its devices go in. With a single zone you can just write the zone name. A device is registered in the zone of the network its address belongs to."));
  const pluginSelect = h("select", { name: "plugin" }, ...state.plugins.map((p) => h("option", { value: p.id }, `${p.name}${p.enabled ? "" : " (off)"}`)));
  pluginSelect.value = state.plugin || "";
  if (state.plugins.length > 1) form.appendChild(field("DNS plugin", pluginSelect));
  const grace = h("input", { type: "number", name: "grace_hours", min: "0", max: "168", step: "0.5", value: String(s.grace_hours) });
  form.appendChild(field("Wait before registering (hours)", grace, "A device without a DNS record is registered only after this long, so a device that registers itself (Windows) gets there first. 0 registers at once."));
  const known = checkbox("only_known", s.only_known, "Only register known devices", "A new device must be marked as known first, so nobody can claim a name just by announcing it.");
  const windows = checkbox("skip_windows", s.skip_windows, "Leave Windows machines alone", "They register themselves. Set a device to 'Always register' on its page to register one anyway.");
  const template = h("input", { type: "text", name: "template", value: s.template });
  form.append(known, windows, field("Name for devices without one", template, "A pattern with {type}, {vendor}, {mac4}, {mac6} and {ip}, for example tv-samsung-a1b2. A generated name stays the same afterwards. You can set a DNS name by hand on the device's page."));
  const offline = h("input", { type: "number", name: "max_offline_days", min: "1", max: "3650", value: String(s.max_offline_days) });
  form.appendChild(field("Ignore devices not seen for (days)", offline));
  const containers = checkbox("register_containers", s.register_containers, "Give containers that share their host's address a name", "A running Docker container on a bridge or host network that publishes a port gets a CNAME to its host (for example web.home.example.com pointing to the host). Containers with their own address are devices and are registered like any other.");
  const sites = checkbox("register_sites", s.register_sites, "Give the sites of a reverse proxy a name", "The domains your reverse proxy (Nginx Proxy Manager) publishes that fall inside one of your zones get a CNAME to the proxy's host, so they resolve inside your network. Names that already exist in DNS are left alone.");
  const remove = checkbox("remove", s.remove, "Remove records of devices that are gone", "Only records Netlens created, and only with the plugin account allowed to delete. Off by default: leftovers are just listed.");
  const auto = checkbox("auto_apply", s.auto_apply, "Apply automatically after every scan", "Adds missing and changed records without asking (never removes any). Turn it on when you have seen that the preview is what you want.");
  const limit = h("input", { type: "number", name: "max_changes", min: "1", max: "500", value: String(s.max_changes) });
  form.append(containers, sites, remove, auto, field("Most changes per run", limit, "A safety limit: a bigger plan needs approving in smaller parts."));
  const save = h("button", { type: "submit", class: "btn primary", id: "dns-save" }, "Save");
  form.appendChild(save);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const val = (n) => form.elements[n];
    const body = {
      networks: val("networks").value, grace_hours: Number(val("grace_hours").value), only_known: val("only_known").checked, skip_windows: val("skip_windows").checked,
      template: val("template").value, max_offline_days: Number(val("max_offline_days").value), remove: val("remove").checked, register_containers: val("register_containers").checked, register_sites: val("register_sites").checked, auto_apply: val("auto_apply").checked,
      max_changes: Number(val("max_changes").value),
    };
    if (state.plugins.length > 1) body.plugin = pluginSelect.value;
    save.disabled = true;
    try {
      render(card, await put("/api/dns/settings", body), mode);
      toast("DNS settings saved", "success");
    } catch (err) {
      toast(err.message || "Could not save", "error");
      save.disabled = false;
    }
  });
  if (mode === "settings") {
    form.classList.add("dns-form");
    card.appendChild(form);
    card.appendChild(h("p", { class: "hint" }, "The preview of what Netlens would register, and the button to apply it, are on the ", h("a", { href: "#/dns" }, "DNS page"), "."));
    return;
  }

  // ---- the server and the preview
  card.appendChild(h("h3", {}, "What Netlens would do"));
  const bar = h("div", { class: "btn-row" });
  const refresh = h("button", { type: "button", class: "btn", id: "dns-refresh" }, "Read the DNS server now");
  bar.appendChild(refresh);
  refresh.addEventListener("click", async () => {
    refresh.disabled = true;
    refresh.textContent = "Reading…";
    try {
      render(card, await post("/api/dns/refresh"), mode);
      toast("DNS server read", "success");
    } catch (err) {
      toast(err.message || "Could not read the DNS server", "error");
      refresh.disabled = false;
      refresh.textContent = "Read the DNS server now";
    }
  });
  card.appendChild(bar);

  if (state.status && state.status.ok === false) card.appendChild(h("p", { class: "error", id: "dns-error" }, `The plugin failed: ${state.status.error}`));
  if (state.snapshot) {
    const w = state.snapshot.writable.length ? `writable zones: ${state.snapshot.writable.join(", ")}` : "no zone is writable for this account";
    card.appendChild(h("p", { class: "hint", id: "dns-snapshot" }, `Read ${state.snapshot.records} records in ${state.snapshot.zones} zones (${state.snapshot.managed} made by Netlens), ${w}${state.status && state.status.ts ? `, ${timeAgo(state.status.ts)}` : ""}.`));
  }
  if (state.needs_setup) {
    card.appendChild(h("p", { class: "hint" }, "First enter your network and zone under ", h("a", { href: "#/settings/dns" }, "Settings → DNS registration"), ", then read the DNS server."));
    return;
  }
  if (!state.plan) {
    card.appendChild(h("p", { class: "hint" }, state.plan_error || "Read the DNS server to see the preview."));
    return;
  }
  renderPlan(card, state);
}

function renderPlan(card, state) {
  const plan = state.plan;
  const counts = h("div", { class: "dns-counts", id: "dns-counts" });
  let filter = "";
  const applyFilter = () => {
    for (const r of card.querySelectorAll("tr.dns-row")) r.hidden = filter ? r.dataset.state !== filter : (r.classList.contains("ok") || r.classList.contains("self")) && !(card.querySelector("#dns-show-ok") || {}).checked && r.dataset.settled === "1";
    for (const c of counts.children) c.classList.toggle("active", c.dataset.key === filter);
  };
  for (const key of ORDER) {
    if (plan.counts[key]) {
      const chip = h("button", { type: "button", class: `dns-chip ${key}`, title: `${STATE_HELP[key]} Click to show only these.`, "data-key": key,
        onclick: () => { filter = filter === key ? "" : key; applyFilter(); } }, `${plan.counts[key]} ${STATE_LABEL[key].toLowerCase()}`);
      counts.appendChild(chip);
    }
  }
  card.appendChild(counts);
  if (!plan.items.length) {
    card.appendChild(h("p", { class: "hint" }, "No device is in the networks above."));
    return;
  }
  const boxes = [];
  const table = h("table", { class: "table dns-plan", id: "dns-plan" });
  table.appendChild(h("thead", {}, h("tr", {}, ["", "Device", "DNS name", "Address", "State", "Why / what"].map((t) => h("th", {}, t)))));
  const body = h("tbody");
  for (const item of plan.items) {
    const actionable = ACTIONABLE.has(item.state) && item.changes.length > 0;
    const box = h("input", { type: "checkbox", "aria-label": `Apply ${item.name}`, checked: actionable, disabled: !actionable });
    box.dataset.ids = JSON.stringify(item.changes.map((c) => c.id));
    boxes.push(box);
    const device = item.device_id ? h("a", { href: `#/device/${item.device_id}` }, item.device || `device ${item.device_id}`) : h("span", { class: "hint" }, "—");
    const why = h("div", {}, h("span", {}, item.reason), ...item.changes.map((c) => h("div", { class: "hint dns-change" }, describeChange(c))));
    body.appendChild(h("tr", { class: `dns-row ${item.state}`, "data-state": item.state },
      h("td", {}, box), h("td", {}, device), h("td", { class: "mono" }, item.name || ""), h("td", { class: "mono" }, item.ip || ""),
      h("td", {}, h("span", { class: `dns-chip ${item.state}`, title: STATE_HELP[item.state] }, STATE_LABEL[item.state])), h("td", {}, why)));
  }
  table.appendChild(body);
  // what is already right is out of the way until asked for: the list then shows what needs a look
  const settled = [...body.querySelectorAll("tr.dns-row.ok, tr.dns-row.self")];
  if (settled.length && settled.length < plan.items.length) {
    const toggle = h("input", { type: "checkbox", id: "dns-show-ok" });
    for (const r of settled) r.dataset.settled = "1";
    toggle.addEventListener("change", applyFilter);
    card.appendChild(h("label", { class: "check dns-show-ok" }, toggle, ` Also show the ${settled.length} that are already right`));
  }
  card.appendChild(h("div", { class: "table-wrap" }, table));
  applyFilter();

  const actionable = boxes.filter((b) => !b.disabled);
  if (actionable.length) {
    const apply = h("button", { type: "button", class: "btn primary", id: "dns-apply" }, "Apply the selected changes");
    const status = h("span", { class: "hint", id: "dns-apply-status" }, `${actionable.length} item(s) selected. The preview changes nothing; this button writes to the DNS server.`);
    apply.addEventListener("click", async () => {
      const ids = actionable.filter((b) => b.checked).flatMap((b) => JSON.parse(b.dataset.ids));
      if (!ids.length) {
        toast("Nothing selected", "info");
        return;
      }
      apply.disabled = true;
      apply.textContent = "Writing…";
      try {
        const res = await post("/api/dns/apply", { ids });
        const failed = res.results.filter((r) => !r.ok);
        toast(failed.length ? `${res.results.length - failed.length} written, ${failed.length} failed: ${failed[0].error}` : `${res.results.length} change(s) written`, failed.length ? "error" : "success");
        render(card, res);
      } catch (err) {
        toast(err.message || "Could not write to DNS", "error");
        apply.disabled = false;
        apply.textContent = "Apply the selected changes";
      }
    });
    card.appendChild(h("div", { class: "btn-row" }, apply, status));
  }
}
