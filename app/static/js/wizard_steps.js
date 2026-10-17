// The steps of the getting-started guide. Each one is a small, plain form with the recommended answer filled in;
// the full settings cards stay in Settings (every step links to them). A step is { title, intro, more, build }:
// build() returns { el, commit? } and commit() runs when the user moves on (it may throw a message to stay on the step).
import { api, get, post, put } from "./api.js";
import { h, shortName } from "./util.js";

const link = (href, text) => h("a", { href }, text);
const card = (...children) => h("div", { class: "card wiz-card" }, ...children);
const check = (input, text, hint) => h("div", { class: "field" }, h("label", { class: "check" }, input, ` ${text}`), hint ? h("p", { class: "hint" }, hint) : null);
const tick = (checked) => { const i = h("input", { type: "checkbox" }); i.checked = checked; return i; };
const say = (text) => h("p", {}, text);

// What "Only important things" means for the alert step
export const IMPORTANT = ["device_new", "device_offline", "service_down", "dhcp_rogue", "gateway_changed", "cert_expiring", "login_failed"];

// ---------- 2. network
async function networkStep() {
  const cfg = await get("/api/config");
  const detected = cfg.detected_ranges || [];
  const current = cfg.ranges && cfg.ranges.length ? cfg.ranges : detected;
  const input = h("input", { type: "text", value: current.join(", "), placeholder: "192.168.1.0/24", autocomplete: "off", "aria-label": "Networks to scan" });
  const el = card(
    say(detected.length
      ? "Netlens found the network below and will look for devices on it. If that is your home or office network, just continue."
      : "Netlens could not find your network by itself. Type it below, for example 192.168.1.0/24. If you are unsure, leave it empty and continue."),
    h("div", { class: "field" }, h("label", {}, "Network to scan"), input,
      h("p", { class: "hint" }, "Several networks can be separated by commas.")));
  return {
    el,
    async commit() {
      const wanted = input.value.split(/[\s,;]+/).filter(Boolean);
      const same = wanted.join(",") === current.join(",");
      if (same) return;
      try {
        await put("/api/config/ranges", { ranges: wanted });
      } catch (err) {
        throw new Error(err.message || "Those networks were not accepted. Use the form 192.168.1.0/24.");
      }
    },
  };
}

// ---------- 3. names
async function namesStep() {
  let passive = null;
  try { passive = await get("/api/passive"); } catch (err) { /* not available here (for example in the demo) */ }
  let dns = null;
  try { dns = await get("/api/dns"); } catch (err) { /* only a remark */ }
  const box = tick(passive ? passive.enabled : false);
  let dnsText = "Netlens can also add the names it learns to your own DNS server (for example Technitium) so you can use them everywhere. That needs a DNS plugin and is not needed to get started.";
  if (dns && dns.plugins.length) {
    const active = dns.plugins.find((p) => p.id === dns.plugin);
    dnsText = active && active.enabled
      ? `Your DNS server (${active.name}) is connected. Netlens only changes it after you approve each change in Network → DNSation.`
      : "A DNS plugin is installed but switched off. You can turn it on later under Settings → Plugins.";
  }
  return {
    el: card(
      say("Many devices tell the network their name when they join. Netlens can listen for that quietly, without sending anything, so your list shows “Living room TV” instead of a number."),
      passive ? check(box, "Listen for device names (recommended)") : h("p", { class: "hint" }, "Listening for device names is not available on this installation."),
      h("p", { class: "hint" }, dnsText)),
    async commit() {
      if (passive && box.checked !== passive.enabled) await put("/api/passive", { enabled: box.checked }).catch(() => { throw new Error("Could not change listening. It needs the container permission NET_RAW."); });
    },
  };
}

// ---------- 4. always-on
async function alwaysOnStep() {
  const rows = (await get("/api/uptime/core")).devices;
  const picked = new Set(rows.filter((r) => r.always_on).map((r) => r.id));
  const listed = rows.filter((r) => r.suggested || picked.has(r.id));
  const original = [...picked].sort().join(",");
  if (!listed.length) {
    return { el: card(say("Netlens needs a few days of history before it can suggest which devices run all day. You can choose them later on the Uptime page; nothing to do now.")) };
  }
  const count = h("strong", {});
  const boxes = [];
  const update = () => { count.textContent = `${picked.size} selected`; };
  const list = h("div", { class: "up-choose-list" });
  for (const r of listed) {
    const box = tick(picked.has(r.id));
    box.addEventListener("change", () => { if (box.checked) picked.add(r.id); else picked.delete(r.id); update(); });
    boxes.push([r, box]);
    list.append(h("label", { class: "up-choose-row" }, box,
      h("span", { class: "up-choose-name" }, shortName(r.name), r.ip ? h("span", { class: "mono hint" }, ` ${r.ip}`) : null),
      h("span", { class: "hint" }, r.type)));
  }
  update();
  const all = h("button", { class: "btn", type: "button", onclick: () => { for (const [r, b] of boxes) { b.checked = true; picked.add(r.id); } update(); } }, "Select all");
  return {
    el: card(
      say("Some devices should be on all day: the router, switches, cameras, servers. Mark them and Netlens reports their availability separately, so a phone that leaves home does not pull the figure down."),
      say("These look like they run all day:"), list, h("p", {}, all, " ", count)),
    async commit() {
      if ([...picked].sort().join(",") === original) return;
      await put("/api/uptime/core", { device_ids: [...picked] });
    },
  };
}

// ---------- 5. alerts
const WAYS = [
  ["email", "E-mail", "A message in your inbox"],
  ["ntfy", "Phone notification", "Free app, no account needed (ntfy)"],
  ["telegram", "Telegram", "A message from your own bot"],
  ["discord", "Discord", "A message in a channel"],
];
const randomTopic = () => `netlens-${Array.from(crypto.getRandomValues(new Uint8Array(6)), (b) => b.toString(36).padStart(2, "0")).join("").slice(0, 10)}`;

async function alertsStep() {
  const overview = await get("/api/notify-channels");
  const existing = overview.channels.filter((c) => c.enabled);
  let way = "later", created = null, preset = "important";
  const formBox = h("div", {});
  const result = h("p", { class: "hint", "aria-live": "polite" }, "");
  const tiles = h("div", { class: "wiz-tiles" });

  const fieldBox = (spec, type) => {
    const f = spec;
    let input;
    if (f.kind === "select") {
      input = h("select", { name: f.key }, f.options.map(([v, label]) => h("option", { value: v }, label)));
      input.value = f.default || f.options[0][0];
    } else {
      input = h("input", { type: f.secret ? "password" : f.kind === "number" ? "number" : "text", name: f.key, autocomplete: "off", value: f.default || "" });
      if (type === "ntfy" && f.key === "topic") input.value = randomTopic();
      if (type === "ntfy" && f.key === "server") input.value = "https://ntfy.sh";
    }
    return [f, input, h("div", { class: "field" }, h("label", {}, f.label + (f.required ? "" : " (optional)")), input, f.help ? h("p", { class: "hint" }, f.help) : null)];
  };

  let inputs = [];
  function drawForm() {
    inputs = [];
    formBox.replaceChildren();
    if (way === "later") return;
    const spec = overview.types[way];
    const main = h("div", {}), more = h("details", {}, h("summary", {}, "More options"));
    const wanted = (f) => f.required || (way === "email" && ["username", "password"].includes(f.key));
    const order = way === "email" ? ["to_addrs", "from_addr", "smtp_host", "username", "password"] : [];
    const fields = [...spec.fields].sort((a, b) => (order.indexOf(a.key) + 99) % 99 - (order.indexOf(b.key) + 99) % 99);
    for (const f of fields) {
      const [, input, wrap] = fieldBox(f, way);
      inputs.push([f, input]);
      (wanted(f) ? main : more).append(wrap);
    }
    if (way === "ntfy") main.append(h("p", { class: "hint" }, "Install the free ntfy app on your phone and subscribe to the topic above (it was made up for you). Nobody else can guess it."));
    if (!more.querySelector(".field")) more.hidden = true;
    const presetBox = h("div", { class: "field" }, h("label", {}, "What should it tell you?"),
      ...[["important", "Only important things (recommended)", "New unknown devices, devices going offline, services down, a second DHCP server, certificate and login problems."],
          ["everything", "Everything", "Every kind of event, including ports, IP changes and so on. Can be a lot."]].map(([value, label, hint]) => {
        const r = h("input", { type: "radio", name: "wiz-preset", value });
        r.checked = value === preset;
        r.addEventListener("change", () => { preset = value; });
        return h("label", { class: "wiz-radio" }, r, h("span", {}, ` ${label}`), h("span", { class: "hint" }, hint));
      }));
    const test = h("button", { class: "btn", type: "button", onclick: async (e) => {
      e.target.disabled = true;
      result.className = "hint";
      result.textContent = "Sending…";
      try {
        await save();
        await post(`/api/notify-channels/${created}/test`, {});
        result.textContent = "Test sent. Check your inbox or phone.";
      } catch (err) {
        result.className = "error";
        result.textContent = err.message || "The test failed";
      }
      e.target.disabled = false;
    } }, "Send a test message");
    formBox.append(main, more, presetBox, h("p", {}, test), result);
  }

  async function save() {
    const settings = {};
    for (const [f, input] of inputs) settings[f.key] = input.value;
    const events = preset === "everything" ? overview.events.map((e) => e.key) : IMPORTANT;
    if (created) {
      await put(`/api/notify-channels/${created}`, { settings, events });
    } else {
      created = (await post("/api/notify-channels", { type: way, name: overview.types[way].label, settings, events })).id;
    }
  }

  for (const [key, label, hint] of [...WAYS, ["later", "Not now", "I will set this up later"]]) {
    const r = h("input", { type: "radio", name: "wiz-way", value: key });
    r.checked = key === way;
    r.addEventListener("change", () => { way = key; created = null; result.textContent = ""; drawForm(); });
    tiles.append(h("label", { class: "wiz-tile" }, r, h("strong", {}, label), h("span", { class: "hint" }, hint)));
  }

  const intro = existing.length
    ? card(say(`You already have ${existing.length === 1 ? "an alert channel" : `${existing.length} alert channels`}: ${existing.map((c) => c.name).join(", ")}. You can add another way below, or just continue.`))
    : null;
  return {
    el: h("div", { class: "wiz-body" }, intro,
      card(say("When something needs your attention, such as a new unknown device, Netlens can tell you. How would you like to hear about it?"), tiles, formBox)),
    async commit() {
      if (way === "later") return;
      // nothing typed in: the same as \u201cNot now\u201d
      if (!created && inputs.filter(([f]) => f.required).every(([, input]) => !input.value.trim())) return;
      try {
        await save();
      } catch (err) {
        throw new Error(err.message || "That did not work. Check the fields above, or choose “Not now”.");
      }
    },
  };
}

// ---------- 6. checks
async function checksStep() {
  const data = await get("/api/netchecks");
  const box = tick(data.settings.dhcp_enabled);
  return {
    el: card(
      say("Two things on a home network should almost never change by themselves: who hands out addresses (DHCP), and the router. If either changes, it can be a new device that is hijacking your traffic, or just a broken router."),
      check(box, "Warn me when a second DHCP server shows up (recommended)",
        "Netlens asks the network once in a while who answers. The first answer is taken as normal.")),
    async commit() {
      if (box.checked !== data.settings.dhcp_enabled) await api("/api/netchecks", { method: "PUT", body: { dhcp_enabled: box.checked, dhcp_hours: data.settings.dhcp_hours } });
    },
  };
}

// ---------- static steps
const text = (...children) => async () => ({ el: card(...children) });

// ---------- the end: what is set up now
async function doneStep() {
  const rows = [];
  const add = (ok, yes, no) => rows.push(h("li", { class: ok ? "yes" : "no" }, h("span", { "aria-hidden": "true" }, ok ? "✓ " : "– "), ok ? yes : no));
  try {
    const cfg = await get("/api/config");
    const n = (cfg.ranges && cfg.ranges.length ? cfg.ranges : cfg.detected_ranges || []);
    add(n.length > 0, `Scanning ${n.join(", ")}`, "No network to scan yet");
  } catch (err) { /* left out */ }
  try { add((await get("/api/passive")).enabled, "Listening for device names", "Not listening for device names"); } catch (err) { /* left out */ }
  try {
    const n = (await get("/api/uptime/core")).devices.filter((d) => d.always_on).length;
    add(n > 0, `${n} always-on device${n === 1 ? "" : "s"}`, "No always-on devices chosen yet");
  } catch (err) { /* left out */ }
  try {
    const c = (await get("/api/notify-channels")).channels.filter((x) => x.enabled);
    add(c.length > 0, `Alerts go to: ${c.map((x) => x.name).join(", ")}`, "No alerts set up yet");
  } catch (err) { /* left out */ }
  try { add((await get("/api/netchecks")).settings.dhcp_enabled, "Watching for a second DHCP server", "DHCP check is off"); } catch (err) { /* left out */ }
  return {
    el: card(h("ul", { class: "wiz-summary" }, rows),
      say("Netlens keeps scanning in the background. The first results appear on the dashboard within a few minutes."),
      h("p", {}, link("#/dashboard", "The dashboard"), " · ", link("#/map", "The map"), " · ", link("#/devices", "All devices"))),
  };
}

export const STEPS = [
  { title: "Welcome", intro: "A few minutes now saves a lot of searching later.",
    build: text(
      say("Netlens scans your network, remembers every device it sees and tells you when something changes: a new device, a device that goes offline, a certificate that is about to expire."),
      say("This guide asks a few simple questions. Everything has a sensible answer already filled in, you can skip any step, and you can open this guide again from Settings."),
      h("p", { class: "hint" }, "Nothing here is permanent: every choice can be changed later in Settings.")) },
  { title: "Your network", intro: "Which network should Netlens look at?", build: networkStep,
    more: [["#/settings/ranges", "Scan ranges"], ["#/settings/schedule", "How often to scan"]] },
  { title: "Device names", intro: "So you see names instead of numbers.", build: namesStep,
    more: [["#/settings/nmap", "Scan performance and listening"], ["#/dns", "DNS registration"]] },
  { title: "Always-on devices", intro: "Which devices should never be offline?", build: alwaysOnStep,
    more: [["#/uptime", "All devices on the Uptime page"]] },
  { title: "Alerts", intro: "How should Netlens reach you?", build: alertsStep,
    more: [["#/settings/channels", "All channels, events and quiet hours"]] },
  { title: "Safety checks", intro: "Two things that should not change by themselves.", build: checksStep,
    more: [["#/settings/netchecks", "Network checks"]] },
  { title: "Integrations", intro: "Optional: connect other systems.",
    build: text(
      say("Plugins add data from other systems you may have: Proxmox and Hyper-V virtual machines, Docker containers, Nginx Proxy Manager sites, TrueNAS and more. You do not need any of them to start; each has a short setup guide."),
      h("p", {}, link("#/settings/plugin-browse", "Browse the available plugins"))),
    more: [["#/settings/plugins", "Installed plugins"]] },
  { title: "Users and backups", intro: "Optional, but worth a minute.",
    build: text(
      say("Give family or colleagues their own read-only account instead of sharing yours, and set up a scheduled backup so a lost disk is not a lost network map."),
      h("p", {}, link("#/settings/users", "Add a user"), " · ", link("#/settings/backup", "Set up backups")),
      h("p", { class: "hint" }, "If Netlens can be reached from the internet, put it behind a VPN or an access list.")) },
  { title: "All set", intro: "That was it.", build: doneStep },
];
