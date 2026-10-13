// Getting-started wizard: a guided walk through the settings that matter on a new install.
// Every step reuses the real settings card, so there is one implementation per setting. All steps can be skipped;
// whatever is changed is saved right away by the card itself. Progress is kept on the server (GET/PUT /api/wizard).
import { get, put } from "../api.js";
import { h, clear, toast, shortName, isAdmin } from "../util.js";
import { buildRangesCard } from "./settings.js";
import { buildScheduleCard } from "../cards/general.js";
import { buildPassiveCard } from "../cards/passive.js";
import { buildDnsCard } from "../cards/dns.js";
import { buildChannelsCard } from "../cards/channels.js";
import { buildNetchecksCard } from "../cards/netchecks.js";

const link = (href, text) => h("a", { href }, text);

// the devices that look like they should be always-on, ticked in one go (the full chooser is on the Uptime page)
async function buildAlwaysOn() {
  const rows = (await get("/api/uptime/core")).devices;
  const picked = new Set(rows.filter((r) => r.always_on).map((r) => r.id));
  const suggested = rows.filter((r) => r.suggested || picked.has(r.id)); // the likely ones, and what is already ticked
  const box = h("div", { class: "card wiz-card" }, h("h2", {}, "Always-on devices"));
  if (!suggested.length && !picked.size) {
    box.append(h("p", { class: "hint" }, "Netlens needs a few days of history before it can suggest which devices run all day. Come back later: on the Uptime page, “Choose always-on devices” does this."));
    return box;
  }
  const count = h("strong", {});
  const update = () => { count.textContent = `${picked.size} selected`; };
  const list = h("div", { class: "up-choose-list" });
  for (const r of suggested) {
    list.append(h("label", { class: "up-choose-row" },
      h("input", { type: "checkbox", checked: picked.has(r.id), onchange: (e) => { if (e.target.checked) picked.add(r.id); else picked.delete(r.id); update(); } }),
      h("span", { class: "up-choose-name" }, shortName(r.name), r.ip ? h("span", { class: "mono hint" }, ` ${r.ip}`) : null),
      h("span", { class: "hint" }, r.type)));
  }
  update();
  const save = h("button", { class: "btn primary", type: "button", onclick: async (e) => {
    e.target.disabled = true;
    try {
      await put("/api/uptime/core", { device_ids: [...picked] });
      toast("Saved", "success");
    } catch (err) {
      toast(err.message || "Could not save", "error");
    }
    e.target.disabled = false;
  } }, "Save");
  box.append(
    h("p", { class: "hint" }, "Always-on devices are the ones that should be online all the time: router, switches, servers, cameras. Uptime, the dashboard and Statistics then show them apart, so a phone that leaves home does not pull the figure down."),
    suggested.length ? h("p", {}, "These look like always-on devices (ticked ones are already marked):") : null,
    list, h("p", {}, count, " ", save));
  return box;
}

const info = (title, ...paragraphs) => async () => h("div", { class: "card wiz-card" }, h("h2", {}, title), ...paragraphs);

const STEPS = [
  { title: "Welcome", intro: "A few minutes now saves a lot of searching later.",
    build: info("What Netlens does",
      h("p", {}, "Netlens scans your network, remembers every device it sees and tells you when something changes: a new device, a device that goes offline, a rogue DHCP server, a certificate that is about to expire."),
      h("p", {}, "This guide walks through the settings that matter most. Every step can be skipped, whatever you change is saved straight away, and you can open this guide again any time from Settings → Setup guide.")) },
  { title: "Networks and schedule", intro: "What to scan and how often.",
    build: async () => h("div", { class: "wiz-body" }, await buildRangesCard(), await buildScheduleCard()) },
  { title: "Better names", intro: "Netlens names devices from what they say about themselves.",
    build: async () => h("div", { class: "wiz-body" },
      h("div", { class: "card wiz-card" }, h("p", { class: "hint" }, "Passive discovery listens quietly for devices announcing themselves (mDNS, SSDP, DHCP). Registering names in your DNS server makes the names usable everywhere. Both are optional.")),
      await buildPassiveCard(), await buildDnsCard()) },
  { title: "Always-on devices", intro: "Tell Netlens which devices should never be offline.", build: buildAlwaysOn },
  { title: "Alerts", intro: "Where Netlens should tell you when something is wrong.",
    build: async () => h("div", { class: "wiz-body" },
      h("div", { class: "card wiz-card" }, h("p", { class: "hint" }, "Add at least one channel (e-mail, ntfy, Telegram, a webhook…) and choose which events it carries. Quiet hours keep it calm at night.")),
      await buildChannelsCard()) },
  { title: "Network checks", intro: "Two things that should not change by themselves.", build: buildNetchecksCard },
  { title: "Integrations", intro: "Plugins bring in what the network itself cannot tell.",
    build: info("Plugins",
      h("p", {}, "Plugins add data from other systems: Proxmox and Hyper-V guests, Docker containers, Nginx Proxy Manager sites and certificates, TrueNAS, and more. Each one has a short setup guide."),
      h("p", {}, link("#/settings/plugin-browse", "Browse the available plugins"), " · ", link("#/settings/plugins", "See the installed ones"))) },
  { title: "Safety", intro: "Other people, backups and who can reach Netlens.",
    build: info("Users and backups",
      h("p", {}, link("#/settings/users", "Users & tokens"), ": give family or colleagues a read-only account instead of sharing yours."),
      h("p", {}, link("#/settings/backup", "Backup & restore"), ": set up a scheduled backup and keep a copy off this machine."),
      h("p", { class: "hint" }, "If Netlens is reachable from the internet, put it behind a VPN or an access list, and switch on “Failed logins” in your notification channel.")) },
  { title: "All set", intro: "That was it.",
    build: info("You are ready",
      h("p", {}, "Netlens keeps scanning in the background. Good places to go next:"),
      h("p", {}, link("#/dashboard", "The dashboard"), " · ", link("#/map", "The map"), " · ", link("#/devices", "All devices"), " · ", link("#/settings", "All settings"))) },
];

export async function render(container) {
  if (!isAdmin()) {
    container.append(h("div", { class: "card" }, h("p", {}, "Only an administrator can use the setup guide.")));
    return;
  }
  let state = { status: "new", step: 0 };
  try { state = await get("/api/wizard"); } catch (err) { /* open at the first step */ }
  let step = Math.min(Math.max(state.step || 0, 0), STEPS.length - 1);
  let disposed = false;
  const body = h("div", { class: "wiz-body" });
  const nav = h("div", { class: "wiz-nav" });
  const dots = h("ol", { class: "wiz-dots", "aria-label": "Steps" });
  const title = h("h1", {});
  const intro = h("p", { class: "hint" });
  container.append(h("div", { class: "wiz" }, h("div", { class: "wiz-head" }, title, intro, dots), body, nav));

  let status = state.status;
  const save = (next) => { status = next; return put("/api/wizard", { status, step }).catch(() => {}); };

  async function show(n) {
    step = n;
    save(step === STEPS.length - 1 || status === "done" ? "done" : "pending");
    const s = STEPS[step];
    title.textContent = s.title;
    intro.textContent = `Step ${step + 1} of ${STEPS.length}. ${s.intro}`;
    clear(dots);
    STEPS.forEach((t, i) => dots.append(h("li", { class: i === step ? "now" : i < step ? "past" : "" },
      h("button", { type: "button", title: t.title, "aria-current": i === step ? "step" : null, onclick: () => show(i) }, String(i + 1)))));
    clear(body);
    body.append(h("p", { class: "hint" }, "Loading…"));
    try {
      const card = await s.build();
      if (disposed || step !== n) return;
      clear(body);
      body.append(card);
    } catch (err) {
      if (disposed || step !== n) return;
      clear(body);
      body.append(h("div", { class: "card" }, h("p", { class: "error" }, err.message || "Could not load this step")));
    }
    clear(nav);
    const last = step === STEPS.length - 1;
    nav.append(
      step > 0 ? h("button", { class: "btn", type: "button", onclick: () => show(step - 1) }, "Back") : h("span", {}),
      h("span", { class: "wiz-nav-end" },
        last ? null : h("button", { class: "btn", type: "button", onclick: async () => { await save(status === "done" ? "done" : "dismissed"); location.hash = "#/dashboard"; } }, "Close for now"),
        h("button", { class: "btn primary", type: "button", onclick: async () => {
          if (last) { await save("done"); location.hash = "#/dashboard"; } else show(step + 1);
        } }, last ? "Open the dashboard" : step === 0 ? "Start" : "Next")));
    window.scrollTo(0, 0);
  }

  await show(step);
  return () => { disposed = true; };
}
