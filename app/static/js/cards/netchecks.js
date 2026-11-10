import { api, get } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";

const HOURS = { 1: "every hour", 6: "every 6 hours", 12: "every 12 hours", 24: "every day", 72: "every 3 days" };

function fill(card, data) {
  clear(card);
  card.appendChild(h("h2", {}, "Network checks"));
  card.appendChild(h("p", { class: "hint" },
    "Netlens watches for two things that should not change by themselves. A second DHCP server (a rogue one hands out wrong addresses, gateways or DNS) " +
    "and a changed MAC address behind your gateway (a replaced router, or someone pretending to be it). Alerts go to your notification channels and break through quiet hours."));

  // ---- DHCP
  card.appendChild(h("h3", {}, "DHCP servers"));
  const enabled = h("input", { type: "checkbox", name: "dhcp_enabled" });
  enabled.checked = data.settings.dhcp_enabled;
  const every = h("select", { name: "dhcp_hours" });
  for (const hours of data.intervals) every.appendChild(h("option", { value: String(hours) }, HOURS[hours] || `every ${hours} hours`));
  every.value = String(data.settings.dhcp_hours);
  const save = h("button", { type: "button", class: "btn" }, "Save");
  const run = h("button", { type: "button", class: "btn", id: "dhcp-run" }, "Check now");
  const call = async (btn, request, done) => {
    btn.disabled = true;
    try {
      const res = await request();
      toast(typeof done === "function" ? done(res) : done, "success");
      fill(card, res);
    } catch (err) {
      toast(err.message || "Failed", "error");
      btn.disabled = false;
    }
  };
  save.addEventListener("click", () => call(save, () => api("/api/netchecks", { method: "PUT", body: { dhcp_enabled: enabled.checked, dhcp_hours: Number(every.value) } }), "Saved"));
  run.addEventListener("click", () => {
    run.textContent = "Listening for about 10 seconds…";
    call(run, () => api("/api/netchecks/dhcp/run", { method: "POST" }),
      (res) => res.result.rogue.length ? `New DHCP server found: ${res.result.rogue.join(", ")}` : `${res.result.servers.length} DHCP server(s) answered`);
  });
  card.appendChild(h("div", { class: "field" }, h("label", { class: "check" }, enabled, " Look for DHCP servers regularly")));
  card.appendChild(h("div", { class: "field" }, h("label", {}, "How often"), every));
  card.appendChild(h("p", { class: "hint" },
    "Netlens sends one DHCP discover to the network (like a device that has just been plugged in) and lists every server that answers. The servers found the first time are taken as normal; later ones are reported until you trust them."));
  card.appendChild(h("div", { class: "form-actions" }, save, run));
  const last = data.last;
  if (last) {
    card.appendChild(h("p", { class: last.ok ? "hint" : "error", id: "dhcp-last" },
      last.ok ? `Last check: ${fmtTime(last.at)}, ${last.servers.length} server(s) answered.` : `Last check FAILED at ${fmtTime(last.at)}: ${last.error}`));
  }

  if (data.servers.length) {
    const table = h("table", { class: "table dhcp-servers" });
    table.appendChild(h("thead", {}, h("tr", {}, ["Server", "Hands out", "Last seen", "Status", ""].map((t) => h("th", {}, t)))));
    const body = h("tbody");
    for (const s of data.servers) {
      const who = h("td", {}, h("strong", {}, s.ip), s.name || s.mac ? h("span", { class: "hint" }, ` ${[s.name, s.mac, s.vendor].filter(Boolean).join(", ")}`) : null);
      const gives = h("td", {}, `router ${s.router || "?"}, DNS ${s.dns.length ? s.dns.join(", ") : "?"}`);
      const trust = h("button", { type: "button", class: "btn" }, s.trusted ? "Stop trusting" : "Trust");
      trust.addEventListener("click", () => call(trust, () => api(`/api/netchecks/dhcp/${s.ip}`, { method: "PUT", body: { trusted: !s.trusted } }), s.trusted ? "No longer trusted" : "Trusted"));
      const forget = h("button", { type: "button", class: "btn danger" }, "Forget");
      forget.addEventListener("click", () => call(forget, () => api(`/api/netchecks/dhcp/${s.ip}`, { method: "DELETE" }), "Forgotten"));
      body.appendChild(h("tr", { class: s.trusted ? "" : "untrusted" }, who, gives, h("td", {}, fmtTime(s.last_seen)),
        h("td", {}, s.trusted ? "trusted" : h("span", { class: "error" }, "NOT trusted")), h("td", {}, trust, " ", forget)));
    }
    table.appendChild(body);
    card.appendChild(table);
  } else {
    card.appendChild(h("p", { class: "hint" }, "No DHCP server seen yet. Press Check now."));
  }

  // ---- router exposure
  card.appendChild(h("h3", {}, "Router exposure"));
  const ex = data.exposure;
  const exOn = h("input", { type: "checkbox", name: "exposure_enabled" });
  exOn.checked = ex.settings.enabled;
  exOn.title = "Connects to a few ports on the gateway and asks it for its UPnP port mappings. Read-only, never logs in, every run is audited.";
  const exEvery = h("select", { name: "exposure_hours" });
  for (const hours of ex.intervals) exEvery.appendChild(h("option", { value: String(hours) }, hours === 168 ? "every week" : HOURS[hours] || `every ${hours} hours`));
  exEvery.value = String(ex.settings.hours);
  const exSave = h("button", { type: "button", class: "btn" }, "Save");
  exSave.addEventListener("click", () => call(exSave, () => api("/api/netchecks/exposure", { method: "PUT", body: { enabled: exOn.checked, hours: Number(exEvery.value) } }), "Saved"));
  const exRun = h("button", { type: "button", class: "btn", id: "exposure-run" }, "Check now");
  exRun.disabled = !ex.settings.enabled;
  exRun.addEventListener("click", () => {
    exRun.textContent = "Checking…";
    call(exRun, () => api("/api/netchecks/exposure/run", { method: "POST" }), "Router checked");
  });
  card.appendChild(h("div", { class: "field" }, h("label", { class: "check" }, exOn, " Check what the gateway exposes")));
  card.appendChild(h("div", { class: "field" }, h("label", {}, "How often"), exEvery));
  card.appendChild(h("div", { class: "form-actions" }, exSave, exRun));
  if (ex.last) {
    card.appendChild(h("p", { class: "hint", id: "exposure-last" }, `Gateway ${ex.last.gateway}, checked ${fmtTime(ex.last.at)}. Score ${ex.last.score} of 100.`));
    const list = h("div", { class: "exposure-list" });
    const order = { risk: 0, warn: 1, unknown: 2, ok: 3 };
    for (const f of [...ex.last.findings].sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9))) {
      const tag = { risk: "RISK", warn: "REVIEW", unknown: "UNKNOWN", ok: "OK" }[f.status] || f.status;
      const row = h("div", { class: `exposure-item st-${f.status}`, "data-finding": f.id },
        h("p", {}, h("strong", {}, f.title), " ", h("span", { class: f.status === "risk" ? "error" : "hint" }, `${tag} · ${f.severity}`)),
        h("p", { class: "hint" }, f.evidence));
      if (f.steps.length && f.status !== "ok") {
        row.appendChild(h("details", {}, h("summary", {}, `How to fix · ${f.steps.length} steps`), h("ol", {}, ...f.steps.map((s) => h("li", {}, s)))));
      }
      list.appendChild(row);
    }
    card.appendChild(list);
  }

  // ---- gateway
  card.appendChild(h("h3", {}, "Gateway"));
  card.appendChild(data.gateway
    ? h("p", {}, `Gateway ${data.gateway.ip} answers with MAC address `, h("span", { class: "mono" }, data.gateway.mac), `, known since ${fmtTime(data.gateway.since)}. A change is reported as "Gateway changed".`)
    : h("p", { class: "hint" }, "The gateway is recorded after the next scan."));
}

export async function buildNetchecksCard() {
  const card = h("div", { class: "card" });
  fill(card, await get("/api/netchecks"));
  return card;
}
