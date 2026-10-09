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
  card.appendChild(save);
  card.appendChild(run);
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
