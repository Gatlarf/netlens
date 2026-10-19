import { get, put } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

// Settings page: SNMP traps and syslog that devices send to Netlens (see app/inbound.py).
export async function buildInboundCard() {
  const card = h("div", { class: "card", id: "inbound-card" });
  function listening(s, off) {
    if (s.error) return h("p", { class: "error" }, s.error);
    if (!s.listening) return h("p", { class: "hint" }, off);
    return h("p", { class: "hint" }, s.last ? `Listening. ${s.received} message${s.received === 1 ? "" : "s"} received, the last ${timeAgo(s.last)}.` : "Listening. Nothing received yet.");
  }
  function draw(info) {
    clear(card);
    const p = info.policy;
    card.appendChild(h("h2", {}, "Device messages: SNMP traps and syslog"));
    card.appendChild(h("p", { class: "hint" },
      "Devices can tell Netlens when something happens instead of waiting to be asked: a switch that loses a link, a UPS that goes on battery, a router that logs an error. Netlens turns those messages into events on the right device, so they appear on its page, in your alert channels and in the log forwarding. Both listeners are off until you switch them on, and they use high ports because the standard ones (162 and 514) need extra privileges: point the devices at the ports below. Only the sender's IP address is used to find the device."));

    const trapOn = h("input", { type: "checkbox" });
    trapOn.checked = p.traps.enabled;
    const trapPort = h("input", { type: "number", min: "1", max: "65535", value: String(p.traps.port), style: "width:7em" });
    const comm = h("input", { type: "text", value: p.traps.communities.join(", "), placeholder: "public" });
    const sysOn = h("input", { type: "checkbox" });
    sysOn.checked = p.syslog.enabled;
    const sysPort = h("input", { type: "number", min: "1", max: "65535", value: String(p.syslog.port), style: "width:7em" });
    const sev = h("select", {}, ...info.severities.map((s) => h("option", { value: s, selected: s === p.syslog.min_severity }, s)));

    const body = () => ({
      traps: { enabled: trapOn.checked, port: Number(trapPort.value), communities: comm.value.split(",").map((c) => c.trim()).filter(Boolean) },
      syslog: { enabled: sysOn.checked, port: Number(sysPort.value), min_severity: sev.value },
    });
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      save.disabled = true;
      try { draw(await put("/api/inbound", body())); toast("Saved", "success"); } catch (err) { toast(err.message || "Could not save", "error"); save.disabled = false; }
    });

    card.append(
      h("h3", {}, "SNMP traps"),
      h("p", { class: "hint" }, "SNMP v1 and v2c traps and informs. SNMP v3 traps are not supported. A trap is only accepted when it carries one of the community names below."),
      h("label", { class: "check" }, trapOn, " Receive SNMP traps"),
      h("div", { class: "field" }, h("label", {}, "UDP port"), trapPort),
      h("div", { class: "field" }, h("label", {}, "Community names (separated by commas)"), comm),
      listening(info.traps, "Off."),
      h("h3", {}, "Syslog"),
      h("p", { class: "hint" }, "RFC 3164 and RFC 5424 over UDP. Only messages from devices Netlens knows, at or above the severity you choose, become events; the rest are counted and dropped."),
      h("label", { class: "check" }, sysOn, " Receive syslog"),
      h("div", { class: "field" }, h("label", {}, "UDP port"), sysPort),
      h("div", { class: "field" }, h("label", {}, "Lowest severity that becomes an event"), sev),
      listening(info.syslog, "Off."),
      info.dropped || info.ignored ? h("p", { class: "hint" }, `${info.ignored} message${info.ignored === 1 ? "" : "s"} ignored (wrong community or not understood), ${info.dropped} dropped because a sender was too chatty (more than 60 a minute).`) : null,
      h("p", { class: "hint" }, `Point your devices at ${location.hostname}: traps to port ${p.traps.port}, syslog to port ${p.syslog.port}. With Docker bridge networking, publish those UDP ports.`),
      h("div", { class: "form-actions" }, save));
  }
  draw(await get("/api/inbound"));
  return card;
}
