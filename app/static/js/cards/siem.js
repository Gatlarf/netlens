import { get, put, post } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

// Settings page: forward events and the audit log to a syslog server or SIEM.
export async function buildSiemCard() {
  const card = h("div", { class: "card" });
  function draw(info) {
    clear(card);
    const p = info.policy;
    card.appendChild(h("h2", {}, "Log forwarding (syslog)"));
    card.appendChild(h("p", { class: "hint" },
      "Send what happens in Netlens (events) and what people do in it (the audit log) to your log server: Graylog, Splunk, Wazuh, Elastic, rsyslog ... as RFC 5424 syslog over UDP or TCP. Netlens remembers what it has sent, so a server that is down only delays the delivery. Part of the Small business and Enterprise editions and the free trial."));
    if (!info.allowed) card.appendChild(h("p", { class: "warn-text" }, "Part of the Small business and Enterprise editions, and the free trial (Settings → Licence)."));
    const enabled = h("input", { type: "checkbox" });
    enabled.checked = p.enabled;
    const host = h("input", { type: "text", value: p.host, placeholder: "logs.example.com or 192.168.0.9" });
    const port = h("input", { type: "number", min: "1", max: "65535", value: String(p.port), style: "width:7em" });
    const proto = h("select", {}, h("option", { value: "udp", selected: p.protocol === "udp" }, "UDP"), h("option", { value: "tcp", selected: p.protocol === "tcp" }, "TCP"));
    const facility = h("select", {}, ...info.facilities.map((f) => h("option", { value: f, selected: f === p.facility }, f)));
    const events = h("input", { type: "checkbox" });
    events.checked = p.send_events;
    const audit = h("input", { type: "checkbox" });
    audit.checked = p.send_audit;
    const body = () => ({ enabled: enabled.checked, host: host.value.trim(), port: Number(port.value), protocol: proto.value, facility: facility.value, send_events: events.checked, send_audit: audit.checked });
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      save.disabled = true;
      try { draw(await put("/api/siem", body())); toast("Saved", "success"); } catch (err) { toast(err.message || "Could not save", "error"); save.disabled = false; }
    });
    const test = h("button", { class: "btn", type: "button" }, "Send a test message");
    test.addEventListener("click", async () => {
      test.disabled = true;
      try { await put("/api/siem", body()); await post("/api/siem/test", {}); toast("Sent (UDP gives no confirmation: check the server)", "success"); } catch (err) { toast(err.message || "Failed", "error"); }
      test.disabled = false;
    });
    const st = info.status || {};
    card.append(h("label", { class: "check" }, enabled, " Forward to a syslog server"),
      h("div", { class: "field" }, h("label", {}, "Server"), host), h("div", { class: "field" }, h("label", {}, "Port"), port), h("div", { class: "field" }, h("label", {}, "Protocol"), proto),
      h("div", { class: "field" }, h("label", {}, "Facility"), facility), h("label", { class: "check" }, events, " Events (alerts, devices, services ...)"), h("label", { class: "check" }, audit, " Audit log (who changed what)"),
      st.ts ? h("p", { class: st.ok ? "hint" : "error" }, st.ok ? `Last delivery ${timeAgo(st.ts)}: ${st.sent} message${st.sent === 1 ? "" : "s"}.` : `Last attempt ${timeAgo(st.ts)} failed: ${st.error}`) : null,
      h("div", { class: "form-actions" }, save, test));
  }
  draw(await get("/api/siem"));
  return card;
}
