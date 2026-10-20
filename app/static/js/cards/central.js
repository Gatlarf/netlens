import { get, put, post } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

function field(label, input, hint) {
  const wrap = h("div", { class: "field" }, h("label", {}, label), input);
  if (hint) wrap.appendChild(h("p", { class: "hint" }, hint));
  return wrap;
}

// Settings page: this Netlens reports to another one (it is a remote site of it).
export async function buildCentralCard() {
  const card = h("div", { class: "card" });
  async function load() {
    draw(await get("/api/central"));
  }

  function draw(info) {
    clear(card);
    card.appendChild(h("h2", {}, "Report to a central Netlens"));
    card.appendChild(h("p", { class: "hint" },
      "Use this when this Netlens watches a second location (a branch office, a holiday house, a customer) and you want one overview. This Netlens keeps scanning and checking its own network as before and sends what it finds to the central Netlens every minute. The connection goes out from here; nothing at this location has to be reachable from outside. On the central Netlens open Monitoring → Remote sites → Add a remote site to get the address and the token."));
    const url = h("input", { type: "url", placeholder: "https://netlens.example.com", value: info.url || "", spellcheck: "false" });
    const token = h("input", { type: "password", autocomplete: "off", placeholder: info.has_token ? "(kept, paste to change)" : "nlp_…" });
    const enabled = h("input", { type: "checkbox" });
    enabled.checked = info.enabled;
    const result = h("div", {});
    const trust = h("input", { type: "checkbox" });
    trust.checked = !!info.pin;
    const accept = h("input", { type: "checkbox" });
    accept.checked = !!info.accept_config;
    const body = () => {
      const out = { url: url.value.trim(), enabled: enabled.checked, accept_config: accept.checked };
      if (trust.checked !== !!info.pin || (trust.checked && url.value.trim() !== info.url)) out.trust_certificate = trust.checked;
      if (token.value.trim()) out.token = token.value.trim();
      return out;
    };
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      save.disabled = true;
      try {
        draw(await put("/api/central", body()));
        toast("Saved", "success");
      } catch (err) {
        toast(err.message || "Could not save", "error");
        save.disabled = false;
      }
    });
    const send = h("button", { class: "btn", type: "button" }, "Send a report now");
    send.addEventListener("click", async () => {
      send.disabled = true;
      try {
        await put("/api/central", body());
        const r = await post("/api/central/push", {});
        draw(r);
        toast(r.status && r.status.ok ? "The central Netlens received the report" : (r.status && r.status.error) || "The report did not arrive", r.status && r.status.ok ? "success" : "error");
      } catch (err) {
        toast(err.message || "Could not send", "error");
        send.disabled = false;
      }
    });
    const st = info.status || {};
    if (st.ts) {
      result.appendChild(h("p", { class: st.ok ? "" : "error" },
        st.ok ? `Last report ${timeAgo(st.ts)}: ${st.devices} devices, ${st.services} service checks, ${st.samples} measurements.` : `Last report ${timeAgo(st.ts)} failed: ${st.error}`));
    }
    if (st.skew_s !== null && st.skew_s !== undefined && Math.abs(st.skew_s) > 120) {
      result.appendChild(h("p", { class: "error" }, `The clock of this machine is ${Math.abs(st.skew_s) >= 3600 ? `${Math.round(Math.abs(st.skew_s) / 360) / 10} hours` : `${Math.round(Math.abs(st.skew_s) / 60)} minutes`} ${st.skew_s > 0 ? "ahead of" : "behind"} the central Netlens. Check its time and time zone: graphs would be shifted and measurements too far from the real time are not kept.`));
    }
    if (st.commands && st.commands.length) result.appendChild(h("p", { class: "hint" }, "The central Netlens asked for a scan; it was started."));
    if (st.config) {
      const c = st.config;
      result.appendChild(h("p", { class: c.error ? "error" : "hint" }, c.error ? c.error : `Configuration from the central Netlens (revision ${info.config_rev}): ${c.services} service check(s), ${c.monitors} monitor(s).${c.skipped && c.skipped.length ? ` Skipped: ${c.skipped.join("; ")}` : ""}`));
    }
    card.appendChild(h("form", { class: "edit-form", onsubmit: (e) => e.preventDefault() },
      field("Address of the central Netlens", url, "Use https:// across the internet. A plain http:// address is accepted for a server on your own network (a VPN, for example)."),
      field("Token", token, "Made on the central Netlens for this location. It is stored encrypted here."),
      h("label", {}, trust, " Trust the certificate of the central Netlens (it is self-signed)"),
      h("p", { class: "hint" }, info.pin ? `Trusted certificate (SHA-256): ${info.pin}. Compare it with the certificate of the central Netlens. If that certificate is ever replaced, reports stop until you untick this box, save, tick it and save again.`
        : "Only for a central Netlens with its own (self-signed) certificate, for example behind a VPN. Netlens remembers the certificate it sees when you save and accepts only that one. With a normal certificate (Let’s Encrypt, a reverse proxy) leave this off."),
      h("label", {}, enabled, " Report to the central Netlens"),
      h("label", {}, accept, " Accept configuration and commands from the central Netlens"),
      h("p", { class: "hint" }, "When ticked, the central Netlens may set up service checks and health monitors here (they appear marked as managed from the central Netlens and cannot be changed here) and ask this Netlens to scan its network. Leave it off to keep all settings at this location. Logins it sends are stored encrypted."),
      h("div", { class: "form-actions" }, save, send), result));
  }

  await load();
  return card;
}
