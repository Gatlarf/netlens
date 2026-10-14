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
    const body = () => {
      const out = { url: url.value.trim(), enabled: enabled.checked };
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
    card.appendChild(h("form", { class: "edit-form", onsubmit: (e) => e.preventDefault() },
      field("Address of the central Netlens", url, "Use https:// across the internet. A plain http:// address is accepted for a server on your own network (a VPN, for example)."),
      field("Token", token, "Made on the central Netlens for this location. It is stored encrypted here."),
      h("label", {}, enabled, " Report to the central Netlens"),
      h("div", { class: "form-actions" }, save, send), result));
  }

  await load();
  return card;
}
