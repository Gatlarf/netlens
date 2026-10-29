import { get, post, del } from "../api.js";
import { h, clear, toast } from "../util.js";

// Settings -> HTTPS: Netlens can serve https itself. A self-signed certificate (a browser warns about it) or your own certificate and key; a change is applied by a restart.
export async function buildTlsCard() {
  const card = h("div", { class: "card admin-only" });
  let st = await get("/api/tls");

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "HTTPS"));
    card.appendChild(h("p", { class: "hint" }, "Netlens can serve https itself, without a reverse proxy. Security keys and passkeys need https. The key is stored on the server's data volume, readable by Netlens only, and is never shown again."));
    if (!st.configured) card.appendChild(h("p", {}, st.page_is_https ? "This page is served over https by something in front of Netlens. Netlens itself serves plain http." : h("span", { class: "warn-text" }, "Netlens serves plain http: passwords and sessions cross the network unencrypted. Set up https below, or put a reverse proxy in front.")));
    else if (st.valid === false) card.appendChild(h("p", { class: "error" }, st.problem));
    else {
      card.appendChild(h("p", {}, h("span", { class: `tag ${st.running ? "ok" : ""}` }, st.running ? "serving https" : "configured, not running yet"), ` ${st.self_signed ? "self-signed" : "issued by " + st.issuer}`));
      card.appendChild(h("table", { class: "kv" }, h("tbody", {},
        [["Names", (st.names || []).join(", ") || "—"], ["Subject", st.subject], ["Expires", `${st.expires.slice(0, 10)} (${st.days_left} days)`], ["Fingerprint (SHA-256)", st.fingerprint], ["Set by", st.env_managed ? "NETLENS_TLS_CERT in the container's environment" : "this page"]]
          .map(([k, v]) => h("tr", {}, h("th", {}, k), h("td", { class: "mono", style: "overflow-wrap:anywhere" }, v))))));
      if (st.days_left < 30) card.appendChild(h("p", { class: "warn-text" }, "This certificate ends soon: replace it."));
    }
    if (st.restart_needed) {
      const restart = h("button", { class: "btn", type: "button" }, "Restart Netlens now");
      restart.addEventListener("click", async () => {
        if (!window.confirm("Netlens stops for a moment and starts again with the new setting. It needs a container restart policy (restart: unless-stopped) to come back by itself. Continue?")) return;
        try { await post("/api/tls/restart", {}); toast("Restarting… reload the page in a few seconds (the address may now start with https://)", "success"); } catch (err) { toast(err.message || "Could not restart", "error"); }
      });
      card.append(h("p", { class: "warn-text" }, "The change is applied when Netlens restarts."), h("div", { class: "btn-row" }, restart));
    }
    if (st.env_managed) return;
    const names = h("input", { type: "text", value: location.hostname, placeholder: "netlens.example.com, 192.168.1.10", "aria-label": "Names for the certificate" });
    const make = h("button", { class: "btn", type: "button" }, "Make a self-signed certificate");
    make.addEventListener("click", async () => {
      try { st = await post("/api/tls/self-signed", { names: names.value.split(",").map((x) => x.trim()).filter(Boolean) }); toast("Certificate made", "success"); draw(); } catch (err) { toast(err.message || "Failed", "error"); }
    });
    const cert = h("textarea", { rows: 5, class: "mono", placeholder: "-----BEGIN CERTIFICATE----- (the server certificate first, then the chain)", "aria-label": "Certificate" });
    const key = h("textarea", { rows: 4, class: "mono", placeholder: "-----BEGIN PRIVATE KEY----- (without a password)", "aria-label": "Private key" });
    const upload = h("button", { class: "btn", type: "button" }, "Use this certificate and key");
    upload.addEventListener("click", async () => {
      try { st = await post("/api/tls/upload", { certificate: cert.value, key: key.value }); key.value = ""; toast("Certificate installed", "success"); draw(); } catch (err) { toast(err.message || "Failed", "error"); }
    });
    card.append(h("h3", {}, "Make one"), h("div", { class: "field" }, h("label", {}, "Names (host names or addresses, separated by commas)"), names), h("div", { class: "btn-row" }, make),
      h("h3", {}, "Or use your own certificate"), h("p", { class: "hint" }, "From your own CA or a public one (for example Let's Encrypt). To renew automatically, point NETLENS_TLS_CERT and NETLENS_TLS_KEY at files your tooling renews, and restart after a renewal."),
      h("div", { class: "field" }, h("label", {}, "Certificate"), cert), h("div", { class: "field" }, h("label", {}, "Private key"), key), h("div", { class: "btn-row" }, upload));
    if (st.configured) card.appendChild(h("div", { class: "btn-row" }, h("button", { class: "btn danger", type: "button", onclick: async () => {
      if (!window.confirm("Remove the certificate? After a restart Netlens serves plain http again.")) return;
      try { st = await del("/api/tls"); draw(); } catch (err) { toast(err.message || "Failed", "error"); }
    } }, "Remove the certificate")));
  }
  draw();
  return card;
}
