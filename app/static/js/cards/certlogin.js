import { get, put } from "../api.js";
import { h, clear, toast } from "../util.js";

// Settings -> Client certificates: sign in with a certificate that a reverse proxy has checked. Netlens believes the two headers only from the proxies listed here.
export async function buildCertLoginCard() {
  const card = h("div", { class: "card admin-only" });
  let data = await get("/api/cert-login");

  function draw() {
    clear(card);
    const s = data.settings;
    card.appendChild(h("h2", {}, "Client certificates"));
    card.appendChild(h("p", { class: "hint" }, "Your reverse proxy (nginx, Traefik, Caddy, HAProxy, a load balancer) asks the browser for a certificate, checks it against your CA and tells Netlens who it was in two headers. Netlens believes those headers only from the proxies below, and only when the proxy says the certificate was good. The certificate replaces the password; a user with a second factor still gives it. Link a certificate to a user under Users & tokens (button “Certificate”)."));
    if (!data.allowed) card.appendChild(h("p", { class: "warn-text" }, "Part of the Enterprise edition and the free trial (Settings → Licence)."));
    const enabled = h("input", { type: "checkbox", checked: s.enabled });
    const proxies = h("textarea", { rows: 3, class: "mono", placeholder: "10.0.0.5\n172.18.0.0/16  (one per line)", "aria-label": "Proxies" });
    proxies.value = s.proxies.join("\n");
    const verifyHeader = h("input", { type: "text", value: s.verify_header, "aria-label": "Verify header" });
    const verifyValue = h("input", { type: "text", value: s.verify_value, "aria-label": "Verify value" });
    const identityHeader = h("input", { type: "text", value: s.identity_header, "aria-label": "Identity header" });
    const field = (label, el, hint) => h("div", { class: "field" }, h("label", {}, label), el, hint ? h("p", { class: "hint" }, hint) : null);
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      try {
        data = await put("/api/cert-login", { enabled: enabled.checked, proxies: proxies.value.split(/[\s,]+/).filter(Boolean), verify_header: verifyHeader.value.trim(), verify_value: verifyValue.value, identity_header: identityHeader.value.trim() });
        toast("Saved", "success");
        draw();
      } catch (err) { toast(err.message || "Could not save", "error"); }
    });
    card.append(h("div", { class: "field" }, h("label", { class: "check-row" }, enabled, " Allow sign-in with a client certificate")),
      field("Reverse proxies", proxies, "The address of the proxy as Netlens sees it. Never a network that a client could be on: the proxy must overwrite these headers."),
      field("Header that says the certificate was verified", verifyHeader, "nginx: X-SSL-Client-Verify"), field("Value of that header for a good certificate", verifyValue, "nginx: SUCCESS"),
      field("Header with the identity", identityHeader, "nginx: X-SSL-Client-S-DN (the subject). Whatever it holds must equal, exactly, what you link to the user."),
      h("p", { class: "hint" }, `${data.linked} user${data.linked === 1 ? " is" : "s are"} linked to a certificate.`), h("div", { class: "form-actions" }, save));
  }
  draw();
  return card;
}
