import { get, put, post } from "../api.js";
import { h, clear, toast } from "../util.js";

function copyBox(title, text) {
  const area = h("textarea", { readonly: true, rows: Math.min(14, text.split("\n").length + 1), class: "mono", style: "width:100%" }, text);
  const copy = h("button", { class: "btn", type: "button" }, "Copy");
  copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(text); toast("Copied", "success"); } catch { area.select(); } });
  return h("div", { class: "field" }, h("label", {}, title), area, copy);
}

// Settings → Host probes: where a probe's login comes from (Netlens CA, Vault / OpenBao), and how to lock a host down so the probe is all it can run.
export async function buildHostProbeCard() {
  const card = h("div", { class: "card" });
  let s = await get("/api/hostprobe/settings");

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Host probes"));
    card.appendChild(h("p", { class: "hint" }, "Storage inspection (device page) logs in to a host and reads what uses its disks. It only reads, and the host can be locked down so that it can run nothing else. Logins can be short-lived: nothing secret is then kept on the host or reused."));

    // 1. the Netlens certificate authority
    const ca = h("div", { class: "field" }, h("h3", {}, "Netlens certificate authority"));
    if (s.ca_public_key) {
      ca.append(h("p", { class: "hint" }, "Netlens signs a new certificate for every look, valid for a few minutes. A host only has to trust this public key."), copyBox("CA public key", s.ca_public_key + "\n"));
    } else {
      ca.appendChild(h("p", { class: "hint" }, "Not created yet. Create it to use certificates instead of a stored password or key."));
    }
    const make = h("button", { class: "btn", type: "button" }, s.ca_public_key ? "Replace the CA (hosts must trust the new key)" : "Create the CA");
    make.addEventListener("click", async () => {
      if (s.ca_public_key && !window.confirm("The old key stops working on every host. Continue?")) return;
      try { await post("/api/hostprobe/ca", {}); s = await get("/api/hostprobe/settings"); toast("Done", "success"); draw(); } catch (err) { toast(err.message || "Could not create", "error"); }
    });
    ca.appendChild(make);
    card.appendChild(ca);

    // 2. settings (one Save)
    const v = s.providers.vault_ssh;
    const f = {
      ttl: h("input", { type: "number", min: 60, max: 3600, value: s.providers.netlens_ca.ttl_s }),
      url: h("input", { type: "url", value: v.url, placeholder: "https://vault.example:8200" }),
      mount: h("input", { type: "text", value: v.mount }), role: h("input", { type: "text", value: v.role }), ns: h("input", { type: "text", value: v.namespace }),
      user: h("input", { type: "text", value: v.username }), token: h("input", { type: "password", autocomplete: "off", placeholder: v.has_token ? "(set; type to replace)" : "" }),
      roleId: h("input", { type: "text", autocomplete: "off" }), secretId: h("input", { type: "password", autocomplete: "off", placeholder: v.has_approle ? "(set; type to replace)" : "" }),
      names: h("input", { type: "checkbox", checked: s.names_to_llm }), keep: h("input", { type: "number", min: 1, max: 365, value: s.keep_days }),
    };
    const field = (label, input, hint) => h("div", { class: "field" }, h("label", {}, label), input, hint ? h("p", { class: "hint" }, hint) : null);
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      const vault = { url: f.url.value, mount: f.mount.value, role: f.role.value, namespace: f.ns.value, username: f.user.value };
      if (f.token.value) vault.token = f.token.value;
      if (f.roleId.value) vault.role_id = f.roleId.value;
      if (f.secretId.value) vault.secret_id = f.secretId.value;
      try {
        s = await put("/api/hostprobe/settings", { names_to_llm: f.names.checked, keep_days: Number(f.keep.value), providers: { netlens_ca: { ttl_s: Number(f.ttl.value) }, vault_ssh: vault } });
        toast("Saved", "success");
        draw();
      } catch (err) { toast(err.message || "Could not save", "error"); }
    });
    card.append(
      h("h3", {}, "Certificate lifetime"), field("Netlens CA certificates last (seconds)", f.ttl, "Between 60 and 3600."),
      h("h3", {}, "Vault or OpenBao (SSH secrets engine)"),
      h("p", { class: "hint" }, "Instead of the Netlens CA, a Vault or OpenBao server signs the certificate. Netlens keeps only a token or an AppRole for it. Choose \"Vault / OpenBao\" on a device to use it."),
      field("Address", f.url), field("Mount", f.mount), field("Role", f.role), field("Namespace (optional)", f.ns), field("User name on the hosts", f.user),
      field("Token", f.token, "A token that may sign with this role. Or use an AppRole:"), field("AppRole role id", f.roleId), field("AppRole secret id", f.secretId),
      h("h3", {}, "Privacy and records"),
      field("Keep storage snapshots for (days)", f.keep, "The snapshots hold folder and file names. Every look, every change of these settings and every time someone views the names is written to the audit log (Settings → Audit log, kept for the period set under Database), and is forwarded with Log forwarding."),
      h("div", { class: "field" }, h("label", { class: "check-row" }, f.names, " Let the language model see file and folder names"), h("p", { class: "hint" }, "Off: when an investigation is written out by a language model, it is only told how much grew and where, not the names. The built-in text always shows the names.")),
      h("div", { class: "form-actions" }, save));

    // 3. prepare a host
    card.appendChild(h("h3", {}, "Prepare a host"));
    const platform = h("select", {}, [["linux", "Linux"], ["windows", "Windows (OpenSSH server)"]].map(([k, t]) => h("option", { value: k }, t)));
    const user = h("input", { type: "text", value: "netlens-ro" });
    const pub = h("input", { type: "text", placeholder: "ssh-ed25519 AAAA… (only to use a key instead of certificates)" });
    const out = h("div", {});
    const show = h("button", { class: "btn", type: "button" }, "Show the files");
    show.addEventListener("click", async () => {
      clear(out);
      try {
        const r = await get(`/api/hostprobe/setup?platform=${platform.value}&user=${encodeURIComponent(user.value)}${pub.value ? `&public_key=${encodeURIComponent(pub.value)}` : ""}`);
        const names = { install: "Run on the host (installs the read-only script and the account)", authorized_keys: "authorized_keys of the account (binds the key to the probe)", sshd_config: "Add to sshd_config (trust the Netlens CA, run only the probe)", ca_public_key: "Contents of the CA public key file", sudoers: "/etc/sudoers.d/netlens-probe", script: "The probe script itself (read it before you install it)" };
        for (const [k, t] of Object.entries(names)) if (r.files[k]) out.appendChild(copyBox(t, r.files[k]));
        if (!r.has_ca && !pub.value) out.prepend(h("p", { class: "hint" }, "Create the CA above, or paste a public key, to get the lines that let Netlens in."));
      } catch (err) { toast(err.message || "Could not load", "error"); }
    });
    card.append(h("p", { class: "hint" }, "The host gets a root-owned script that only reads, and an account that can run nothing but that script, however it is asked. Nothing else is changed."),
      field("System", platform), field("Account name", user), field("Public key (optional)", pub), h("div", { class: "form-actions" }, show), out);
  }
  draw();
  return card;
}
