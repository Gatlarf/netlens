import { get, put, post } from "../api.js";
import { field, longHint } from "../ui.js";
import { h, clear, toast } from "../util.js";
import { buildDeviceProbeCard } from "./device_probe.js";

function copyBox(title, text) {
  const area = h("textarea", { readonly: true, rows: Math.min(14, text.split("\n").length + 1), class: "mono w-full" }, text);
  const copy = h("button", { class: "btn", type: "button" }, "Copy");
  copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(text); toast("Copied", "success"); } catch { area.select(); } });
  return h("div", { class: "field" }, h("label", {}, title), area, copy);
}

// Settings → Host probes: where a probe's login comes from (Netlens CA, Vault / OpenBao), and how to lock a host down so the probe is all it can run.
export async function buildHostProbeCard() {
  const card = h("div", { class: "card" });
  let s = await get("/api/hostprobe/settings");
  let monitored = [];
  try { monitored = (await get("/api/monitors")).monitors.filter((m) => ["ssh", "winrm"].includes(m.method)); } catch (e) { /* the list is optional */ }

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Host probes"));
    card.appendChild(longHint("Host probes (device page) log in to a host and look at it: what uses its disks, processor, memory and network, which applications fail, what changed, what is scheduled, hardware and security. They only read, and the host can be locked down so that it can run nothing else. Logins can be short-lived: nothing secret is then kept on the host or reused."));

    // 1. the Netlens certificate authority
    const ca = h("div", { class: "field" });
    card.appendChild(h("h3", {}, "Netlens certificate authority"));
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
    };
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      const vault = { url: f.url.value, mount: f.mount.value, role: f.role.value, namespace: f.ns.value, username: f.user.value };
      if (f.token.value) vault.token = f.token.value;
      if (f.roleId.value) vault.role_id = f.roleId.value;
      if (f.secretId.value) vault.secret_id = f.secretId.value;
      try {
        s = await put("/api/hostprobe/settings", { providers: { netlens_ca: { ttl_s: Number(f.ttl.value) }, vault_ssh: vault } });
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
      h("div", { class: "form-actions" }, save));

    // 3. the hosts: switch probing on, choose the probes and the login, install or update the script on the host
    card.appendChild(h("h3", {}, "Fine-tune one host"));
    const hostSlot = h("div", {});
    const pick = h("select", {}, h("option", { value: "" }, "Choose a host…"), monitored.map((m) => h("option", { value: m.device_id }, `${m.name} (${m.method})`)));
    pick.addEventListener("change", async () => {
      clear(hostSlot);
      if (!pick.value) return;
      try { hostSlot.appendChild(await buildDeviceProbeCard({ id: Number(pick.value) }, "setup")); } catch (err) { toast(err.message || "Could not load", "error"); }
    });
    card.append(h("p", { class: "hint" }, "To set up or remove many hosts at once, use Settings → Hosts. Here you fine-tune one host (which probes, how often, how it logs in). What the probes find is on the device page, under Health."), field("Host", pick), hostSlot);

    // 4. prepare a host
    card.appendChild(h("h3", {}, "Prepare a host manually"));
    const platform = h("select", {}, [["linux", "Linux"], ["windows", "Windows (OpenSSH server)"]].map(([k, t]) => h("option", { value: k }, t)));
    const user = h("input", { type: "text", value: "netlens-ro" });
    const pub = h("input", { type: "text", placeholder: "ssh-ed25519 AAAA… (only to use a key instead of certificates)" });
    const out = h("div", {});
    const show = h("button", { class: "btn", type: "button" }, "Show the files");
    show.addEventListener("click", async () => {
      clear(out);
      try {
        const r = await get(`/api/hostprobe/setup?platform=${platform.value}&user=${encodeURIComponent(user.value)}${pub.value ? `&public_key=${encodeURIComponent(pub.value)}` : ""}`);
        const names = { install: "Run on the host (installs the read-only script and the account)", authorized_keys: "authorized_keys of the account (binds the key to the probe)", sshd_config: "Add to sshd_config (trust the Netlens CA, run only the probe)", ca_public_key: "Contents of the CA public key file", sudoers: "/etc/sudoers.d/netlens-probe", script: "The probe script itself (read it before you install it)", entry: "The only command the account may run (sshd starts this whatever is asked)", uninstall: "Uninstaller: run it on the host to take the probe off again, without Netlens" };
        for (const [k, t] of Object.entries(names)) if (r.files[k]) out.appendChild(copyBox(t, r.files[k]));
        if (!r.has_ca && !pub.value) out.prepend(h("p", { class: "hint" }, "Create the CA above, or paste a public key, to get the lines that let Netlens in."));
      } catch (err) { toast(err.message || "Could not load", "error"); }
    });
    card.append(h("p", { class: "hint" }, "The host gets a root-owned script that only reads, a small entry script, and an account that can run nothing but the probes by name, however it is asked. Nothing else is changed."),
      field("System", platform), field("Account name", user), field("Public key (optional)", pub), h("div", { class: "form-actions" }, show), out);

    // one box per section, so that the page reads the same all the way down
    const parts = [...card.children].slice(2);
    let box = null;
    for (const el of parts) {
      if (el.tagName === "H3") { box = h("section", { class: "probe-section" }); card.insertBefore(box, el); }
      if (box) box.appendChild(el);
    }
  }
  draw();
  return card;
}
