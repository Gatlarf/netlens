import { get, put, post } from "../api.js";
import { h, toast, sessionInfo, timeAgo } from "../util.js";


// ---- a second factor (authenticator app) ------------------------------------------------------------------------------------------------
// Netlens only checks the codes; the user's own authenticator (Google or Microsoft Authenticator, Authy, 1Password, a hardware token ...) makes them.
let qrLoaded = null;
function loadQr() {
  if (window.qrcode) return Promise.resolve();
  if (!qrLoaded) {
    qrLoaded = new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = "vendor/qrcode.js";
      s.onload = resolve;
      s.onerror = () => reject(new Error("the QR code library did not load"));
      document.head.appendChild(s);
    });
  }
  return qrLoaded;
}

async function drawQr(canvas, text) {
  await loadQr();
  const qr = window.qrcode(0, "M");
  qr.addData(text);
  qr.make();
  const n = qr.getModuleCount();
  const scale = 5, margin = 4;
  canvas.width = canvas.height = (n + margin * 2) * scale;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#000";
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) ctx.fillRect((c + margin) * scale, (r + margin) * scale, scale, scale);
}

function passwordField(label = "Your password") {
  return h("input", { type: "password", autocomplete: "current-password", "aria-label": label, placeholder: label, style: "max-width:18rem" });
}

function recoveryBox(codes) {
  const text = codes.join("\n");
  const copy = h("button", { class: "btn", type: "button" }, "Copy");
  copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(text); toast("Copied", "success"); } catch { toast("Select the codes and copy them", "error"); } });
  const save = h("button", { class: "btn", type: "button" }, "Download");
  save.addEventListener("click", () => {
    const a = h("a", { href: URL.createObjectURL(new Blob([`Netlens recovery codes\n\n${text}\n`], { type: "text/plain" })), download: "netlens-recovery-codes.txt" });
    document.body.appendChild(a); a.click(); a.remove();
  });
  return h("div", { class: "card", style: "margin:.6em 0" },
    h("p", { class: "warn-text" }, "Keep these recovery codes somewhere safe, apart from your phone. Each works once if you lose the authenticator. They are shown only now."),
    h("pre", { class: "code-block", style: "columns:2;column-gap:2em" }, text), h("div", { class: "btn-row" }, copy, save));
}

function buildTotpSection(wrap) {
  async function draw() {
    wrap.replaceChildren(h("h3", {}, "Second factor"));
    let st;
    try { st = await get("/api/me/totp"); } catch { return; }
    wrap.appendChild(h("p", { class: "hint" },
      "Ask for a code from your authenticator app after the password. Netlens does not make the codes: use the authenticator you already have (Google or Microsoft Authenticator, Authy, 1Password, a hardware token ...)."));
    if (!st.enabled) {
      const pass = passwordField();
      const start = h("button", { class: "btn", type: "button" }, "Set up an authenticator");
      const area = h("div", {});
      start.addEventListener("click", async () => {
        start.disabled = true;
        try {
          const r = await post("/api/me/totp/begin", { password: pass.value });
          const canvas = h("canvas", { width: "10", height: "10", role: "img", "aria-label": "QR code for your authenticator", style: "max-width:14rem;height:auto;background:#fff" });
          await drawQr(canvas, r.uri).catch(() => canvas.remove());
          const code = h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "8", placeholder: "6-digit code", "aria-label": "Code from the authenticator", style: "width:9em" });
          const confirm = h("button", { class: "btn primary", type: "button" }, "Confirm and switch on");
          confirm.addEventListener("click", async () => {
            try {
              const done = await post("/api/me/totp/confirm", { code: code.value.trim() });
              toast("Second factor switched on", "success");
              document.dispatchEvent(new CustomEvent("netlens:session-changed"));
              await draw();
              wrap.appendChild(recoveryBox(done.recovery_codes));
            } catch (err) { toast(err.message || "That code is not right", "error"); }
          });
          area.replaceChildren(h("p", {}, "Scan this code with your authenticator, or type the key by hand:"), canvas,
            h("p", {}, h("code", { style: "overflow-wrap:anywhere" }, r.secret.match(/.{1,4}/g).join(" "))),
            h("p", { class: "hint" }, "Then enter the code it shows now. Nothing is switched on until the code is right."), h("div", { class: "btn-row" }, code, confirm));
          start.hidden = true; pass.hidden = true;
        } catch (err) { toast(err.message || "Could not start", "error"); start.disabled = false; }
      });
      wrap.append(h("div", { class: "btn-row" }, pass, start), area);
      return;
    }
    wrap.appendChild(h("p", {}, h("span", { class: "tag ok" }, "on"), ` since ${st.since ? timeAgo(st.since) : "—"} · ${st.recovery_left} recovery code${st.recovery_left === 1 ? "" : "s"} left`));
    const pass = passwordField();
    const code = h("input", { type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "24", placeholder: "code or recovery code", "aria-label": "Code from the authenticator", style: "width:15em" });
    const fresh = h("button", { class: "btn", type: "button" }, "New recovery codes");
    const off = h("button", { class: "btn danger", type: "button" }, "Switch off");
    fresh.addEventListener("click", async () => {
      try {
        const r = await post("/api/me/totp/recovery", { password: pass.value, code: code.value.trim() });
        await draw();
        wrap.appendChild(recoveryBox(r.recovery_codes));
      } catch (err) { toast(err.message || "Failed", "error"); }
    });
    off.addEventListener("click", async () => {
      if (!confirm("Switch the second factor off? Signing in then needs only the password.")) return;
      try { await post("/api/me/totp/disable", { password: pass.value, code: code.value.trim() }); toast("Second factor switched off", "success"); await draw(); } catch (err) { toast(err.message || "Failed", "error"); }
    });
    wrap.append(h("p", { class: "hint" }, "To make new recovery codes or switch it off, enter your password and a code."), h("div", { class: "btn-row" }, pass, code), h("div", { class: "btn-row" }, fresh, off));
  }
  draw();
}


// ---- the sessions of this user -------------------------------------------------------------------------------------------------------
function buildSessionsSection(wrap) {
  const phone = (ua) => {
    const t = ua || "";
    const browser = /Edg\//.test(t) ? "Edge" : /Firefox\//.test(t) ? "Firefox" : /Chrome\//.test(t) ? "Chrome" : /Safari\//.test(t) ? "Safari" : /curl|python|node/i.test(t) ? "a script" : "a browser";
    const os = /Windows/.test(t) ? "Windows" : /Android/.test(t) ? "Android" : /iPhone|iPad/.test(t) ? "iOS" : /Mac OS/.test(t) ? "macOS" : /Linux/.test(t) ? "Linux" : "";
    return os ? `${browser} on ${os}` : browser;
  };
  async function draw(list) {
    wrap.replaceChildren(h("h3", {}, "Where you are signed in"));
    let sessions = list;
    if (!sessions) { try { sessions = (await get("/api/me/sessions")).sessions; } catch { return; } }
    if (sessions.length < 1) return;
    const table = h("table", { class: "table" }, h("thead", {}, h("tr", {}, ...["Where", "How", "Started", "Last used", ""].map((x) => h("th", {}, x)))));
    const body = h("tbody", {});
    for (const x of sessions) {
      const end = x.current ? h("span", { class: "tag ok" }, "this session") : h("button", { class: "btn", type: "button" }, "End");
      if (!x.current) end.addEventListener("click", async () => { try { await draw((await post("/api/me/sessions/end", { id: x.id })).sessions); toast("Session ended", "success"); } catch (err) { toast(err.message || "Failed", "error"); } });
      body.appendChild(h("tr", {}, h("td", {}, `${phone(x.user_agent)}${x.ip ? ` · ${x.ip}` : ""}`), h("td", {}, x.method || "-"), h("td", {}, timeAgo(x.created)), h("td", {}, timeAgo(x.last_seen)), h("td", {}, end)));
    }
    table.appendChild(body);
    wrap.appendChild(h("div", { class: "table-wrap" }, table));
    if (sessions.length > 1) {
      const all = h("button", { class: "btn", type: "button" }, "End all other sessions");
      all.addEventListener("click", async () => { try { await draw((await post("/api/me/sessions/revoke-others", {})).sessions); toast("Other sessions ended", "success"); } catch (err) { toast(err.message || "Failed", "error"); } });
      wrap.appendChild(h("div", { class: "btn-row" }, all));
    }
  }
  draw();
}

// The signed-in account: who it is, password change (users only) and logout.
export function buildAccountCard() {
  const me = sessionInfo();
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Account"));
  if (me) {
    card.appendChild(h("p", {}, `Signed in as `, h("strong", {}, me.username), me.builtin ? " (access token, administrator)" : ` (${me.role === "admin" ? "administrator" : "viewer, read-only"})`));
  }

  if (me && !me.builtin) {
    const form = h("form", { class: "edit-form", id: "password-form" });
    const field = (label, name) => h("div", { class: "field" }, h("label", {}, label), h("input", { type: "password", name, autocomplete: name === "current" ? "current-password" : "new-password", required: true }));
    form.appendChild(field("Current password", "current"));
    form.appendChild(field("New password (at least 8 characters)", "new"));
    form.appendChild(h("button", { type: "submit", class: "btn" }, "Change password"));
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await post("/api/me/password", { current: form.elements.current.value, new: form.elements.new.value });
        form.reset();
        toast("Password changed. Your other logins were ended.", "success");
      } catch (err) {
        toast(err.message || "Could not change the password", "error");
      }
    });
    card.appendChild(form);
    const totpWrap = h("div", { class: "totp-section" });
    card.appendChild(totpWrap);
    buildTotpSection(totpWrap);
    const sessWrap = h("div", { class: "sessions-section" });
    card.appendChild(sessWrap);
    buildSessionsSection(sessWrap);
  }

  // the page Netlens opens on
  const start = h("select", { id: "start-page", "aria-label": "Start page" }, h("option", { value: "" }, "Dashboard (default)"));
  const startRow = h("div", { class: "field" }, h("label", { for: "start-page" }, "Start page"), start,
    h("p", { class: "hint" }, "The page Netlens opens on when you open it without a link to a page. Kept on the server, so it follows you to every browser."));
  card.appendChild(startRow);
  get("/api/me/preferences").then((p) => {
    for (const o of p.start_pages) if (o.value !== "#/dashboard") start.appendChild(h("option", { value: o.value }, o.label));
    start.value = p.start_page && p.start_page !== "#/dashboard" ? p.start_page : "";
    start.addEventListener("change", async () => {
      try {
        await put("/api/me/preferences", { start_page: start.value || null });
        toast(start.value ? "Saved: Netlens will open on this page" : "Netlens opens on the dashboard", "success");
      } catch (err) {
        toast(err.message || "Could not save", "error");
      }
    });
  }).catch(() => { startRow.hidden = true; });

  const logoutBtn = h("button", { class: "btn", type: "button" }, "Log out");
  logoutBtn.addEventListener("click", async () => {
    try {
      await post("/api/logout");
      toast("Logged out", "info");
      document.dispatchEvent(new CustomEvent("netlens:unauth"));
    } catch (err) {
      toast(err.message || "Logout failed", "error");
    }
  });
  card.appendChild(logoutBtn);
  return card;
}
