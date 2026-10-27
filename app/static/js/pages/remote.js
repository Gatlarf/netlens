// Remote access: the devices that can be reached by SSH, Telnet, RDP or VNC on the left, the sessions on the right.
// SSH and Telnet reuse the web terminal. RDP and VNC are drawn with the Guacamole client library, through the guacd helper
// container (see the "Set up" tab, which also shows how to add that container).
import { get, post, del } from "../api.js";
import { h, clear, toast, shortName, statusDot } from "../util.js";
import { mountTerminal } from "../terminal.js";
import { savedLoginButton } from "../ui.js";

let guacLoaded = null;
function loadGuac() {
  if (typeof Guacamole !== "undefined") return Promise.resolve();
  if (!guacLoaded) {
    guacLoaded = new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = "vendor/guacamole-common.min.js";
      s.onload = () => (typeof Guacamole !== "undefined" ? resolve() : reject(new Error("The remote desktop library did not load")));
      s.onerror = () => reject(new Error("The remote desktop library did not load"));
      document.head.appendChild(s);
    });
  }
  return guacLoaded;
}

const COMPOSE = `  guacd:
    image: guacamole/guacd:1.5.5
    container_name: netlens-guacd
    restart: unless-stopped
    ports:
      - "127.0.0.1:4822:4822"   # only this machine can reach it`;
const COMPOSE_BRIDGE = `  guacd:
    image: guacamole/guacd:1.5.5
    container_name: netlens-guacd
    restart: unless-stopped
    # no ports: Netlens reaches it by the name "guacd" on the same Docker network`;
const SHORT = { ssh: "SSH", telnet: "Telnet", rdp: "RDP", vnc: "VNC" };

function codeBlock(text) {
  const pre = h("pre", { class: "remote-code" }, text);
  const copy = h("button", { type: "button", class: "btn", onclick: async () => {
    try { await navigator.clipboard.writeText(text); toast("Copied", "success"); } catch (e) { toast("Select the text and copy it", "info"); }
  } }, "Copy");
  return h("div", { class: "remote-code-wrap" }, pre, copy);
}

function setupGuide(helper, recheck, onClose) {
  const state = helper.reachable
    ? h("p", { class: "remote-ok" }, `✓ The helper answers at ${helper.address}. RDP and VNC are ready to use.`)
    : h("p", { class: "remote-bad" }, helper.configured ? `The helper at ${helper.address} cannot be reached: ${helper.error}.` : "The helper is switched off (NETLENS_GUACD).");
  return h("div", { class: "card remote-setup" },
    h("div", { class: "remote-setup-head" }, h("h2", {}, "Set up RDP and VNC"), h("button", { type: "button", class: "btn", onclick: onClose }, "Close")),
    h("p", {}, "SSH and Telnet work out of the box. To use a Windows machine through RDP, or any machine through VNC, Netlens needs a small helper: ",
      h("strong", {}, "guacd"), " from the Apache Guacamole project. It is a separate container because it does the heavy lifting of the remote desktop protocols. Netlens is the only thing that talks to it, and your passwords are only passed on while a session opens."),
    state,
    h("button", { type: "button", class: "btn", onclick: recheck }, "Check again"),
    h("h3", {}, "1. Add the helper container"),
    h("p", {}, "Add this service to the compose file you run Netlens from (next to the ", h("code", {}, "netlens"), " service), then run ", h("code", {}, "docker compose up -d"), "."),
    h("p", { class: "hint" }, "Netlens is normally started with ", h("code", {}, "network_mode: host"), " (the default compose file does). Then it reaches the helper on the loopback address of the Docker host, so the helper publishes its port on 127.0.0.1 only:"),
    codeBlock(COMPOSE),
    h("p", { class: "hint" }, "In Portainer: Stacks → your Netlens stack → Editor, paste the service under ", h("code", {}, "services:"), " and press Update the stack."),
    h("h3", {}, "2. Tell Netlens where it is"),
    h("p", {}, "With the setup above there is nothing to do: Netlens looks for the helper at ", h("code", {}, "127.0.0.1:4822"), " by default. Only if you put the helper somewhere else, set the environment variable on the Netlens container:"),
    codeBlock("NETLENS_GUACD=guacd-host:4822"),
    h("details", {}, h("summary", {}, "My Netlens container is not on the host network"),
      h("p", { class: "hint" }, "Put the helper in the same compose file and network, without publishing a port, and set the address to its service name:"),
      codeBlock(COMPOSE_BRIDGE), codeBlock("NETLENS_GUACD=guacd:4822")),
    h("h3", {}, "3. Use it"),
    h("p", {}, "Press ", h("strong", {}, "Check again"), " above. Devices with port 3389 (RDP) or 5900–5909 (VNC) open then get an RDP or VNC button in the list. Port information comes from the scans, so a device shows up after a scan has seen the port open (a deep scan looks at more ports than a quick one)."),
    h("h3", {}, "Good to know"),
    h("ul", {},
      h("li", {}, "Only administrators on a direct connection from the local network can use remote access, the same rule as the web terminal (NETLENS_TERMINAL, NETLENS_TERMINAL_REMOTE)."),
      h("li", {}, "The helper has no login of its own. That is why it should only be reachable by Netlens: keep it on 127.0.0.1 (or on a private Docker network) and never publish its port to your network or the internet."),
      h("li", {}, "RDP certificates of the target are accepted without checking, as Windows machines use self-signed ones. NLA (network level authentication) is supported."),
      h("li", {}, "Clipboard works both ways. Drives, printers and sound are not redirected."),
      h("li", {}, "Passwords are asked for each session. You can choose “Remember this login”: it is then stored encrypted with the Netlens key (see Settings → Backup & restore).")));
}

// ---------- one graphical (RDP/VNC) session
function graphicalSession(device, svc, saved, helperOk, onClose) {
  const root = h("div", { class: "remote-session" });
  let client = null, keyboard = null, observer = null, resizeTimer = null, fit = true;

  function showForm(message) {
    teardown();
    clear(root);
    const user = h("input", { type: "text", name: "username", autocomplete: "off", value: saved ? saved.username : "" });
    const pass = h("input", { type: "password", name: "password", autocomplete: "off" });
    const domain = h("input", { type: "text", name: "domain", autocomplete: "off", value: saved ? saved.domain : "" });
    const remember = h("input", { type: "checkbox", name: "remember" });
    const stored = h("select", { name: "stored" }, h("option", { value: "" }, "Type a login below"));
    get("/api/credentials").then((r) => { for (const c of r.credentials.filter((x) => x.kind === "login")) stored.appendChild(h("option", { value: c.id }, `${c.name}${c.username ? ` (${c.username})` : ""}`)); }).catch(() => {});
    stored.addEventListener("change", () => { const typed = stored.value === ""; for (const el of [user, pass, domain, remember]) el.disabled = !typed; });
    const error = h("p", { class: "error", role: "alert" }, message || "");
    const form = h("form", { class: "remote-form card" },
      h("h2", {}, `${SHORT[svc.proto]} to ${shortName(device.name) || device.ip}`),
      h("p", { class: "hint mono" }, `${device.ip}:${svc.port}`),
      h("div", { class: "field" }, h("label", {}, "Stored login"), stored, h("p", { class: "hint" }, "Logins are kept under Settings → Credentials.")),
      h("div", { class: "field" }, h("label", {}, svc.proto === "rdp" ? "User name" : "User name (only some VNC servers ask for one)"), user),
      h("div", { class: "field" }, h("label", {}, "Password"), pass),
      svc.proto === "rdp" ? h("div", { class: "field" }, h("label", {}, "Domain (optional)"), domain) : null,
      h("div", { class: "field" }, h("label", { class: "check" }, remember, " Save this login in the credential store (encrypted, only you can use it)")),
      error,
      h("div", { class: "btn-row" },
        h("button", { type: "submit", class: "btn primary" }, "Connect"),
        saved ? savedLoginButton(`Connect as ${saved.username || "saved login"}`, () => connect({ use_saved: true }), async () => {
          try { await del(`/api/remote/${device.id}/saved/${svc.proto}`); saved = null; svc.saved = null; toast("Saved login forgotten", "success"); showForm(); } catch (e) { toast(e.message || "Failed", "error"); }
        }) : null),
      h("p", { class: "hint" }, "The password is sent once to open the session and is not kept unless you choose to remember it."));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      if (stored.value) connect({ credential_id: stored.value });
      else connect({ username: user.value, password: pass.value, domain: domain.value, remember: remember.checked });
    });
    root.appendChild(form);
    user.focus();
  }

  function teardown() {
    if (resizeTimer) clearTimeout(resizeTimer);
    if (observer) observer.disconnect();
    if (keyboard) { keyboard.onkeydown = keyboard.onkeyup = null; keyboard.reset && keyboard.reset(); }
    if (client) { try { client.disconnect(); } catch (e) { /* already gone */ } }
    client = keyboard = observer = null;
  }

  async function connect(credentials) {
    try {
      await loadGuac();
    } catch (err) {
      return showForm(err.message);
    }
    clear(root);
    const status = h("span", { class: "hint" }, "Connecting…");
    const screen = h("div", { class: "remote-screen", tabindex: "0" });
    const bar = h("div", { class: "remote-bar" },
      h("strong", {}, `${SHORT[svc.proto]} · ${shortName(device.name) || device.ip}`), status,
      h("span", { class: "remote-bar-end" },
        h("button", { type: "button", class: "btn", title: "Send Ctrl+Alt+Del", onclick: () => { for (const k of [0xFFE3, 0xFFE9, 0xFFFF]) client && client.sendKeyEvent(1, k); for (const k of [0xFFFF, 0xFFE9, 0xFFE3]) client && client.sendKeyEvent(0, k); } }, "Ctrl+Alt+Del"),
        h("button", { type: "button", class: "btn", id: "remote-fit", title: "Scale the screen to the window", "aria-pressed": "true", onclick: (e) => { fit = !fit; e.currentTarget.setAttribute("aria-pressed", String(fit)); scale(); } }, "Fit"),
        h("button", { type: "button", class: "btn", title: "Full screen", onclick: () => (screen.requestFullscreen ? screen.requestFullscreen() : null) }, "Full screen"),
        h("button", { type: "button", class: "btn danger", onclick: () => { teardown(); showForm(); } }, "Disconnect")));
    root.append(bar, screen);

    const width = Math.max(640, screen.clientWidth || 1024), height = Math.max(400, screen.clientHeight || 640);
    let ticket;
    try {
      ticket = await post(`/api/remote/${device.id}/session`, {
        proto: svc.proto, port: svc.port, username: "", password: "", domain: "", width, height, dpi: 96,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, ...credentials,
      });
    } catch (err) {
      return showForm(err.message || "Could not start the session");
    }
    const url = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}${location.pathname.replace(/[^/]*$/, "")}api/remote/ws`;
    const tunnel = new Guacamole.WebSocketTunnel(url);
    client = new Guacamole.Client(tunnel);
    const display = client.getDisplay();
    screen.appendChild(display.getElement());

    const scale = () => {
      const w = display.getWidth(), hgt = display.getHeight();
      if (!w || !hgt) return;
      display.scale(fit ? Math.min(screen.clientWidth / w, screen.clientHeight / hgt) : 1);
    };
    display.onresize = scale;

    const mouse = "ontouchstart" in window ? new Guacamole.Mouse.Touchscreen(display.getElement()) : new Guacamole.Mouse(display.getElement());
    const send = (state) => client && client.sendMouseState(state, true);
    mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = (state) => {
      const k = display.getScale ? display.getScale() : 1;
      send(new Guacamole.Mouse.State(state.x / k, state.y / k, state.left, state.middle, state.right, state.up, state.down));
    };
    keyboard = new Guacamole.Keyboard(screen);
    keyboard.onkeydown = (sym) => client && client.sendKeyEvent(1, sym);
    keyboard.onkeyup = (sym) => client && client.sendKeyEvent(0, sym);
    screen.addEventListener("mousedown", () => screen.focus());
    // clipboard: what is pasted into the window goes to the remote machine; what the remote machine copies is put on this one
    screen.addEventListener("paste", (e) => {
      const text = e.clipboardData && e.clipboardData.getData("text/plain");
      if (!text || !client) return;
      const stream = client.createClipboardStream("text/plain");
      const writer = new Guacamole.StringWriter(stream);
      writer.sendText(text);
      writer.sendEnd();
    });
    client.onclipboard = (stream, mimetype) => {
      if (mimetype !== "text/plain") return;
      const reader = new Guacamole.StringReader(stream);
      let data = "";
      reader.ontext = (t) => { data += t; };
      reader.onend = () => { navigator.clipboard && navigator.clipboard.writeText(data).catch(() => {}); };
    };
    client.onstatechange = (state) => {
      if (state === 3) { status.textContent = "Connected"; screen.focus(); }
      else if (state === 5) { status.textContent = "Disconnected"; }
    };
    client.onerror = (err) => {
      const message = (err && err.message) || "The connection was closed";
      teardown();
      showForm(message);
    };
    observer = new ResizeObserver(() => {
      scale();
      if (resizeTimer) clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => { if (client && screen.clientWidth > 100) client.sendSize(screen.clientWidth, screen.clientHeight); }, 400);
    });
    observer.observe(screen);
    client.connect(`ticket=${encodeURIComponent(ticket.ticket)}`);
  }

  if (!helperOk) {
    root.append(h("div", { class: "card" }, h("p", { class: "error" }, "The remote desktop helper (guacd) is not reachable, so RDP and VNC cannot start. Open the Set up tab for the three steps.")));
  } else {
    showForm();
  }
  return { el: root, close: () => teardown() };
}

// ---------- the page
// Sessions stay open while you look at another page (debugging with the statistics next to a terminal, say): they live here and not in the page,
// and the page picks them up again when you come back. A browser reload or closing the tab ends them, as the connection is the browser's.
const kept = { sessions: new Map(), counter: 0, activeId: null, setupShown: false };
let current = null;                  // the mounted page's own select / close, null while another page is shown

function dropKept(id) {
  const s = kept.sessions.get(id);
  if (!s) return;
  try { s.close(); } catch (e) { /* ignore */ }
  s.tab.remove();
  s.pane.remove();
  kept.sessions.delete(id);
  if (id === "__setup") kept.setupShown = false;
  if (kept.activeId === id) kept.activeId = [...kept.sessions.keys()].pop() || null;
}

const closeAny = (id) => (current ? current.close(id) : dropKept(id));

export async function render(container) {
  let data;
  try {
    data = await get("/api/remote");
  } catch (err) {
    container.append(h("div", { class: "card" }, h("h1", {}, "Remote access"), h("p", { class: "error" }, err.message || "Remote access is not available")));
    return;
  }
  let disposed = false, filter = "";
  const sessions = kept.sessions;   // id -> { tab, pane, close }

  const list = h("div", { class: "remote-list" });
  const tabs = h("div", { class: "remote-tabs", role: "tablist" });
  const panes = h("div", { class: "remote-panes" });
  const helperLine = h("div", { class: "remote-helper" });
  const search = h("input", { type: "search", placeholder: "Search devices", "aria-label": "Search devices", oninput: (e) => { filter = e.target.value.trim().toLowerCase(); drawList(); } });

  const needsHelper = () => data.devices.some((d) => d.services.some((s) => s.proto === "rdp" || s.proto === "vnc"));

  function drawHelper() {
    clear(helperLine);
    const hp = data.helper;
    helperLine.append(h("span", { class: hp.reachable ? "remote-ok" : "remote-bad", title: hp.reachable ? `The helper answers at ${hp.address}` : "RDP and VNC need a small helper container" },
      hp.reachable ? "✓ RDP/VNC helper connected" : "RDP/VNC helper not set up"));
    if (!hp.reachable) helperLine.append(" ", h("button", { type: "button", class: "btn", onclick: showSetup }, "Set up RDP & VNC"));      // once it is set up there is nothing left to do
  }

  function drawList() {
    clear(list);
    const items = data.devices.filter((d) => !filter || `${d.name} ${d.ip}`.toLowerCase().includes(filter));
    if (!items.length) {
      list.append(h("p", { class: "hint" }, data.devices.length ? "No device matches." : "No device with SSH, Telnet, RDP or VNC open has been found yet. Run a scan; a deep scan looks at more ports."));
      return;
    }
    for (const d of items) {
      list.append(h("div", { class: `remote-dev ${d.online ? "" : "offline"}` },
        h("div", { class: "remote-dev-name" }, statusDot(d.online), h("span", { title: d.name }, shortName(d.name) || d.ip), h("span", { class: "mono hint" }, d.ip)),
        h("div", { class: "remote-dev-btns" }, d.services.map((s) => h("button", {
          type: "button", class: `btn remote-svc ${s.saved ? "has-saved" : ""}`, title: `${s.label} on port ${s.port}${s.saved ? " (login saved)" : ""}`,
          onclick: () => open(d, s),
        }, SHORT[s.proto])))));
    }
  }

  function select(id) {
    kept.activeId = id;
    for (const [key, s] of sessions) {
      const on = key === id;
      s.tab.setAttribute("aria-selected", String(on));
      s.pane.hidden = !on;
    }
    if (id !== "__setup" && sessions.has(id)) window.dispatchEvent(new Event("resize"));
  }

  function addSession(id, label, builder) {
    const tab = h("div", { class: "remote-tab", role: "tab" },
      h("button", { type: "button", class: "remote-tab-name", onclick: () => current && current.select(id) }, label),
      h("button", { type: "button", class: "remote-tab-x", "aria-label": `Close ${label}`, onclick: () => closeAny(id) }, "×"));
    const pane = h("div", { class: "remote-pane", hidden: true });
    tabs.append(tab);
    panes.append(pane);
    const made = builder(pane);
    sessions.set(id, { tab, pane, close: made && made.close ? made.close : () => {} });
    select(id);
  }

  function close(id) {
    const s = sessions.get(id);
    if (!s) return;
    try { s.close(); } catch (e) { /* ignore */ }
    s.tab.remove();
    s.pane.remove();
    sessions.delete(id);
    if (id === "__setup") kept.setupShown = false;
    if (kept.activeId === id) select([...sessions.keys()].pop() || null);
    drawEmpty();
  }

  function drawEmpty() {
    emptyNote.hidden = sessions.size > 0;
  }

  async function recheck() {
    try {
      data = await get("/api/remote");
      drawHelper();
      drawList();
      if (kept.setupShown) { close("__setup"); showSetup(); }
    } catch (err) {
      toast(err.message || "Could not check", "error");
    }
  }

  function showSetup() {
    if (kept.setupShown) return select("__setup");
    kept.setupShown = true;
    addSession("__setup", "Set up RDP & VNC", (pane) => { pane.append(setupGuide(data.helper, recheck, () => closeAny("__setup"))); });
    drawEmpty();
  }

  function open(device, svc) {
    if (!data.available) return toast(data.why, "error");
    if ((svc.proto === "rdp" || svc.proto === "vnc") && !data.helper.reachable) return showSetup();
    const id = `s${++kept.counter}`;
    const label = `${SHORT[svc.proto]} · ${shortName(device.name) || device.ip}`;
    addSession(id, label, (pane) => {
      if (svc.proto === "ssh" || svc.proto === "telnet") {
        const slot = h("div", {});
        pane.append(slot);
        let handle = null;
        mountTerminal(slot, { id: device.id, ports: [{ proto: "tcp", port: svc.port, state: "open", service: svc.proto }] }).then((t) => {
          handle = t;
          const btn = slot.querySelector(".btn-row .btn");
          if (btn) btn.click();
        }).catch((err) => toast(err.message || "The terminal could not start", "error"));
        return { close: () => { if (handle && handle.dispose) handle.dispose(); } };            // closing the tab ends the session
      }
      const session = graphicalSession(device, svc, svc.saved, data.helper.reachable, () => closeAny(id));
      pane.append(session.el);
      return session;
    });
    drawEmpty();
  }

  const emptyNote = h("div", { class: "remote-empty" },
    h("p", {}, data.available ? "Choose a device on the left to open a session." : data.why),
    needsHelper() && !data.helper.reachable && data.available ? h("p", {}, "RDP and VNC need a small helper container. ", h("button", { type: "button", class: "btn", onclick: showSetup }, "Show me how to set it up")) : null);

  container.append(
    h("div", { class: "remote" },
      h("aside", { class: "remote-side" }, h("div", { class: "remote-title" }, h("h1", {}, "Remote access"), helperLine), search, list),
      h("section", { class: "remote-main" }, tabs, panes, emptyNote)));
  drawHelper();
  drawList();

  // sessions that were left open on this page earlier: back into the tabs
  current = { select, close };
  if (kept.setupShown) dropKept("__setup");
  for (const s of sessions.values()) { tabs.append(s.tab); panes.append(s.pane); }
  if (sessions.size) select(sessions.has(kept.activeId) ? kept.activeId : [...sessions.keys()].pop());
  drawEmpty();

  // arriving from a device page: #/remote?device=ID&proto=rdp
  const wanted = new URLSearchParams((location.hash.split("?")[1] || ""));
  if (wanted.get("device")) {
    const d = data.devices.find((x) => String(x.id) === wanted.get("device"));
    const s = d && d.services.find((x) => x.proto === wanted.get("proto")) || (d && d.services[0]);
    if (d && s) open(d, s);
  }

  return () => {
    disposed = true;
    current = null;                  // the sessions stay open (see the top of the file); only the set-up tab is not worth keeping
    dropKept("__setup");
  };
}
