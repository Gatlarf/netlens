import { get, post, del, ApiError } from "./api.js";
import { h, clear, toast } from "./util.js";
import { infoTip, savedLoginButton } from "./ui.js";
import { ensureFresh, prompt as stepUpPrompt } from "./stepup.js";
import { reasonFor } from "./reason.js";
import { ask as askApproval } from "./approval.js";

const activeTerminals = new WeakMap();

// busy = a session is running, or the user is filling in the connection form (a page refresh would wipe it)
export function isTerminalActive(slot) {
  return activeTerminals.has(slot) || !!slot.querySelector(".ssh-form, .terminal-wrap, .connect-pending");
}

let xtermLoaded = null;

function loadXterm() {
  if (xtermLoaded) return xtermLoaded;

  xtermLoaded = new Promise((resolve, reject) => {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "vendor/xterm.css";
    document.head.appendChild(link);

    const scriptXterm = document.createElement("script");
    scriptXterm.src = "vendor/xterm.js";
    scriptXterm.onload = () => {
      const scriptFit = document.createElement("script");
      scriptFit.src = "vendor/addon-fit.js";
      scriptFit.onload = () => {
        if (typeof Terminal === "undefined" || typeof FitAddon === "undefined") {
          reject(new Error("Terminal libraries failed to load"));
        } else {
          resolve();
        }
      };
      scriptFit.onerror = () => reject(new Error("Failed to load fit addon"));
      document.head.appendChild(scriptFit);
    };
    scriptXterm.onerror = () => reject(new Error("Failed to load xterm.js"));
    document.head.appendChild(scriptXterm);
  });

  return xtermLoaded;
}

// The stored login that last opened a session on a device (only its id and a label are kept in this browser, never a password)
const lastKey = (device) => `netlens.ssh.last.${device.id}`;
function readLast(device) {
  try {
    const v = JSON.parse(localStorage.getItem(lastKey(device)) || "null");
    return v && typeof v.id === "string" && typeof v.label === "string" ? v : null;
  } catch (e) {
    return null;
  }
}
function writeLast(device, value) {
  try { localStorage.setItem(lastKey(device), JSON.stringify(value)); } catch (e) { /* not remembered */ }
}
function forgetLast(device) {
  try { localStorage.removeItem(lastKey(device)); } catch (e) { /* nothing kept */ }
}

export async function mountTerminal(slot, device, { onWideChange } = {}) {
  let pendingLast = null;          // becomes the "last used" login when the session really opens
  let cfg;
  try {
    cfg = await get("/api/config");
  } catch (e) {
    return null;
  }

  if (!cfg.terminal_available) return null;

  const ports = device.ports || [];
  let sshPort = null;
  let telnetPort = null;

  for (const p of ports) {
    if (p.state && p.state.startsWith("open") && p.proto === "tcp") {
      if (p.port === 22 || p.service === "ssh") {
        if (!sshPort || p.port === 22) sshPort = p;
      }
      if (p.port === 23 || p.service === "telnet") {
        if (!telnetPort || p.port === 23) telnetPort = p;
      }
    }
  }

  if (!sshPort && !telnetPort) return null;

  const card = h("div", { class: "card" });
  const h2 = h("h2", {}, "Console");
  card.appendChild(h2);
  if (onWideChange) {
    let wide = false;
    const wideBtn = h("button", { type: "button", class: "btn terminal-wide-btn", title: "Show the console across the whole page width" }, "Wide view");
    wideBtn.addEventListener("click", () => {
      wide = !wide;
      wideBtn.textContent = wide ? "Narrow view" : "Wide view";
      onWideChange(wide);
      card.scrollIntoView({ block: "nearest" });
    });
    h2.appendChild(wideBtn);
  }

  const btnRow = h("div", { class: "btn-row" });
  const protos = [];
  if (sshPort) protos.push({ proto: "ssh", port: sshPort.port, label: `SSH (${sshPort.port})` });
  if (telnetPort) protos.push({ proto: "telnet", port: telnetPort.port, label: `Telnet (${telnetPort.port})` });
  if (sshPort) {
    const btn = h("button", { class: "btn" }, `SSH (${sshPort.port})`);
    btn.addEventListener("click", () => showConnectionArea("ssh", sshPort.port));
    btnRow.appendChild(btn);
  }
  if (telnetPort) {
    const btn = h("button", { class: "btn" }, `Telnet (${telnetPort.port})`);
    btn.addEventListener("click", () => showConnectionArea("telnet", telnetPort.port));
    btnRow.appendChild(btn);
  }
  card.appendChild(btnRow);

  const connectionArea = h("div", { class: "connection-area" });
  card.appendChild(connectionArea);

  slot.appendChild(card);

  function showConnectionArea(proto, port) {
    clear(connectionArea);

    if (proto === "ssh") {
      const form = h("form", { class: "ssh-form" });
      const stored = h("select", { name: "stored" }, h("option", { value: "" }, "Type a login below"));
      let last = readLast(device);           // the stored login that opened a session here last time
      const lastSlot = h("span", {});
      const drawLast = () => {
        clear(lastSlot);
        if (last) lastSlot.appendChild(savedLoginButton(`Connect as ${last.label}`, () => connectWith(last.id, last.label), () => { forgetLast(device); last = null; drawLast(); }));
      };
      get("/api/credentials").then((r) => {
        for (const c of r.credentials) stored.appendChild(h("option", { value: c.id }, `${c.name}${c.username ? ` (${c.username})` : ""}`));
        if (last && ![...stored.options].some((o) => o.value === last.id)) { forgetLast(device); last = null; }     // it was deleted under Settings -> Credentials
        drawLast();
      }).catch(() => {});
      const usernameInput = h("input", { type: "text", name: "username", autocomplete: "off" });
      const saveBox = h("input", { type: "checkbox", name: "save" });
      stored.addEventListener("change", () => { for (const el of [usernameInput, passwordInput, keyTextarea, passphraseInput, saveBox]) el.disabled = stored.value !== ""; });
      const passwordInput = h("input", { type: "password", name: "password", autocomplete: "off" });
      const keySection = h("details", { class: "collapsible" });
      const keySummary = h("summary", {}, "Use a private key");
      const keyTextarea = h("textarea", { name: "private_key", rows: 5 });
      const fileInput = h("input", { type: "file", accept: ".pem,.key" });
      fileInput.addEventListener("change", (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
          keyTextarea.value = reader.result;
        };
        reader.readAsText(file);
      });
      keySection.appendChild(keySummary);
      keySection.appendChild(keyTextarea);
      keySection.appendChild(fileInput);

      const passphraseInput = h("input", { type: "password", name: "passphrase", autocomplete: "off" });
      const connectBtn = h("button", { type: "submit", class: "btn primary" }, "Connect");
      const field = (label, input, tip) => h("div", { class: "field" }, h("label", {}, label, tip ? infoTip(tip) : null), input);

      form.appendChild(field("Stored login", stored, "A typed login is sent to the Netlens server only to open this session, unless you save it. Stored logins are under Settings → Credentials."));
      form.appendChild(h("div", { class: "ssh-cols" }, field("User name", usernameInput), field("Password", passwordInput)));
      form.appendChild(h("div", { class: "field" }, keySection));
      form.appendChild(field("Passphrase (for the key)", passphraseInput));
      form.appendChild(h("div", { class: "field" }, h("label", { class: "check" }, saveBox, " Save this login in the credential store (encrypted, only you can use it)")));
      form.appendChild(h("div", { class: "btn-row" }, connectBtn, lastSlot));

      async function connectWith(credentialId, label) {
        pendingLast = { id: credentialId, label };
        clear(connectionArea);
        await startTerminal(proto, port, "", "", "", "", credentialId);
      }

      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const username = usernameInput.value;
        const password = passwordInput.value;
        const key = keyTextarea.value;
        const passphrase = passphraseInput.value;
        if (!stored.value && !username) { toast("Enter a user name or pick a stored login", "error"); return; }
        let credentialId = stored.value;
        let label = credentialId ? stored.selectedOptions[0].textContent : "";
        if (!stored.value && saveBox.checked) {
          try {
            const name = `SSH ${device.name || device.ip || device.id}`;
            const made = await post("/api/credentials", key ? { name, kind: "ssh_key", username, private_key: key, passphrase }
              : { name, kind: "login", username, password });
            toast("Login saved in the credential store", "success");
            if (made && made.id) { credentialId = made.id; label = `${name} (${username})`; }       // from now on it is the last used login
          } catch (err) { toast(err.message || "Could not save the login", "error"); }
        }
        pendingLast = credentialId ? { id: credentialId, label } : null;
        clear(connectionArea);
        if (credentialId && !stored.value) await startTerminal(proto, port, "", "", "", "", credentialId);
        else await startTerminal(proto, port, username, password, key, passphrase, credentialId);
      });

      connectionArea.appendChild(form);
      usernameInput.focus();
    } else {
      const connectBtn = h("button", { class: "btn connect-pending" }, "Connect");
      connectBtn.addEventListener("click", async () => {
        clear(connectionArea);
        await startTerminal(proto, port, null, null, null, null);
      });
      connectionArea.appendChild(connectBtn);
      connectBtn.focus();
    }
  }

  async function startTerminal(proto, port, username, password, key, passphrase, credentialId = "", confirmed = false) {
    if (!confirmed && !(await ensureFresh())) { toast("This action needs a fresh confirmation, which was not given (or is not possible with this sign-in)", "error"); return; }
    const reason = await reasonFor(credentialId);
    if (reason === null) return;
    try {
      await loadXterm();
    } catch (e) {
      toast("Failed to load terminal libraries", "error");
      return;
    }

    const wrapEl = h("div", { class: "terminal-wrap" });
    const statusLine = h("p", { class: "muted" }, "Connecting...");
    const disconnectBtn = h("button", { class: "btn danger" }, "Disconnect");

    connectionArea.appendChild(wrapEl);
    connectionArea.appendChild(statusLine);
    connectionArea.appendChild(disconnectBtn);

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: "ui-monospace, Menlo, Consolas, monospace",
      fontSize: 14,
      theme: { background: "#0b1020" }
    });
    const fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open(wrapEl);
    fit.fit();

    const wsUrl = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/api/terminal/" + device.id + "/ws?proto=" + proto + "&port=" + port;
    const ws = new WebSocket(wsUrl);
    ws.binaryType = "arraybuffer";

    activeTerminals.set(slot, ws);

    const resizeObserver = new ResizeObserver(() => {
      fit.fit();
      if (ws.readyState === 1) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    });
    resizeObserver.observe(wrapEl);

    const windowResizeHandler = () => {
      fit.fit();
      if (ws.readyState === 1) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    };
    window.addEventListener("resize", windowResizeHandler);

    term.onData((d) => {
      if (ws.readyState === 1) {
        ws.send(new TextEncoder().encode(d));
      }
    });

    ws.addEventListener("open", () => {
      const authMsg = {
        type: "auth",
        username: username || null,
        password: password || null,
        private_key: key || null,
        passphrase: passphrase || null,
        credential_id: credentialId || null,
        reason: reason || null,
        cols: term.cols,
        rows: term.rows
      };
      ws.send(JSON.stringify(authMsg));

      // Blank credentials immediately
      username = null;
      password = null;
      key = null;
      passphrase = null;
    });

    ws.addEventListener("message", (event) => {
      if (event.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(event.data));
      } else {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === "status") {
            let statusText = "Connected";
            if (proto === "ssh" && msg.fingerprint) {
              statusText += " · host key " + msg.fingerprint + (msg.new_key ? " (trusted on first use)" : " (verified)");
            }
            statusLine.textContent = statusText;
            if (pendingLast) { writeLast(device, pendingLast); pendingLast = null; }
            term.focus();
          } else if (msg.type === "error" && msg.code === "approval_required") {
            statusLine.textContent = "Waiting for approval";
            askApproval("terminal", msg.target, device && (device.name || device.ip) || "").then((ok) => { if (ok) { clear(connectionArea); startTerminal(proto, port, username, password, key, passphrase, credentialId, true); } else statusLine.textContent = "No approval: the terminal was not opened"; });
          } else if (msg.type === "error" && msg.code === "step_up") {
            // the confirmation ran out while the form was open: ask once more and start again
            statusLine.textContent = "Confirmation needed";
            stepUpPrompt(String(msg.message).split(":")[1] || "password").then((ok) => { if (ok) { clear(connectionArea); startTerminal(proto, port, username, password, key, passphrase, credentialId, true); } });
          } else if (msg.type === "error") {
            term.writeln("\x1b[31m" + msg.message + "\x1b[0m");
            statusLine.textContent = msg.message;
          } else if (msg.type === "hostkey_mismatch") {
            clear(connectionArea);
            const warningCard = h("div", { class: "card warning" });
            warningCard.appendChild(h("h3", {}, "WARNING: the SSH host key of this device has CHANGED."));
            warningCard.appendChild(h("p", { class: "mono" }, "Expected: " + msg.expected));
            warningCard.appendChild(h("p", { class: "mono" }, "Actual: " + msg.actual));
            warningCard.appendChild(h("p", {}, "This can mean the device was reinstalled, or that someone is intercepting the connection."));
            const forgetBtn = h("button", { class: "btn" }, "Forget stored key and try again");
            forgetBtn.addEventListener("click", async () => {
              try {
                await del("/api/devices/" + device.id + "/hostkey");
                clear(connectionArea);
                showConnectionArea("ssh", port);
              } catch (e) {
                toast("Failed to forget host key", "error");
              }
            });
            warningCard.appendChild(forgetBtn);
            connectionArea.appendChild(warningCard);
          } else if (msg.type === "closed") {
            statusLine.textContent = "Session closed: " + msg.reason;
          }
        } catch (e) {
          // Ignore non-JSON messages
        }
      }
    });

    ws.addEventListener("close", () => {
      statusLine.textContent = "Disconnected";
      const reconnectBtn = h("button", { class: "btn" }, "Reconnect");
      reconnectBtn.addEventListener("click", () => {
        clear(connectionArea);
        showConnectionArea(proto, port);
      });
      connectionArea.appendChild(reconnectBtn);
    });

    disconnectBtn.addEventListener("click", () => {
      ws.close();
      term.dispose();
      resizeObserver.disconnect();
      window.removeEventListener("resize", windowResizeHandler);
      activeTerminals.delete(slot);
    });

    return {
      dispose() {
        if (ws.readyState === 1 || ws.readyState === 0) {
          ws.close();
        }
        term.dispose();
        resizeObserver.disconnect();
        window.removeEventListener("resize", windowResizeHandler);
        activeTerminals.delete(slot);
      }
    };
  }

  return {
    protos,
    // jump to the console and open the connection form (used by the buttons at the top of the page)
    open(proto) {
      const wanted = protos.find((p) => p.proto === proto) || protos[0];
      card.scrollIntoView({ behavior: "smooth", block: "start" });
      if (!activeTerminals.has(slot)) showConnectionArea(wanted.proto, wanted.port);
    },
    dispose() {
      const ws = activeTerminals.get(slot);
      if (ws) {
        if (ws.readyState === 1 || ws.readyState === 0) {
          ws.close();
        }
        activeTerminals.delete(slot);
      }
    }
  };
}