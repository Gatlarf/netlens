import { get, del, ApiError } from "./api.js";
import { h, clear, toast } from "./util.js";

const activeTerminals = new WeakMap();

export function isTerminalActive(slot) {
  return activeTerminals.has(slot);
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

export async function mountTerminal(slot, device) {
  let cfg;
  try {
    cfg = await get("/api/config");
  } catch (e) {
    return null;
  }

  if (!cfg.terminal_enabled) return null;

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

  const btnRow = h("div", { class: "btn-row" });
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
      const usernameInput = h("input", { type: "text", name: "username", autocomplete: "off", required: true });
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
      const connectBtn = h("button", { type: "submit", class: "btn" }, "Connect");
      const note = h("p", { class: "muted" }, "Credentials are sent to the Netlens server only to open this session; they are not stored.");

      form.appendChild(h("label", {}, "Username"));
      form.appendChild(usernameInput);
      form.appendChild(h("label", {}, "Password"));
      form.appendChild(passwordInput);
      form.appendChild(keySection);
      form.appendChild(h("label", {}, "Passphrase"));
      form.appendChild(passphraseInput);
      form.appendChild(connectBtn);
      form.appendChild(note);

      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const username = usernameInput.value;
        const password = passwordInput.value;
        const key = keyTextarea.value;
        const passphrase = passphraseInput.value;

        clear(connectionArea);
        await startTerminal(proto, port, username, password, key, passphrase);
      });

      connectionArea.appendChild(form);
    } else {
      const connectBtn = h("button", { class: "btn" }, "Connect");
      connectBtn.addEventListener("click", async () => {
        clear(connectionArea);
        await startTerminal(proto, port, null, null, null, null);
      });
      connectionArea.appendChild(connectBtn);
    }
  }

  async function startTerminal(proto, port, username, password, key, passphrase) {
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
            term.focus();
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