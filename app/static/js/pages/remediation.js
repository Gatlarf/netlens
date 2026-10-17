import { get, post, put, del } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

const MODE_TEXT = {
  suggest: "Suggest: only show it here",
  ask: "Ask: announce it and wait for my approval",
  auto: "Automatic: do it at once",
  engineer: "Engineer: do it when the digital engineer is sure, otherwise ask me",
};
const ACTION_TEXT = { wake: "Wake the device (Wake-on-LAN)", webhook: "Call a web address (an automation)", ssh: "Run one command on the device over SSH", vm: "Restart the virtual machine (through its hypervisor)" };
const POWER_TEXT = { reset: "Hard reset (the reset button)", reboot: "Clean restart (the guest is asked)", shutdown: "Clean shutdown", start: "Start it" };
const PRESETS = [
  ["", "Choose a ready-made command…"],
  ["sudo systemctl restart SERVICE", "Restart a Linux service"],
  ["docker restart CONTAINER", "Restart a Docker container"],
  ["sudo reboot", "Reboot the device"],
  ["powershell -Command \"Restart-Service -Name SERVICE\"", "Restart a Windows service"],
];
const STATE = { ok: ["run-ok", "Done"], failed: ["error", "Failed"], pending: ["warn-text", "Waiting"], suggested: ["hint", "Suggested"], denied: ["hint", "Denied"], skipped: ["hint", "Skipped"], running: ["warn-text", "Running"] };

function analysisBlock(a) {
  if (!a) return null;
  const rec = a.recommended_rule_id ? `recommends this rule${a.approve ? " (approved)" : ""}` : "recommends no rule";
  return h("div", { class: "hint rem-analysis" }, h("strong", {}, "Digital engineer: "), `${a.diagnosis || "no diagnosis"} (${a.confidence} confidence, ${rec}). `, a.reasoning || "",
    a.next_steps && a.next_steps.length ? h("ul", {}, ...a.next_steps.map((s) => h("li", {}, s))) : null);
}

function lookBack(run) {
  if (run.state === "suggested" || run.state === "denied" || run.state === "skipped") return null;
  const slot = h("div", { class: "hint rem-analysis" });
  const btn = h("button", { class: "btn ghost", type: "button", title: "Did it work, and does this keep coming back?" }, "Look back");
  btn.addEventListener("click", async () => {
    btn.disabled = true; clear(slot);
    try {
      const res = await get(`/api/insights/postmortem/${run.id}?words=true`);
      slot.appendChild(h("div", {}, res.words || res.summary));
    } catch (err) { slot.appendChild(h("span", { class: "error" }, err.message || "Failed")); }
    btn.disabled = false;
  });
  return h("div", {}, btn, slot);
}

export async function render(container) {
  let destroyed = false, editing = null, formOpen = false;
  const body = h("div", {}, h("p", { class: "hint" }, "Loading..."));
  container.append(h("div", { class: "toolbar" }, h("strong", {}, "Remediation"), h("span", { class: "hint" }, "Let Netlens fix known problems itself, or propose the fix and wait for you.")), body);
  let data;

  async function load() {
    try { data = await get("/api/remediation"); } catch (err) { if (!destroyed) { clear(body); body.appendChild(h("p", { class: "error" }, err.message || "Could not load.")); } return; }
    if (!destroyed && !formOpen) draw();
  }

  function deviceSelect(value) {
    return h("select", {}, h("option", { value: "" }, "Any device"), ...data.devices.map((d) => h("option", { value: String(d.id), selected: value === d.id }, d.name || `device ${d.id}`)));
  }

  function ruleForm(rule) {
    const r = rule || { name: "", kinds: [], device_id: null, match_text: "", action: { type: "ssh", command: "" }, mode: "ask", cooldown_min: 30, max_per_day: 3, enabled: true };
    const name = h("input", { type: "text", value: r.name, maxlength: "80", placeholder: "Restart the file server" });
    const kinds = h("select", { multiple: true, size: "8" }, ...data.kinds.map((k) => h("option", { value: k.id, selected: r.kinds.includes(k.id), title: k.label }, `${k.id} · ${k.label}`.slice(0, 90))));
    const device = deviceSelect(r.device_id);
    const match = h("input", { type: "text", value: r.match_text, placeholder: "Only when the message contains…  (optional)" });
    const type = h("select", {}, ...data.actions.map((a) => h("option", { value: a, selected: r.action.type === a }, ACTION_TEXT[a])));
    const command = h("input", { type: "text", value: r.action.command || "", placeholder: "sudo systemctl restart smbd", maxlength: "500" });
    const preset = h("select", {}, ...PRESETS.map(([v, l]) => h("option", { value: v }, l)));
    preset.addEventListener("change", () => { if (preset.value) command.value = preset.value; });
    const url = h("input", { type: "url", value: r.action.url || "", placeholder: "http://192.168.0.5:8123/api/webhook/restart-nas" });
    const method = h("select", {}, h("option", { value: "POST", selected: r.action.method !== "GET" }, "POST"), h("option", { value: "GET", selected: r.action.method === "GET" }, "GET"));
    const bodyText = h("input", { type: "text", value: r.action.body || "", placeholder: '{"device": "{device}"}' });
    const headerName = h("input", { type: "text", value: r.action.header_name || "", placeholder: "Authorization (optional)" });
    const headerValue = h("input", { type: "password", autocomplete: "off", placeholder: r.action.has_header_value ? "(kept, type to change)" : "header value" });
    const mode = h("select", {}, ...data.modes.map((m) => h("option", { value: m, selected: r.mode === m }, MODE_TEXT[m])));
    const cooldown = h("input", { type: "number", min: "1", max: "1440", value: String(r.cooldown_min) });
    const perDay = h("input", { type: "number", min: "1", max: "50", value: String(r.max_per_day) });
    const enabled = h("input", { type: "checkbox" });
    enabled.checked = r.enabled;
    const sshBox = h("div", {}, h("div", { class: "field" }, h("label", {}, "Command"), preset, command, h("p", { class: "hint" }, "Runs on the device with the login of its SSH host monitor (device page → Monitor). Replace SERVICE or CONTAINER. One command on one line.")));
    const hookBox = h("div", {}, h("div", { class: "field" }, h("label", {}, "Web address"), url), h("div", { class: "field" }, h("label", {}, "Method"), method),
      h("div", { class: "field" }, h("label", {}, "Body"), bodyText, h("p", { class: "hint" }, "You can use {device}, {ip}, {event} and {detail}.")), h("div", { class: "field" }, h("label", {}, "Header"), headerName, headerValue));
    const wakeBox = h("p", { class: "hint" }, "Sends a Wake-on-LAN packet to the device the event is about (it needs a MAC address).");
    const power = h("select", {}, ...Object.entries(POWER_TEXT).map(([v, l]) => h("option", { value: v, selected: (r.action.power || "reset") === v }, l)));
    const vmBox = h("div", { class: "field" }, h("label", {}, "Power action"), power, h("p", { class: "hint" }, "For a device that is a virtual machine reported by a hypervisor plugin (Proxmox, Hyper-V, ...). Netlens finds the machine itself. The plugin's token needs the right to power guests on and off; the plugin's page says which."));
    function showType() { vmBox.hidden = type.value !== "vm"; sshBox.hidden = type.value !== "ssh"; hookBox.hidden = type.value !== "webhook"; wakeBox.hidden = type.value !== "wake"; }
    type.addEventListener("change", showType);
    showType();
    const save = h("button", { class: "btn primary", type: "submit" }, "Save the rule");
    return h("form", { class: "card edit-form", onsubmit: async (e) => {
      e.preventDefault();
      const action = type.value === "ssh" ? { type: "ssh", command: command.value } : type.value === "webhook"
        ? { type: "webhook", url: url.value, method: method.value, body: bodyText.value, header_name: headerName.value, ...(headerValue.value ? { header_value: headerValue.value } : {}) } : type.value === "vm" ? { type: "vm", power: power.value } : { type: "wake" };
      const payload = { name: name.value, kinds: [...kinds.selectedOptions].map((o) => o.value), device_id: device.value ? Number(device.value) : null, match_text: match.value, action, mode: mode.value,
        cooldown_min: Number(cooldown.value), max_per_day: Number(perDay.value), enabled: enabled.checked };
      save.disabled = true;
      try {
        if (rule) await put(`/api/remediation/rules/${rule.id}`, payload); else await post("/api/remediation/rules", payload);
        formOpen = false; editing = null; toast("Saved", "success"); await load();
      } catch (err) { toast(err.message || "Could not save", "error"); save.disabled = false; }
    } }, h("h2", {}, rule ? "Edit the rule" : "New rule"),
    h("div", { class: "field" }, h("label", {}, "Name"), name),
    h("div", { class: "field" }, h("label", {}, "When this happens"), kinds, h("p", { class: "hint" }, "Hold Ctrl (or Cmd) to choose several.")),
    h("div", { class: "field" }, h("label", {}, "On"), device), h("div", { class: "field" }, h("label", {}, "Message contains"), match),
    h("div", { class: "field" }, h("label", {}, "Do this"), type), sshBox, hookBox, wakeBox, vmBox,
    h("div", { class: "field" }, h("label", {}, "How"), mode), h("div", { class: "field" }, h("label", {}, "At most once every (minutes)"), cooldown), h("div", { class: "field" }, h("label", {}, "At most per day"), perDay),
    h("label", { class: "check" }, enabled, " Rule is on"),
    h("div", { class: "form-actions" }, save, h("button", { class: "btn", type: "button", onclick: () => { formOpen = false; editing = null; draw(); } }, "Cancel")));
  }

  function draw() {
    clear(body);
    const s = data.summary;
    if (!data.allowed) {
      body.appendChild(h("div", { class: "card" }, h("h2", {}, "Auto-remediation is a Business feature"),
        h("p", {}, "Netlens can restart a service, wake a device or call an automation when something breaks, ask you first, or let a digital engineer (a language model you choose) judge the situation. It is included in every licence and in the free 30-day trial."),
        h("p", {}, h("a", { class: "btn primary", href: "#/settings/licence" }, "Open the licence page"))));
    }
    const pause = h("button", { class: `btn ${data.paused ? "danger" : ""}`, type: "button" }, data.paused ? "Paused: resume" : "Pause everything");
    pause.addEventListener("click", async () => { await put("/api/remediation/paused", { paused: !data.paused }); await load(); });
    const tile = (label, value, tone) => h("div", { class: `card tile ${tone || ""}` }, h("div", { class: "tile-value" }, String(value)), h("div", { class: "hint" }, label));
    body.appendChild(h("div", { class: "card-row" }, tile("rules on", s.rules), tile("waiting for you", s.pending, s.pending ? "warn" : ""), tile("failed today", s.failed_today, s.failed_today ? "bad" : ""), h("div", { class: "card tile" }, pause)));
    if (data.paused) body.appendChild(h("p", { class: "warn-text" }, "Everything is paused: no rule does anything until you resume."));

    const waiting = data.runs.filter((r) => r.state === "pending" || r.state === "suggested");
    if (waiting.length) {
      const card = h("div", { class: "card" }, h("h2", {}, `Waiting for you (${waiting.length})`));
      for (const r of waiting) {
        const row = h("div", { class: "rem-run" }, h("div", {}, h("strong", {}, r.rule_name), ` on ${r.device || "the network"} · `, h("span", { class: "hint" }, `${r.kind || "test"} ${timeAgo(r.created)}`)),
          r.detail ? h("div", { class: "hint" }, r.detail) : null, analysisBlock(r.analysis));
        const go = h("button", { class: "btn primary", type: "button" }, "Approve and do it");
        const no = h("button", { class: "btn", type: "button" }, "Deny");
        const ask = h("button", { class: "btn", type: "button" }, "Ask the digital engineer");
        const act = async (fn) => { [go, no, ask].forEach((b) => { b.disabled = true; }); try { await fn(); } catch (err) { toast(err.message || "Failed", "error"); } await load(); };
        go.addEventListener("click", () => act(async () => { const res = await post(`/api/remediation/runs/${r.id}/decide`, { approve: true }); toast(res.state === "ok" ? "Done" : `Failed: ${res.result}`, res.state === "ok" ? "success" : "error"); }));
        no.addEventListener("click", () => act(() => post(`/api/remediation/runs/${r.id}/decide`, { approve: false })));
        ask.addEventListener("click", () => act(async () => { await post(`/api/remediation/runs/${r.id}/ask`, {}); toast("The engineer answered", "success"); }));
        row.appendChild(h("div", { class: "form-actions admin-only" }, go, no, data.engineer.enabled && data.engineer.allowed ? ask : null));
        card.appendChild(row);
      }
      body.appendChild(card);
    }

    const rules = h("div", { class: "card" }, h("h2", {}, `Rules (${data.rules.length})`));
    const add = h("button", { class: "btn primary admin-only", type: "button" }, "New rule");
    add.addEventListener("click", () => { formOpen = true; editing = null; draw(); });
    rules.appendChild(add);
    if (!data.rules.length) rules.appendChild(h("p", { class: "hint" }, "No rules yet. A rule says: when this happens, do that (or ask me first)."));
    const table = h("table", { class: "data" });
    table.appendChild(h("thead", {}, h("tr", {}, ...["Rule", "When", "On", "Does", "How", ""].map((c) => h("th", {}, c)))));
    const tb = h("tbody");
    for (const r of data.rules) {
      const dev = data.devices.find((d) => d.id === r.device_id);
      const edit = h("button", { class: "btn", type: "button" }, "Edit");
      edit.addEventListener("click", () => { formOpen = true; editing = r; draw(); });
      const test = h("button", { class: "btn", type: "button", title: "Run it once now on the device" }, "Try it");
      test.addEventListener("click", async () => {
        const target = r.device_id || Number(window.prompt("Device id to try it on (see the device page address)", ""));
        if (!target || !window.confirm(`Run “${r.name}” now?`)) return;
        try { const res = await post(`/api/remediation/rules/${r.id}/run`, { device_id: target }); toast(res.state === "ok" ? `Done: ${res.result}` : `Failed: ${res.result}`, res.state === "ok" ? "success" : "error"); } catch (err) { toast(err.message || "Failed", "error"); }
        await load();
      });
      const remove = h("button", { class: "btn danger", type: "button" }, "Remove");
      remove.addEventListener("click", async () => { if (!window.confirm(`Remove the rule “${r.name}”?`)) return; await del(`/api/remediation/rules/${r.id}`); await load(); });
      tb.appendChild(h("tr", {}, h("td", {}, r.name, r.enabled ? "" : h("span", { class: "hint" }, " (off)")), h("td", {}, r.kinds.join(", ")), h("td", {}, dev ? dev.name : "any device"),
        h("td", {}, ACTION_TEXT[r.action.type]), h("td", {}, r.mode), h("td", { class: "admin-only" }, edit, " ", test, " ", remove)));
    }
    table.appendChild(tb);
    if (data.rules.length) rules.appendChild(h("div", { class: "table-wrap" }, table));
    body.appendChild(rules);
    if (formOpen) { const f = ruleForm(editing); body.insertBefore(f, rules); f.scrollIntoView({ block: "nearest" }); }

    const history = data.runs.filter((r) => r.state !== "pending" && r.state !== "suggested");
    const hc = h("div", { class: "card" }, h("h2", {}, "What happened"));
    if (!history.length) hc.appendChild(h("p", { class: "hint" }, "Nothing yet."));
    else {
      const t = h("table", { class: "data" });
      t.appendChild(h("thead", {}, h("tr", {}, ...["When", "Rule", "On", "Because of", "Result", "Problem gone"].map((c) => h("th", {}, c)))));
      const b = h("tbody");
      for (const r of history) {
        const [cls, label] = STATE[r.state] || ["", r.state];
        b.appendChild(h("tr", {}, h("td", { title: r.created }, timeAgo(r.created)), h("td", {}, r.rule_name, r.decided_by ? h("span", { class: "hint" }, ` · ${r.decided_by}`) : ""), h("td", {}, r.device || ""),
          h("td", { class: "hint" }, r.kind || "test"), h("td", {}, h("span", { class: cls }, label), r.result ? h("div", { class: "hint" }, r.result) : null, analysisBlock(r.analysis)),
          h("td", {}, r.recovered ? h("span", { class: "run-ok" }, `yes, ${timeAgo(r.recovered)}`) : r.state === "ok" ? h("span", { class: "hint" }, "not yet") : "", lookBack(r))));
      }
      t.appendChild(b);
      hc.appendChild(h("div", { class: "table-wrap" }, t));
    }
    body.appendChild(hc);
  }

  await load();
  const timer = setInterval(() => { if (!document.hidden && !formOpen) load(); }, 20000);
  return () => { destroyed = true; clearInterval(timer); };
}
