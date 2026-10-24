import { get, put, post } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

// Settings page: escalate alerts that nobody acknowledges.
export async function buildEscalationCard() {
  const card = h("div", { class: "card" });
  function draw(info) {
    clear(card);
    card.appendChild(h("h2", {}, "Escalation"));
    card.appendChild(h("p", { class: "hint" },
      "An alert that nobody acknowledges is sent on to other channels after a while: after 15 minutes tell the first person, after 45 minutes the team. It follows the serious events (the ones that break through quiet hours, or the ones you choose). It stops when someone acknowledges the alert here or when the problem has gone. Make a channel per person or per team under Alert channels. Part of every licence and the free trial."));
    if (!info.allowed) card.appendChild(h("p", { class: "warn-text" }, "Needs a licence or the free trial (Settings → Licence)."));
    const enabled = h("input", { type: "checkbox" });
    enabled.checked = info.policy.enabled;
    const levels = h("div", {});
    const rows = [];
    function addLevel(level) {
      const after = h("input", { type: "number", min: "1", max: "1440", value: String(level.after_min), style: "width:6em" });
      const chans = h("select", { multiple: true, size: String(Math.min(4, Math.max(2, info.channels.length))) }, ...info.channels.map((c) => h("option", { value: c.id, selected: level.channels.includes(c.id) }, c.name)));
      const row = h("div", { class: "field" }, h("label", {}, `After (minutes)`), after, h("label", {}, "Tell"), chans);
      rows.push({ after, chans, row });
      levels.appendChild(row);
    }
    info.policy.levels.forEach(addLevel);
    const more = h("button", { class: "btn", type: "button" }, "Add a level");
    more.addEventListener("click", () => { const last = rows.length ? Number(rows[rows.length - 1].after.value) : 0; addLevel({ after_min: Math.min(1440, last + 30), channels: [] }); });
    const kinds = h("select", { multiple: true, size: "6" }, ...info.kinds.map((k) => h("option", { value: k.id, selected: info.policy.kinds.includes(k.id), title: k.label }, `${k.id} · ${k.label}`.slice(0, 90))));
    // how fast each importance escalates: a percentage of the level times above (50 = twice as fast), empty = never
    const timing = {};
    const timingRow = h("div", { class: "field" }, h("label", {}, "Speed by importance (%)"), ...[["critical", "Critical"], ["normal", "Normal"], ["low", "Low"]].map(([tier, label]) => {
      const input = h("input", { type: "number", min: "10", max: "500", value: info.policy.timing[tier] == null ? "" : String(info.policy.timing[tier]), placeholder: "never", style: "width:5.5em", title: `${label}: 100 = the times above, 50 = twice as fast, empty = never escalates` });
      timing[tier] = input;
      return h("span", { class: "inline-field" }, `${label} `, input);
    }), h("p", { class: "hint" }, "100 uses the times above, 50 escalates twice as fast, empty never escalates. A problem on something marked critical is always followed, whatever events you chose."));
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      save.disabled = true;
      try {
        draw(await put("/api/escalation", { enabled: enabled.checked, kinds: [...kinds.selectedOptions].map((o) => o.value),
          timing: Object.fromEntries(Object.entries(timing).map(([t, i]) => [t, i.value === "" ? null : Number(i.value)])),
          levels: rows.map((r) => ({ after_min: Number(r.after.value), channels: [...r.chans.selectedOptions].map((o) => o.value) })) }));
        toast("Saved", "success");
      } catch (err) { toast(err.message || "Could not save", "error"); save.disabled = false; }
    });
    card.append(h("label", { class: "check" }, enabled, " Escalate alerts that nobody acknowledges"), levels, more, timingRow,
      h("div", { class: "field" }, h("label", {}, "Which events"), kinds, h("p", { class: "hint" }, "Hold Ctrl (or Cmd) to choose several.")), h("div", { class: "form-actions" }, save));
    card.appendChild(h("h3", {}, `Waiting for someone (${info.open.length})`));
    if (!info.open.length) card.appendChild(h("p", { class: "hint" }, "Nothing is waiting."));
    const shown = info.open.slice(0, 8);
    if (info.open.length > shown.length) card.appendChild(h("p", { class: "hint" }, `The newest ${shown.length} are listed; ${info.open.length - shown.length} older ones wait too and close when the problem is gone or someone takes them.`));
    for (const item of shown) {
      const ack = h("button", { class: "btn", type: "button" }, "I'm on it");
      ack.addEventListener("click", async () => { ack.disabled = true; try { draw(await post(`/api/escalation/${item.id}/ack`, {})); } catch (err) { toast(err.message || "Failed", "error"); ack.disabled = false; } });
      card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, h("strong", {}, item.device || "network"), ` · ${item.kind} ${timeAgo(item.ts)}${item.tier === "critical" ? " · critical" : ""}`), h("span", {}, item.detail || "", " ", item.level ? h("span", { class: "warn-text" }, `level ${item.level} sent `) : "", ack)));
    }
  }
  draw(await get("/api/escalation"));
  return card;
}
