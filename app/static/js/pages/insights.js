import { get, post, put, patch } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

const TYPES = ["router", "switch", "ap", "server", "pc", "phone", "tablet", "tv", "speaker", "console", "appliance", "printer", "iot", "camera", "nas", "vm"];

export async function render(container) {
  let destroyed = false, data;
  const body = h("div", {}, h("p", { class: "hint" }, "Loading..."));
  container.append(h("div", { class: "toolbar" }, h("strong", {}, "Insights"), h("span", { class: "hint" }, "Questions, incidents, unusual readings and predictions, worked out from your own data.")), body);

  async function load() {
    try { data = await get("/api/insights"); } catch (err) { if (!destroyed) { clear(body); body.appendChild(h("p", { class: "error" }, err.message || "Could not load.")); } return; }
    if (!destroyed) draw();
  }

  function modelNote() {
    const s = data.status;
    if (s.llm_ready) return "A language model is connected: it can answer free questions and word the summaries. Names and addresses are anonymised first (Settings → Digital engineer).";
    if (!s.llm_configured) return "No language model is connected. Everything here still works from the numbers; connect one under Settings → Digital engineer if you want free-form answers.";
    return "A language model is set up but switched off for insights, so the plain versions are shown.";
  }

  function askCard() {
    const input = h("input", { type: "text", maxlength: "500", placeholder: "Ask about your network, for example: what happened last night?" });
    const out = h("div", { class: "ins-answer" });
    const go = h("button", { class: "btn primary", type: "submit" }, "Ask");
    async function ask(question) {
      input.value = question;
      go.disabled = true; clear(out); out.appendChild(h("p", { class: "hint" }, "Looking..."));
      try {
        const res = await post("/api/insights/ask", { question });
        clear(out);
        out.appendChild(h("p", { class: "ins-text" }, res.answer));
        out.appendChild(h("p", { class: "hint" }, res.source === "model" ? `Answered by the language model from: ${res.tools.join(", ") || "its own knowledge of the question"}.` : "Answered from the numbers (no language model)."));
      } catch (err) { clear(out); out.appendChild(h("p", { class: "error" }, err.message || "Could not answer.")); }
      go.disabled = false;
    }
    const form = h("form", { class: "ins-ask", onsubmit: (e) => { e.preventDefault(); if (input.value.trim()) ask(input.value.trim()); } }, input, go);
    const presets = h("div", { class: "ins-presets" }, ...data.presets.map((p) => h("button", { class: "btn ghost", type: "button", onclick: () => ask(p.text) }, p.text)));
    return h("div", { class: "card" }, h("h2", {}, "Ask your network"), form, presets, out);
  }

  function incidentsCard() {
    const card = h("div", { class: "card" }, h("h2", {}, `Incidents, last 7 days (${data.incidents.length})`));
    if (!data.incidents.length) card.appendChild(h("p", { class: "hint" }, "No incidents. When several alerts belong together they are shown here as one story."));
    for (const i of data.incidents) {
      const text = h("div", { class: "ins-text" }, i.summary);
      const row = h("div", { class: "rem-run" }, h("div", {}, h("strong", {}, i.title), " ", h("span", { class: `badge ${i.resolved ? "" : "warn"}` }, i.resolved ? "over" : i.ongoing ? "going on" : "open"), " ",
        h("span", { class: "hint", title: i.start }, timeAgo(i.start))), text);
      if (data.status.llm_ready) {
        const words = h("button", { class: "btn ghost", type: "button" }, "Say it in the model's words");
        words.addEventListener("click", async () => {
          words.disabled = true;
          try { const res = await post(`/api/insights/incidents/${i.id}/words`, {}); text.textContent = res.text; if (res.source !== "model") toast("The model did not answer; the plain summary stays", "info"); } catch (err) { toast(err.message || "Failed", "error"); }
          words.disabled = false;
        });
        row.appendChild(words);
      }
      card.appendChild(row);
    }
    return card;
  }

  function unusualCard() {
    const card = h("div", { class: "card" }, h("h2", {}, `Unusual right now (${data.anomalies.length})`),
      h("p", { class: "hint" }, "Compared with what is normal for that device at this time of day over the last two weeks (processor, memory and response times). Needs about a week of history."));
    if (!data.anomalies.length) card.appendChild(h("p", {}, "Nothing is unusual."));
    for (const a of data.anomalies) card.appendChild(h("div", { class: "rem-run" }, a.text));
    return card;
  }

  function predictionsCard() {
    const p = data.predictions;
    const card = h("div", { class: "card" }, h("h2", {}, "Predictions"));
    if (!p.disks.length && !p.memory.length) card.appendChild(h("p", {}, "Nothing is on course to run out within a year."));
    for (const d of p.disks) card.appendChild(h("div", { class: "rem-run" }, `${d.device} ${d.label}: ${d.current}% used, full in about ${Math.max(1, Math.round(d.days_to_full))} days (around ${d.full_on}).`));
    for (const m of p.memory) card.appendChild(h("div", { class: "rem-run" }, `${m.device}: memory use keeps rising (${m.current}% now), it would run out in about ${Math.max(1, Math.round(m.days_to_full))} days. A leak, or a cache that never shrinks.`));
    return card;
  }

  function unknownCard() {
    const card = h("div", { class: "card" }, h("h2", {}, `Devices without a type (${data.unknown_devices.length})`),
      h("p", { class: "hint" }, "Netlens weighs what it knows (manufacturer, open ports, names). “Suggest” shows its reasoning and, if a model is connected, the model's opinion. Nothing changes until you apply a suggestion."));
    if (!data.unknown_devices.length) card.appendChild(h("p", {}, "Every device has a type."));
    for (const d of data.unknown_devices) {
      const slot = h("div", {});
      const btn = h("button", { class: "btn", type: "button" }, "Suggest");
      btn.addEventListener("click", async () => {
        btn.disabled = true; clear(slot);
        try { const s = await get(`/api/insights/identify/${d.id}`); slot.appendChild(suggestion(d, s)); } catch (err) { slot.appendChild(h("p", { class: "error" }, err.message || "Failed")); }
        btn.disabled = false;
      });
      card.appendChild(h("div", { class: "rem-run" }, h("strong", {}, d.name || `device ${d.id}`), " ", h("span", { class: "hint" }, `${d.ip || ""} ${d.vendor || ""}`), " ", btn, slot));
    }
    return card;
  }

  function suggestion(d, s) {
    const wrap = h("div", { class: "ins-suggest" });
    const options = [];
    if (s.rules) options.push({ who: "Netlens's rules", ...s.rules });
    if (s.model) options.push({ who: "The language model", ...s.model });
    if (!options.length) wrap.appendChild(h("p", { class: "hint" }, "Not enough is known to say. A scan with port detection may help."));
    for (const o of options) {
      if (o.type === "unknown") continue;
      const apply = h("button", { class: "btn primary", type: "button" }, `Use “${o.type}”${o.name ? ` and the name “${o.name}”` : ""}`);
      apply.addEventListener("click", async () => {
        apply.disabled = true;
        try { await patch(`/api/devices/${d.id}`, { type_override: TYPES.includes(o.type) ? o.type : null, ...(o.name && !d.name?.trim() ? { custom_name: o.name } : {}) }); toast("Saved", "success"); await load(); } catch (err) { toast(err.message || "Failed", "error"); apply.disabled = false; }
      });
      wrap.appendChild(h("div", {}, h("strong", {}, `${o.who}: ${o.type}`), ` (${o.confidence} confidence). ${o.reason || ""} `, apply));
    }
    if (s.clues.length) wrap.appendChild(h("details", {}, h("summary", { class: "hint" }, "All the clues"), h("ul", {}, ...s.clues.map((c) => h("li", {}, `${c.type}: ${c.why}`)))));
    return wrap;
  }

  function settingsCard() {
    const s = data.status;
    const llm = h("input", { type: "checkbox" }); llm.checked = s.llm_wanted; llm.disabled = !s.llm_configured;
    const rep = h("input", { type: "checkbox" }); rep.checked = s.report_summary;
    const save = async () => { try { await put("/api/insights/settings", { llm: llm.checked, report_summary: rep.checked }); toast("Saved", "success"); await load(); } catch (err) { toast(err.message || "Failed", "error"); } };
    llm.addEventListener("change", save); rep.addEventListener("change", save);
    const result = h("div", {});
    const check = h("button", { class: "btn", type: "button", title: "Six small exams with made-up data" }, "Check the model");
    check.addEventListener("click", async () => {
      check.disabled = true; clear(result); result.appendChild(h("p", { class: "hint" }, "Running six exams, this can take a minute..."));
      try {
        const r = await post("/api/insights/model-check", {});
        clear(result);
        result.appendChild(h("p", { class: r.verdict === "good" ? "run-ok" : r.verdict === "usable" ? "warn-text" : "error" }, `${r.passed} of ${r.total} passed (${r.model}): ${r.advice}`));
        result.appendChild(h("ul", {}, ...r.checks.map((c) => h("li", {}, `${c.ok ? "✓" : "✗"} ${c.name}: ${c.detail} (${c.seconds}s)`))));
      } catch (err) { clear(result); result.appendChild(h("p", { class: "error" }, err.message || "The check failed.")); }
      check.disabled = false;
    });
    return h("div", { class: "card" }, h("h2", {}, "Settings"), h("p", { class: "hint" }, modelNote()), s.llm_configured ? h("div", { class: "form-actions" }, check) : null, result,
      h("label", { class: "check" }, llm, " Let the language model word the answers and summaries"),
      h("label", { class: "check" }, rep, " Start the weekly report with a short summary"));
  }

  function draw() {
    clear(body);
    if (!data.status.allowed) {
      body.appendChild(h("div", { class: "card" }, h("h2", {}, "Insights are a Business feature"),
        h("p", {}, "Ask questions about your network, get incidents explained as one story, see unusual readings and predictions, and let Netlens suggest what unknown devices are. They work without a language model. Included in every licence and in the free 30-day trial."),
        h("p", {}, h("a", { class: "btn primary", href: "#/settings/licence" }, "Open the licence page"))));
      return;
    }
    body.append(askCard(), incidentsCard(), unusualCard(), predictionsCard(), unknownCard(), settingsCard());
  }

  await load();
  return () => { destroyed = true; };
}
