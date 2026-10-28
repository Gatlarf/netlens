import { get, post, put, patch, del } from "../api.js";
import { h, clear, toast, timeAgo, fmtTime, isAdmin } from "../util.js";
import { pageHead } from "../ui.js";
import { boardPage } from "../layout_cards.js";

const TYPES = ["router", "switch", "ap", "server", "pc", "phone", "tablet", "tv", "speaker", "console", "appliance", "printer", "iot", "camera", "nas", "vm"];

export async function render(container) {
  let destroyed = false, data, coverage = null;
  let everything = false;           // also phones, tablets and other devices that come and go
  try { everything = localStorage.getItem("netlens.ask.all") === "1"; } catch (e) { /* private window */ }
  // one tick box, shown where it matters (the question and the incidents); it redraws the page
  function scopeBox() {
    const box = h("input", { type: "checkbox" });
    box.checked = everything;
    box.addEventListener("change", () => { everything = box.checked; try { localStorage.setItem("netlens.ask.all", everything ? "1" : "0"); } catch (e) { /* ignore */ } load(); });
    return h("label", { class: "check", title: "Off: only the devices that should always be on (servers, routers, switches, NAS, cameras, anything marked always-on), services and network problems. On: phones, tablets and the like count too." },
      box, " Include phones, tablets and other devices that come and go");
  }
  const board = boardPage("insights", "Insights", [["main", "Insights"]], "*", isAdmin);
  const body = h("div", {}, h("p", { class: "hint" }, "Loading..."));
  container.append(pageHead("Insights", "Questions, incidents, unusual readings and predictions, worked out from your own data. The AI report is under Reports.", board.button()), body);

  async function load() {
    try { coverage = await get("/api/coverage").catch(() => null); } catch (e) { coverage = null; }
    try { data = await get(`/api/insights${everything ? "?include_all=1" : ""}`); } catch (err) { if (!destroyed) { clear(body); body.appendChild(h("p", { class: "error" }, err.message || "Could not load.")); } return; }
    if (!destroyed) draw();
  }

  function modelNote() {
    const s = data.status;
    if (s.llm_ready) return "A language model is connected: it can answer free questions and word the summaries. Names and addresses are anonymised first (Settings → AI).";
    if (!s.llm_configured) return "No language model is connected. Everything here still works from the numbers; connect one under Settings → AI if you want free-form answers.";
    return "A language model is set up but switched off for insights, so the plain versions are shown.";
  }

  function askCard() {
    const input = h("input", { type: "text", maxlength: "500", placeholder: "Ask about your network, for example: what happened last night?" });
    const out = h("div", { class: "ins-answer" });
    let mode = "auto";
    try { mode = localStorage.getItem("netlens.ask.mode") || "auto"; } catch (e) { /* private window */ }
    if (!data.status.llm_configured) mode = "rules";
    const switcher = h("div", { class: "ins-mode" }, h("span", { class: "hint" }, "Answer with: "), ...[["auto", "Automatic"], ["rules", "Built-in logic"], ["model", "Language model"]].map(([v, label]) => {
      const radio = h("input", { type: "radio", name: "ask-mode", value: v });
      radio.checked = mode === v;
      radio.addEventListener("change", () => { mode = v; try { localStorage.setItem("netlens.ask.mode", v); } catch (e) { /* ignore */ } });
      return h("label", { class: "check", title: v === "auto" ? "The language model when one is connected, otherwise the built-in logic" : v === "rules" ? "Only Netlens's own logic: fast, private, limited to the ready-made kinds of question" : "The language model, which can also handle free-form questions" }, radio, " " + label);
    }));
    const scopeRow = scopeBox();
    const go = h("button", { class: "btn primary", type: "submit" }, "Ask");
    async function ask(question) {
      input.value = question;
      go.disabled = true; clear(out); out.appendChild(h("p", { class: "hint" }, "Looking..."));
      try {
        const res = await post("/api/insights/ask", { question, mode, include_all: everything });
        clear(out);
        out.appendChild(h("p", { class: "ins-text" }, res.answer));
        out.appendChild(h("p", { class: "hint" }, res.source === "model" ? `Answered by the language model from: ${res.tools.join(", ") || "its own knowledge of the question"}.`
          : res.fell_back ? "The language model could not answer this one; the built-in logic answered." : "Answered by the built-in logic, from the numbers."));
      } catch (err) { clear(out); out.appendChild(h("p", { class: "error" }, err.message || "Could not answer.")); }
      go.disabled = false;
    }
    const form = h("form", { class: "ins-ask", onsubmit: (e) => { e.preventDefault(); if (input.value.trim()) ask(input.value.trim()); } }, input, go);
    const button = (p) => h("button", { class: "btn ghost", type: "button", onclick: () => ask(p.text) }, p.text);
    const presets = h("div", { class: "ins-presets" }, ...data.presets.slice(0, 7).map(button));
    const more = data.presets.length > 7 ? h("details", {}, h("summary", { class: "hint" }, `More questions you can ask (${data.presets.length - 7})`), h("div", { class: "ins-presets" }, ...data.presets.slice(7).map(button))) : null;
    return h("div", { class: "card" }, h("h2", {}, "Ask your network"), form, data.status.llm_configured ? switcher : null, scopeRow, presets, more, out, h("hr", {}), settingsCard());
  }

  // The questions nobody could answer: what people ask that Netlens has no tool for, so it can be added. Administrators only; the text of the question is all that is kept.
  function missesCard() {
    const list = h("div", {});
    const card = h("div", { class: "card" }, h("h2", {}, "Questions without an answer"),
      h("p", { class: "hint" }, "What was asked here, in the top bar or through an assistant, and could not be answered. Only the question, how often and when are kept (200 at most, 90 days); no answers and no names of who asked."), list);
    async function show() {
      let r;
      try { r = await get("/api/insights/ask/misses"); } catch (err) { clear(list); list.appendChild(h("p", { class: "error" }, err.message || "Could not load the list")); return; }
      clear(list);
      const on = h("input", { type: "checkbox" });
      on.checked = r.enabled;
      on.addEventListener("change", async () => { try { await put("/api/insights/ask/misses", { enabled: on.checked }); toast(on.checked ? "Unanswered questions are kept" : "Unanswered questions are no longer kept", "success"); } catch (err) { toast(err.message || "Failed", "error"); on.checked = !on.checked; } });
      list.appendChild(h("label", { class: "check" }, on, " Keep a list of questions that got no answer"));
      if (!r.items.length) { list.appendChild(h("p", { class: "hint" }, "Nothing yet: every question so far was answered.")); return; }
      list.appendChild(h("ul", { class: "ins-list" }, ...r.items.slice(0, 30).map((x) => h("li", {}, h("strong", {}, x.q), " ", h("span", { class: "hint" }, `${x.n > 1 ? `${x.n}× · ` : ""}${timeAgo(x.last)}${x.tools && x.tools.length ? ` · tried: ${x.tools.join(", ")}` : " · no tool fitted"}`)))));
      list.appendChild(h("button", { class: "btn", type: "button", onclick: async () => { try { await del("/api/insights/ask/misses"); toast("The list was cleared", "success"); show(); } catch (err) { toast(err.message || "Failed", "error"); } } }, "Clear the list"));
    }
    show();
    return card;
  }

  function incidentsCard() {
    const card = h("div", { class: "card" }, h("h2", {}, `Incidents, last 7 days (${data.incidents.length})`));
    card.appendChild(scopeBox());
    if (!data.incidents.length) card.appendChild(h("p", { class: "hint" }, "No incidents. When several alerts belong together they are shown here as one story."));
    const SHOWN = 6;
    const more = [];
    data.incidents.forEach((i, n) => {
      const text = h("div", { class: "ins-text" }, i.summary);
      const row = h("div", { class: "rem-run" }, h("div", {}, h("strong", {}, i.title), " ", h("span", { class: `badge ${i.resolved ? "" : "warn"}` }, i.resolved ? "over" : i.ongoing ? "going on" : "open"), " ",
        h("span", { class: "badge", title: "The id other systems use for this incident (get_incident_analysis in the assistant, /api/insights/incidents/<id>/analysis)" }, i.ref || `INC-${i.id}`), " ",
        h("span", { class: "hint", title: i.start }, timeAgo(i.start))), text);
      const why = h("div", { class: "ins-text" });
      const dig = h("button", { class: "btn", type: "button" }, "Investigate");
      dig.addEventListener("click", async () => {
        dig.disabled = true;
        try {
          const res = await get(`/api/insights/incidents/${i.id}/investigate${data.status.llm_ready ? "?words=true" : ""}`);
          clear(why);
          if (res.words) why.appendChild(h("p", {}, res.words));
          const list = h("ul", {});
          for (const f of res.findings) list.appendChild(h("li", { class: f.level === "warn" || f.level === "cause" ? "warn-text" : "" }, f.text));
          if (!res.findings.length) list.appendChild(h("li", { class: "hint" }, "Nothing more to say than the summary above."));
          why.appendChild(list);
          for (const d of res.devices) {
            const det = h("details", {}, h("summary", {}, `Timeline of ${d.name}`));
            det.appendChild(h("ul", {}, d.timeline.map((t) => h("li", {}, h("span", { class: "hint" }, `${t.ts.replace("T", " ").replace("Z", "")} `), t.count > 1 ? `${t.count}× ` : "", t.text || t.kind))));
            why.appendChild(det);
          }
        } catch (err) { toast(err.message || "Failed", "error"); }
        dig.disabled = false;
      });
      const rep = h("button", { class: "btn", type: "button", title: "Make the analysis report of this incident: it gets an id that other systems can fetch, and can be sent by e-mail or to a webhook. Information only." }, "Analysis report");
      const repOut = h("div", { class: "ins-text" });
      rep.addEventListener("click", async () => {
        rep.disabled = true;
        try {
          const r = await post(`/api/insights/incidents/${i.id}/analysis`, {});
          clear(repOut);
          repOut.append(h("p", {}, h("strong", {}, `${r.report_ref}`), ` for ${r.incident_ref}. `, r.probable_cause ? r.probable_cause : "No single cause stands out."),
            h("p", { class: "hint" }, "Information only: nothing was changed on any host. Other systems fetch it with this id."));
          const open = h("a", { class: "btn", href: `/api/analysis/${r.report_id}/html`, target: "_blank", rel: "noopener" }, "Open the report");
          const send = h("button", { class: "btn", type: "button" }, "Send it by e-mail / alert channels");
          send.addEventListener("click", async () => {
            send.disabled = true;
            try { const x = await post(`/api/analysis/${r.report_id}/send`, {}); toast(x.sent.length ? `Sent through ${x.sent.join(", ")}` : "Not sent", x.sent.length ? "success" : "error"); if (x.failed.length) toast(x.failed.map((f) => `${f.channel}: ${f.error}`).join("; "), "error"); } catch (err) { toast(err.message || "Could not send", "error"); }
            send.disabled = false;
          });
          repOut.append(h("div", { class: "form-actions" }, open, send));
        } catch (err) { toast(err.message || "Failed", "error"); }
        rep.disabled = false;
      });
      row.append(dig, rep, why, repOut);
      if (data.status.llm_ready) {
        const words = h("button", { class: "btn ghost", type: "button" }, "Say it in the model's words");
        words.addEventListener("click", async () => {
          words.disabled = true;
          try { const res = await post(`/api/insights/incidents/${i.id}/words`, {}); text.textContent = res.text; if (res.source !== "model") toast("The model did not answer; the plain summary stays", "info"); } catch (err) { toast(err.message || "Failed", "error"); }
          words.disabled = false;
        });
        row.appendChild(words);
      }
      if (n >= SHOWN) { row.hidden = true; more.push(row); }
      card.appendChild(row);
    });
    if (more.length) {
      const btn = h("button", { class: "btn", type: "button" }, `Show all ${data.incidents.length}`);
      btn.addEventListener("click", () => { for (const r of more) r.hidden = false; btn.remove(); });
      card.appendChild(btn);
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
    card.appendChild(h("p", { class: "hint" }, "A date is only given when the history follows a straight line for at least a week. Memory that levels off or is given back now and then is not called a leak."));
    if (!p.disks.length && !p.memory.length) card.appendChild(h("p", {}, "Nothing is on course to run out within a year."));
    for (const d of p.disks) card.appendChild(h("div", { class: "rem-run" }, `${d.device} ${d.label}: ${d.current}% used, full in about ${Math.max(1, Math.round(d.days_to_full))} days (around ${d.full_on}).`));
    for (const m of p.memory) {
      const kinds = { levelling: "the rise is slowing down, like a cache that has filled", resets: "memory is given back now and then (restarts or clean-ups)", irregular: "it moves up and down" };
      card.appendChild(h("div", { class: "rem-run" }, m.days_to_full != null
        ? `${m.device}: memory use rose in a steady line over ${m.days_of_data} days (${m.current}% now, about ${m.slope_per_day} points a day). At that pace it would run out in about ${Math.max(1, Math.round(m.days_to_full))} days, which is what a leak looks like. Check whether it is one.`
        : `${m.device}: memory is nearly full (${m.current}%) but does not follow a straight line over ${m.days_of_data} days: ${kinds[m.pattern] || "no clear pattern"}. No date can be given.`));
    }
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
    const save = async () => { try { await put("/api/insights/settings", { llm: llm.checked }); toast("Saved", "success"); await load(); } catch (err) { toast(err.message || "Failed", "error"); } };
    llm.addEventListener("change", save);
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
    return h("div", {}, h("p", { class: "hint" }, modelNote()), s.llm_configured ? h("div", { class: "form-actions" }, check) : null, result,
      h("label", { class: "check" }, llm, " Let the language model word the answers and incident summaries"));
  }

  // what is not yet watching the devices that matter (always-on or critical): a quick check, a service check, a health monitor, a backup, alerts
  function coverageCard() {
    const c = coverage;
    const card = h("div", { class: "card" }, h("h2", {}, `Monitoring coverage (${c.with_gaps} of ${c.watching} with a gap)`));
    card.appendChild(h("p", { class: "hint" }, "The devices you marked always-on or critical, and what does not watch them yet. A gap is where an outage would go unnoticed or unexplained."));
    if (c.no_channel) card.appendChild(h("p", { class: "warn-text" }, ["No alert channel is switched on: nobody is told when something goes down. ", h("a", { href: "#/settings/channels" }, "Add one")]));
    if (!c.devices.length) { card.appendChild(h("p", { class: "run-ok" }, c.watching ? "Every device that matters is covered." : "No device is marked always-on or critical yet.")); return card; }
    const list = h("ul", {});
    for (const d of c.devices.slice(0, 12)) {
      list.appendChild(h("li", {}, h("a", { href: `#/device/${d.id}` }, d.name), d.tier === "critical" ? h("span", { class: "tag unknown-tag" }, "critical") : null, h("span", { class: "hint" }, ` ${d.type}`),
        h("ul", {}, d.missing.map((m) => h("li", {}, h("strong", {}, `No ${m.what}. `), h("span", { class: "hint" }, m.fix))))));
    }
    card.appendChild(list);
    if (c.devices.length > 12) card.appendChild(h("p", { class: "hint" }, `and ${c.devices.length - 12} more.`));
    return card;
  }

  function draw() {
    clear(body);
    if (!data.status.allowed) {
      body.appendChild(h("div", { class: "card" }, h("h2", {}, "Insights are a Business feature"),
        h("p", {}, "Ask questions about your network, get incidents explained as one story, see unusual readings and predictions, and let Netlens suggest what unknown devices are. They work without a language model. Included in every licence and in the free 30-day trial."),
        h("p", {}, h("a", { class: "btn primary", href: "#/settings/licence" }, "Open the licence page"))));
      return;
    }
    const tag = (el, id, title, kind, size) => { el.dataset.card = id; el.dataset.title = title; el.dataset.kind = kind; if (size) el.dataset.size = size; return el; };
    const flow = h("div", { class: "dev-flow" }, ...[
      tag(askCard(), "ask", "Ask your network", "tiles", "f"), isAdmin() ? tag(missesCard(), "misses", "Questions without an answer", "list") : null, tag(incidentsCard(), "incidents", "Incidents", "list", "w"), tag(unusualCard(), "unusual", "Unusual right now", "list"),
      coverage ? tag(coverageCard(), "coverage", "Monitoring coverage", "list") : null,
      tag(predictionsCard(), "predictions", "Predictions", "list"), tag(unknownCard(), "unknown", "Devices without a type", "list")].filter(Boolean));
    body.append(flow);
    board.apply({ main: flow });
  }

  await load();
  return () => { destroyed = true; board.close(); };
}
