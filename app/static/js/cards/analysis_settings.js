import { get, put } from "../api.js";
import { longHint } from "../ui.js";
import { h, clear, toast } from "../util.js";
import { keepDrafts } from "../editguard.js";

// Settings → Analysis reports: how the digital engineer's reports are written and kept, and what a language model may see of them.
// (These were at the bottom of Host probes; the settings belong to the reports, so they have a page of their own.)
export async function buildAnalysisSettingsCard() {
  const card = h("div", { class: "card" });
  let s = await get("/api/hostprobe/settings");

  function draw() { return keepDrafts(card, drawNow); }
  function drawNow() {
    clear(card);
    const f = {
      names: h("input", { type: "checkbox", checked: s.names_to_llm }), auto: h("input", { type: "checkbox", checked: s.analysis_auto }),
      words: h("select", {}, [["rules", "Built-in logic only"], ["auto", "Automatic: a language model when one is connected"], ["model", "Language model (the report says when it was not available)"]].map(([v, t]) => h("option", { value: v, selected: v === (s.analysis_words || "rules") }, t))),
      base: h("input", { type: "url", value: s.base_url || "", placeholder: "https://netlens.example.lan" }),
      keep: h("input", { type: "number", min: 1, max: 365, value: s.keep_days }),
    };
    const field = (label, input, hint) => h("div", { class: "field" }, h("label", {}, label), input, hint ? h("p", { class: "hint" }, hint) : null);
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      try {
        s = await put("/api/hostprobe/settings", { names_to_llm: f.names.checked, analysis_auto: f.auto.checked, analysis_words: f.words.value, base_url: f.base.value, keep_days: Number(f.keep.value) });
        toast("Saved", "success");
        draw();
      } catch (err) { toast(err.message || "Could not save", "error"); }
    });
    card.append(
      h("h2", {}, "Analysis reports"),
      h("section", { class: "probe-section" },
        h("h3", {}, "Reports"),
        longHint("Information only: the digital engineer reads and reports, it changes nothing on any host. Every incident gets an id (INC-…) and every analysis a report id (AR-…), so another system that is allowed to act (an automation platform, an AI agent) knows what is meant and fetches the report: GET /api/analysis/<id>, or the assistant tools get_analysis_report and get_incident_analysis. To have them pushed, include the event \"The digital engineer finished an analysis\" in an alert channel: e-mail gets a formatted report, a webhook gets the whole report as JSON."),
        field("Write the short summary of a report with", f.words, "The findings, the cause and the chains always come from the built-in logic. A language model (Settings → AI) can only add a short plain-language summary on top, from the findings; names of files and folders are withheld from it unless you allow them below. The built-in text is always there, with or without it."),
        h("div", { class: "field" }, h("label", { class: "check-row" }, f.auto, " Analyse every incident automatically, about 10 minutes after it starts")),
        field("Address of this Netlens (for links in e-mails and messages)", f.base, "For example https://netlens.example.lan. Without it the links are paths on this Netlens.")),
      h("section", { class: "probe-section" },
        h("h3", {}, "Privacy and records"),
        field("Keep storage snapshots for (days)", f.keep, "The snapshots hold folder and file names. Every look, every change of these settings and every time someone views the names is written to the audit log (Settings → Audit log, kept for the period set under Database), and is forwarded with Log forwarding."),
        h("div", { class: "field" }, h("label", { class: "check-row" }, f.names, " Let the language model see file and folder names"), h("p", { class: "hint" }, "Off: when an investigation is written out by a language model, it is only told how much grew and where, not the names. The built-in text always shows the names.")),
        h("div", { class: "form-actions" }, save)));
  }
  draw();
  return card;
}
