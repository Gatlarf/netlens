import { get, post } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";

// The AI report: findings found by Netlens, worded by the model when there is one, every sentence tied to the findings it rests on
export function buildAiReportCard(status) {
  const card = h("div", { class: "card" }, h("h2", {}, "AI report: what happened and how it connects"));
  const period = h("select", {}, ...[["6h", "Last 6 hours"], ["24h", "Last 24 hours"], ["3d", "Last 3 days"], ["7d", "Last 7 days"]].map(([v, t]) => h("option", { value: v, selected: v === "24h" }, t)));
  const write = h("button", { class: "btn primary", type: "button" }, status.llm_ready ? "Write the report" : "Make the report");
  const out = h("div", {});
  let everything = false;           // shared with the question on the Insights page
  try { everything = localStorage.getItem("netlens.ask.all") === "1"; } catch (e) { /* private window */ }
  const allBox = h("input", { type: "checkbox" });
  allBox.checked = everything;
  allBox.addEventListener("change", () => { everything = allBox.checked; try { localStorage.setItem("netlens.ask.all", everything ? "1" : "0"); } catch (e) { /* ignore */ } load(); });
  card.append(h("p", { class: "hint" }, "Netlens finds the connections itself: alerts that belong together, devices behind the same switch or host, changes made shortly before a problem, and problems that keep coming back or come at the same time of day. " +
    (status.llm_ready ? "The language model then writes the report from those findings. Every sentence must name the findings it rests on; a sentence that does not, or that contains a number the findings do not, is thrown away. A small model works but writes less." : "No language model is connected, so the report lists the findings. Connect one under Settings → AI to have them written up.")),
    h("label", { class: "check", title: "Off: only what happened to the devices marked always-on, plus services and network problems. On: phones, tablets and the like count too." }, allBox, " Include phones, tablets and other devices that come and go"),
    h("div", { class: "form-actions" }, period, write), out);
  function show(r) {
    clear(out);
    if (!r) { out.appendChild(h("p", { class: "hint" }, "No report written yet for this period.")); return; }
    const badge = r.source === "model" ? `Written by ${r.model || "the language model"} from the findings below` : "The findings, in order of importance";
    out.appendChild(h("p", { class: "hint" }, `${r.label[0].toUpperCase()}${r.label.slice(1)} · ${badge} · ${fmtTime(r.generated || r.until)}`));
    for (const l of r.lines) {
      out.appendChild(h("div", { class: `rem-run${l.kind === "check" ? " ai-check" : ""}` }, l.kind === "check" ? h("strong", {}, "Look at: ") : null, l.text, " ", ...l.refs.map((id) => h("a", { class: "ai-ref", href: `#ai-${id}`, onclick: (e) => { e.preventDefault(); const el = out.querySelector(`[data-finding="${id}"]`); if (el) { el.scrollIntoView({ block: "nearest" }); el.classList.add("flash"); setTimeout(() => el.classList.remove("flash"), 1500); } } }, id)).flatMap((a) => [a, " "])));
    }
    if (r.dropped) out.appendChild(h("p", { class: "hint" }, `${r.dropped} sentence${r.dropped === 1 ? "" : "s"} from the model ${r.dropped === 1 ? "was" : "were"} left out because ${r.dropped === 1 ? "it" : "they"} could not be tied to the findings.`));
    const det = h("details", {}, h("summary", { class: "hint" }, `The findings (${r.findings.length})`));
    for (const f of r.findings) det.appendChild(h("div", { class: "rem-run", "data-finding": f.id }, h("strong", {}, f.id), " ", h("span", { class: "hint" }, `(${f.strength})`), " ", f.text));
    out.appendChild(det);
  }
  async function load() {
    try { const r = await get(`/api/insights/report?period=${period.value}${everything ? "&include_all=1" : ""}`); show(r.report || r.now); if (!r.report) out.prepend(h("p", { class: "hint" }, "Not written yet: this is the list of findings right now.")); }
    catch (err) { clear(out); out.appendChild(h("p", { class: "error" }, err.message)); }
  }
  period.addEventListener("change", load);
  write.addEventListener("click", async () => {
    write.disabled = true; const label = write.textContent; write.textContent = status.llm_ready ? "Writing ... (a small model can take a minute)" : "Working ...";
    try { show(await post("/api/insights/report", { period: period.value, include_all: everything })); } catch (err) { toast(err.message || "Could not make the report", "error"); }
    write.disabled = false; write.textContent = label;
  });
  load();
  return card;
}
