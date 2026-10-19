import { get, put, post } from "../api.js";
import { h, clear, toast } from "../util.js";

const VERDICT = { good: ["good", "ok"], usable: ["usable", "warn"], poor: ["poor", "bad"] };

// No local model? OpenRouter offers free ones. They change often, so the list is read live and each model can be tried with Netlens's own exams.
function openRouterSection(info, keyInput, refresh) {
  const box = h("details", { class: "openrouter", open: info.url.includes("openrouter.ai") });
  box.appendChild(h("summary", {}, "No model of your own? Use a free model on OpenRouter"));
  box.appendChild(h("p", { class: "hint" },
    "OpenRouter is a service that gives access to many language models, some of them free. You need a free OpenRouter account and an API key (type it in the API key field above). " +
    "Free models change often: they are added, renamed, limited or withdrawn without notice, and they have a daily allowance. So this list is read live from OpenRouter, and Netlens looks once a day whether the model you chose is still offered and still free. " +
    "If it is not, you are told here, on the dashboard and (if you switch the event on) by your notification channels. Free models may also keep your questions for their own use: leave the anonymising on."));
  const out = h("div", {});
  const load = h("button", { class: "btn", type: "button" }, "Show the free models");
  box.append(load, out);
  async function show(force) {
    clear(out);
    out.appendChild(h("p", { class: "hint" }, "Reading OpenRouter's list ..."));
    let data;
    try { data = await get(`/api/engineer/openrouter${force ? "?refresh=true" : ""}`); }
    catch (err) { clear(out); out.appendChild(h("p", { class: "error" }, err.message || "Could not load the list")); return; }
    clear(out);
    if (data.watch_message) out.appendChild(h("p", { class: "warn-text" }, data.watch_message));
    if (data.error) { out.appendChild(h("p", { class: "error" }, data.error)); return; }
    if (!data.models.length) { out.appendChild(h("p", { class: "hint" }, "OpenRouter lists no free text model right now.")); return; }
    out.appendChild(h("p", { class: "hint" }, `${data.models.length} free models right now. “Test” runs Netlens's six exams on a model (about eight requests; a free account allows only a few dozen a day, so test one or two). The best result comes first.`));
    const table = h("table", { class: "table" }, h("thead", {}, h("tr", {}, ["Model", "Room", "Exams on this Netlens", ""].map((t) => h("th", {}, t)))));
    const body = h("tbody");
    for (const m of data.models) {
      const t = m.test;
      const state = t ? h("span", { class: VERDICT[t.verdict][1] }, `${VERDICT[t.verdict][0]} (${t.passed}/${t.total})`) : h("span", { class: "hint" }, "not tested");
      const chosen = info.model === m.id && info.url.includes("openrouter.ai");
      const test = h("button", { class: "btn", type: "button" }, t ? "Test again" : "Test");
      const use = h("button", { class: "btn primary", type: "button" }, chosen ? "In use" : "Use this model");
      use.disabled = chosen;
      test.addEventListener("click", async () => {
        test.disabled = true; test.textContent = "Testing ...";
        try { const r = await post("/api/engineer/openrouter/test", { model: m.id, ...(keyInput.value ? { api_key: keyInput.value } : {}) }); toast(`${m.id}: ${r.verdict} (${r.passed}/${r.total}). ${r.advice}`, r.verdict === "poor" ? "error" : "success"); await show(false); }
        catch (err) { toast(err.message || "The test failed", "error"); test.disabled = false; test.textContent = "Test"; }
      });
      use.addEventListener("click", async () => {
        if (t && t.verdict === "poor" && !window.confirm("This model did not pass the exams. Insights and the engineer can then give answers that look right and are wrong. Use it anyway?")) return;
        use.disabled = true;
        try { await post("/api/engineer/openrouter/use", { model: m.id, ...(keyInput.value ? { api_key: keyInput.value } : {}) }); toast("Saved and switched on", "success"); refresh(); }
        catch (err) { toast(err.message || "Could not save", "error"); use.disabled = false; }
      });
      body.appendChild(h("tr", {}, h("td", {}, h("strong", {}, m.id), m.tools ? "" : h("span", { class: "hint" }, " (no tools)")), h("td", {}, `${Math.round(m.context / 1000)}k`), h("td", {}, state, t ? h("span", { class: "hint" }, ` ${t.at.slice(0, 10)}`) : null), h("td", {}, test, " ", use)));
    }
    table.appendChild(body);
    out.append(table, h("button", { class: "btn linklike", type: "button", onclick: () => show(true) }, "Read the list again"));
  }
  load.addEventListener("click", () => show(false));
  if (info.url.includes("openrouter.ai")) show(false);
  return box;
}

// Settings page: the language model behind the digital engineer.
export async function buildEngineerCard() {
  const card = h("div", { class: "card" });
  function draw(info) {
    clear(card);
    card.appendChild(h("h2", {}, "Digital engineer"));
    card.appendChild(h("p", { class: "hint" },
      "A language model that reads an incident (the event, the device, its recent events, earlier fixes) and says what it thinks is wrong and which of your remediation rules would fix it. It never runs anything and can only pick one of your rules. Any OpenAI-compatible server works: a local one (llama.cpp, Ollama, LM Studio) or a hosted one with your own key. Part of every licence and the free trial."));
    if (!info.allowed) card.appendChild(h("p", { class: "warn-text" }, "Needs a licence or the free trial (Settings → Licence)."));
    const enabled = h("input", { type: "checkbox" });
    enabled.checked = info.enabled;
    const url = h("input", { type: "url", value: info.url, placeholder: "http://192.168.0.5:8080/v1" });
    const model = h("input", { type: "text", value: info.model, placeholder: "qwen2.5-14b-instruct" });
    const key = h("input", { type: "password", autocomplete: "off", placeholder: info.has_key ? "(kept, type to change)" : "API key (empty for a local server)" });
    const redact = h("input", { type: "checkbox" });
    redact.checked = info.redact;
    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      save.disabled = true;
      try { draw(await put("/api/engineer", { enabled: enabled.checked, url: url.value, model: model.value, redact: redact.checked, ...(key.value ? { api_key: key.value } : {}) })); toast("Saved", "success"); }
      catch (err) { toast(err.message || "Could not save", "error"); save.disabled = false; }
    });
    const test = h("button", { class: "btn", type: "button" }, "Test the connection");
    test.addEventListener("click", async () => {
      test.disabled = true;
      try { await put("/api/engineer", { url: url.value, model: model.value, ...(key.value ? { api_key: key.value } : {}) }); const r = await post("/api/engineer/test", {}); toast(`The model answered: ${r.answer}`, "success"); }
      catch (err) { toast(err.message || "Failed", "error"); }
      test.disabled = false;
    });
    card.append(h("label", { class: "check" }, enabled, " Digital engineer is on"),
      h("div", { class: "field" }, h("label", {}, "Address (ends in /v1)"), url), h("div", { class: "field" }, h("label", {}, "Model"), model), h("div", { class: "field" }, h("label", {}, "API key"), key),
      h("label", { class: "check" }, redact, " Make it anonymous: replace IP addresses, MAC addresses and device names by placeholders before anything is sent"),
      h("details", {}, h("summary", { class: "hint" }, "What a trustworthy model needs"), h("ul", { class: "hint" },
        h("li", {}, "An OpenAI-compatible chat API (llama.cpp, Ollama, LM Studio, OpenRouter, OpenAI ...) with a context of at least 8,000 tokens."),
        h("li", {}, "It must reply with one JSON object and nothing else, copy names and numbers exactly, and not leave items out of a list. Answers that look right and are wrong are the danger."),
        h("li", {}, "In practice: a model of about 14 billion parameters or more, lightly compressed (4-bit or better), or a current hosted model. Very small or 2-bit models fail these tests."),
        h("li", {}, "“Thinking” models work but take longer. A slow model only makes answers slower, never wrong."),
        h("li", {}, "Run “Check the model” on the Automation → Insights page: six small exams with made-up data show how yours does."))),
      h("p", { class: "hint" }, "The commands of your rules are never sent, only their names and the kind of action. With a hosted model the incident still leaves your network: leave the anonymising on, or use a local model."),
      h("div", { class: "form-actions" }, save, test));
    card.appendChild(openRouterSection(info, key, () => get("/api/engineer").then(draw)));
  }
  draw(await get("/api/engineer"));
  return card;
}
