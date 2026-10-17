import { get, put, post } from "../api.js";
import { h, clear, toast } from "../util.js";

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
        h("li", {}, "Run “Check the model” on the Monitoring → Insights page: six small exams with made-up data show how yours does."))),
      h("p", { class: "hint" }, "The commands of your rules are never sent, only their names and the kind of action. With a hosted model the incident still leaves your network: leave the anonymising on, or use a local model."),
      h("div", { class: "form-actions" }, save, test));
  }
  draw(await get("/api/engineer"));
  return card;
}
