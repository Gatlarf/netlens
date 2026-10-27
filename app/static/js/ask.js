// "Ask your network" in the top bar: a quick question from any page. It uses the same answer engine as Insights (built-in logic, or a language
// model when one is connected, with names anonymised first). The answer opens in a small panel under the box; nothing is changed by a question.
import { post } from "./api.js";
import { h, clear } from "./util.js";

const readFlag = (key, fallback) => { try { return localStorage.getItem(key) || fallback; } catch (e) { return fallback; } };

export function initAsk() {
  const form = document.getElementById("ask-form");
  const input = document.getElementById("ask-input");
  const panel = document.getElementById("ask-panel");
  if (!form || !input || !panel) return;
  let asked = 0;                    // only the newest question may fill the panel

  const close = () => { panel.hidden = true; input.setAttribute("aria-expanded", "false"); };
  const open = () => { panel.hidden = false; input.setAttribute("aria-expanded", "true"); };

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const question = input.value.trim();
    if (!question) return;
    const mine = ++asked;
    clear(panel);
    panel.append(h("p", { class: "ask-q" }, question), h("p", { class: "hint", role: "status" }, "Looking…"));
    open();
    let body;
    try {
      const mode = readFlag("netlens.ask.mode", "auto");
      const res = await post("/api/insights/ask", { question, mode: ["auto", "rules", "model"].includes(mode) ? mode : "auto", include_all: readFlag("netlens.ask.all", "0") === "1" });
      body = [h("p", { class: "ask-a" }, res.answer),
        h("p", { class: "hint" }, res.source === "model" ? `Answered by the language model from: ${(res.tools || []).join(", ") || "its own knowledge of the question"}.` : res.fell_back ? "The language model could not answer this one; the built-in logic answered." : "Answered by the built-in logic, from the numbers.")];
    } catch (err) {
      body = [h("p", { class: "error", role: "alert" }, err.message || "Could not answer.")];
    }
    if (mine !== asked) return;
    clear(panel);
    panel.append(h("p", { class: "ask-q" }, question), ...body,
      h("div", { class: "ask-actions" }, h("a", { class: "btn", href: "#/insights", onclick: close }, "Open Insights"), h("button", { type: "button", class: "btn", onclick: close }, "Close")));
  });
  input.addEventListener("keydown", (e) => { if (e.key === "Escape") { close(); input.blur(); } });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !panel.hidden) close(); });
  document.addEventListener("click", (e) => { if (!form.contains(e.target)) close(); });
  input.addEventListener("focus", () => { if (panel.childElementCount) open(); });
}
