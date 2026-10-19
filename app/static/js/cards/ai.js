import { h } from "../util.js";
import { buildEngineerCard } from "./engineer.js";
import { buildAssistantCard } from "./assistant.js";

// One page for everything about AI, in two parts that point in opposite directions.
export async function buildAiCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "AI"));
  card.appendChild(h("p", { class: "hint" }, "Two separate things. The language model is one Netlens calls, to word summaries and weigh incidents. The AI assistant is one outside Netlens that calls Netlens, to help you set it up or find a problem."));
  for (const build of [buildEngineerCard, buildAssistantCard]) {
    const part = await build();
    part.className = "ai-part";
    card.append(h("hr", {}), part);
  }
  return card;
}
