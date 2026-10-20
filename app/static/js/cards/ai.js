import { h } from "../util.js";
import { buildEngineerCard } from "./engineer.js";
import { buildAssistantCard } from "./assistant.js";
import { buildMcpCard } from "./mcp.js";

// One page for everything about AI, in two parts that point in opposite directions.
export async function buildAiCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "AI"));
  card.appendChild(h("p", { class: "hint" }, "Three parts. The language model is one Netlens calls, to word summaries and weigh incidents. The AI assistant and the MCP server are for agents outside Netlens that call Netlens, to help you set it up, find a problem or act for you: the assistant works through a written guide and the API, the MCP server through tools."));
  for (const build of [buildEngineerCard, buildAssistantCard, buildMcpCard]) {
    const part = await build();
    part.className = "ai-part";
    card.append(h("hr", {}), part);
  }
  return card;
}
