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

// The same content as two settings pages, so each has one Save button: the model Netlens calls, and the agents that call Netlens.
export async function buildAiModelCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "AI language model"));
  card.appendChild(await buildEngineerCard());
  return card;
}

export async function buildAiAgentsCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "AI agents"));
  card.appendChild(h("p", { class: "hint" }, "Agents outside Netlens (Claude, ChatGPT, a local model with tools) that call Netlens: the assistant works through a written guide and the API, the MCP server through tools. A token may only do what you allow here."));
  for (const build of [buildAssistantCard, buildMcpCard]) {
    const part = await build();
    part.className = "ai-part";
    card.append(h("hr", {}), part);
  }
  return card;
}
