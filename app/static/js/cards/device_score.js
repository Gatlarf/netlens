// The health score of one device as a chip next to its name (the same score the dashboard's Network health card adds up). A click opens the Health tab.
import { get } from "../api.js";
import { h } from "../util.js";

const PARTS = { uptime: "reachable this week", loss: "checks answered today", latency: "answer time", temperature: "temperature" };

export function describeScore(s, name = "This device") {
  if (!s || s.score == null) return null;
  const words = s.label === "good" ? "good" : s.label === "fair" ? "fair" : "poor";
  const lines = [`Health score ${s.score} of 100 (${words}).`];
  if (s.reason) lines.push(`${name} ${s.reason}.`);
  const parts = Object.entries(s.parts || {}).filter(([, v]) => v != null).map(([k, v]) => `${PARTS[k] || k}: ${v}`);
  if (parts.length) lines.push(parts.join(" · "));
  lines.push(s.counted ? "It counts towards the network health score." : "It does not count towards the network health score (only always-on and critical devices do).");
  return lines.join("\n");
}

// A chip that fills itself in; it stays out of the way (empty, hidden) while nothing is known or when the score cannot be read.
const cache = new Map();           // the page redraws itself every few seconds: the score is asked for once a minute at most
const scoreOf = (id) => {
  const hit = cache.get(id);
  if (hit && Date.now() - hit.at < 60000) return hit.promise;
  const promise = get(`/api/devices/${id}/score`);
  cache.set(id, { at: Date.now(), promise });
  promise.catch(() => cache.delete(id));
  return promise;
};

export function buildScoreChip(device) {
  const chip = h("a", { class: "score-chip", href: `#/device/${device.id}/health`, hidden: true, "aria-live": "polite" });
  scoreOf(device.id).then((s) => {
    const text = describeScore(s, device.name || "This device");
    if (!text) return;
    chip.className = `score-chip score-${s.label}`;
    chip.title = text;
    chip.setAttribute("aria-label", text.replace(/\n/g, " "));
    chip.replaceChildren(h("span", { class: "score-num" }, String(s.score)), h("span", { class: "score-word" }, "health"));
    chip.hidden = false;
  }).catch(() => {});
  return chip;
}
