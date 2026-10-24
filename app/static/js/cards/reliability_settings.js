import { get, put } from "../api.js";
import { h, toast } from "../util.js";

// The availability target the Reliability card on the dashboard measures against.
export async function buildReliabilityCard() {
  const doc = await get("/api/reliability?days=30");
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Reliability target"));
  card.appendChild(h("p", { class: "hint" }, "The Reliability card on the dashboard reports outages and the time to recover for the devices that matter (marked always-on or critical) and the services that are not marked low, and says whether their availability meets this target. 99.5% allows about 3.6 hours of downtime a month, 99.9% about 43 minutes."));
  const form = h("form", { class: "edit-form" });
  const input = h("input", { type: "number", name: "target", min: "50", max: "100", step: "0.01", value: String(doc.target) });
  form.append(h("div", { class: "field" }, h("label", {}, "Availability target (percent)"), input), h("button", { class: "btn primary", type: "submit" }, "Save"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await put("/api/reliability/target", { target: Number(input.value) });
      toast("Target saved", "success");
    } catch (err) { toast(err.message || "Could not save", "error"); }
  });
  card.appendChild(form);
  return card;
}
