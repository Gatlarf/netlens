import { get, put } from "../api.js";
import { h, clear, toast } from "../util.js";
import { fmtNumber } from "../charts.js";

// The one switch for application statistics (which application and which device used how much traffic).
export async function buildUsageCard() {
  const card = h("div", { class: "card usage-card" });
  async function draw() {
    const state = await get("/api/usage");
    clear(card);
    card.appendChild(h("h2", {}, "Traffic statistics"));
    card.appendChild(h("p", {}, "Some routers can tell which application (YouTube, Netflix, a game...) each device used how much traffic for: the ASUS Traffic Analyzer, and the application statistics (DPI) of an Omada gateway. Netlens shows this in Statistics > Network > Applications and on the Network tab of each device."));
    card.appendChild(h("p", { class: "hint" }, "This is data about what people do online. In some countries it may not be collected at all, or only with the knowledge or consent of the people concerned (a home, a company and a guest network are not the same). It is switched off until you turn it on, and switching it off again deletes everything stored. Only administrators can see it."));
    const box = h("input", { type: "checkbox" });
    box.checked = state.enabled;
    card.appendChild(h("label", { class: "check-row" }, box, " Collect and keep application statistics"));
    card.appendChild(h("p", { class: "hint" }, state.enabled
      ? `${fmtNumber(state.stored_rows)} rows are stored. A router plugin must also have it enabled: ASUS under "Read the Traffic Analyzer statistics", Omada by entering an Open API client.`
      : "Nothing is read from the routers and nothing is stored."));
    box.addEventListener("change", async () => {
      const turnOff = !box.checked;
      if (turnOff && state.stored_rows && !confirm(`Switch it off and delete the ${fmtNumber(state.stored_rows)} stored rows?`)) {
        box.checked = true;
        return;
      }
      box.disabled = true;
      try {
        const done = await put("/api/usage", { enabled: box.checked });
        toast(done.enabled ? "Application statistics are on. The next sync of the router plugin fills them." : `Application statistics are off${done.removed_rows ? " and what was stored is deleted" : ""}.`, "success");
      } catch (err) {
        toast(err.message || "Could not save", "error");
      }
      draw();
    });
  }
  await draw();
  return card;
}
