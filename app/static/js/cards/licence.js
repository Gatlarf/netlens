import { get, put, del, post } from "../api.js";
import { h, clear, toast } from "../util.js";

const STATE_TEXT = { free: "Free", trial: "Free trial", active: "Active", grace: "Ended, grace period", expired: "Ended", trial_over: "Trial ended", invalid: "Not valid" };
const SITES = (n) => (n === null ? "any number of remote sites" : `${n} remote site${n === 1 ? "" : "s"}`);

// Settings page: the edition, the licence key, the free trial.
export async function buildLicenceCard() {
  const card = h("div", { class: "card" });
  async function load() {
    draw(await get("/api/licence"));
  }

  function draw(info) {
    clear(card);
    card.appendChild(h("h2", {}, "Licence"));
    card.appendChild(h("p", { class: "hint" },
      "Netlens is free for home and noncommercial use, with one remote site. A licence key adds more remote sites to the central overview: Supporter takes in 3, Small business 10, Enterprise any number. Monitoring itself is never limited, and nothing is removed when a licence ends: extra sites are only frozen. Host agents (monitoring of locked-down hosts through a collector) are part of the Enterprise edition and the free trial."));
    card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, "Edition"), h("span", {}, h("strong", {}, info.name), " ", h("span", { class: "hl-badge" }, STATE_TEXT[info.state] || info.state))));
    card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, "Takes in"), h("span", {}, `${SITES(info.sites)} (${info.sites_used} added)`)));
    if (info.holder) card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, "Licensed to"), h("span", {}, info.holder)));
    if (info.expires) card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, info.state === "trial" ? "Trial ends" : "Valid until"), h("span", {}, info.expires)));
    else if (info.state === "active") card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, "Valid until"), h("span", {}, "for life")));
    if (info.message) card.appendChild(h("p", { class: ["grace", "expired", "trial_over", "invalid"].includes(info.state) ? "error" : "hint" }, info.message));
    if (info.sites_frozen) card.appendChild(h("p", { class: "error" }, `${info.sites_frozen} remote site${info.sites_frozen === 1 ? " is" : "s are"} frozen: they keep their data but are not updated and raise no alerts.`));
    if (info.clock_warning) card.appendChild(h("p", { class: "error" }, "The clock of this computer was set back. The licence uses the newest time it has seen."));

    const key = h("textarea", { rows: "3", spellcheck: "false", placeholder: "NLK1.…", class: "mono" });
    const save = h("button", { class: "btn primary", type: "button" }, "Use this key");
    save.addEventListener("click", async () => {
      save.disabled = true;
      try {
        draw(await put("/api/licence", { key: key.value }));
        toast("Licence key accepted", "success");
      } catch (err) {
        toast(err.message || "Could not use this key", "error");
        save.disabled = false;
      }
    });
    card.appendChild(h("div", { class: "field" }, h("label", {}, "Licence key"), key));
    const actions = h("div", { class: "form-actions" }, save);
    if (info.trial_available) {
      const trial = h("button", { class: "btn", type: "button" }, "Start the free 30-day trial");
      trial.addEventListener("click", async () => {
        if (!window.confirm("Start the free 30-day trial of the full version? It can be used once on this installation.")) return;
        trial.disabled = true;
        try { draw(await post("/api/licence/trial", {})); toast("The trial has started", "success"); } catch (err) { toast(err.message || "Could not start the trial", "error"); trial.disabled = false; }
      });
      actions.appendChild(trial);
    }
    if (["active", "grace", "expired", "invalid"].includes(info.state)) {
      const remove = h("button", { class: "btn danger", type: "button" }, "Remove the key");
      remove.addEventListener("click", async () => {
        if (!window.confirm("Remove the licence key from this installation?")) return;
        try { draw(await del("/api/licence")); } catch (err) { toast(err.message || "Could not remove it", "error"); }
      });
      actions.appendChild(remove);
    }
    card.appendChild(actions);
  }
  await load();
  return card;
}
