import { get, put } from "../api.js";
import { h, toast } from "../util.js";
import { isHud } from "../theme.js";
import { flash } from "../interface.js";

// Settings → Interface: how Netlens looks for everybody. The HUD options only show when the HUD look is on.
export async function buildInterfaceCard() {
  const doc = await get("/api/interface");
  const s = doc.settings;
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Interface"));
  card.appendChild(h("p", { class: "hint" }, "How Netlens looks for everybody. A user can always choose their own look with the moon / sun / ◈ button at the top right; this is what they see until they do."));
  const select = (name, label, options, value, hint) => {
    const el = h("select", { name }, options.map(([v, t]) => h("option", { value: v, selected: v === value }, t)));
    return { el, field: h("div", { class: "field" }, h("label", {}, label), el, hint ? h("p", { class: "hint" }, hint) : null) };
  };
  const look = select("default_look", "Look for new users", [["system", "Follow the device (light or dark)"], ["light", "Light"], ["dark", "Dark"], ["hud", "HUD (futuristic)"]], s.default_look, "Applies to everybody who has not chosen a look themselves, including on the sign-in page.");
  const seconds = h("input", { type: "number", name: "pulse_seconds", min: "0", max: "10", step: "0.5", value: String(s.pulse_seconds), style: "width:6em" });
  const scope = select("pulse_scope", "Show the flash on", [["hud", "The HUD page only"], ["all", "Every page (while the HUD look is on)"]], s.pulse_scope);
  const forWhom = select("pulse_for", "Flash for", [["all", "Every device"], ["always_on", "Always-on and critical devices"], ["critical", "Critical devices only"]], s.pulse_for, "Phones and tablets come and go all day; choose always-on to keep the flash for devices that matter.");
  let candidates = [];
  try { candidates = (await get("/api/traffic?range=1h")).candidates || []; } catch (e) { /* the choice is then only "find it" */ }
  const wanOptions = [["", "Find it automatically (a router interface named like WAN)"], ...candidates.map((c) => [`${c.device_id}|${c.label}`, `${c.device || `device ${c.device_id}`} · ${c.label}`])];
  if (s.wan && !wanOptions.some(([v]) => v === s.wan)) wanOptions.push([s.wan, s.wan]);
  const wan = select("wan", "Internet connection (WAN) interface", wanOptions, s.wan || "", "The line for the internet connection in the traffic graph of the HUD. It needs a health monitor (SNMP or SSH) on the router, or a plugin that records traffic.");
  const sweep = h("input", { type: "checkbox", name: "hud_sweep", checked: s.hud_sweep });
  const lines = h("input", { type: "checkbox", name: "hud_lines", checked: s.hud_lines });
  const preview = (kind) => h("button", { class: "btn", type: "button", onclick: () => {
    if (!isHud()) { toast("Switch to the HUD look first (the ◈ button at the top right)", "info"); return; }
    flash(kind, Number(seconds.value) || 2);
  } }, kind === "bad" ? "Preview: offline" : "Preview: back online");
  const form = h("form", { class: "edit-form" },
    look.field,
    h("h3", {}, "HUD scanline"),
    h("div", { class: "field" }, h("label", {}, "Flash duration (seconds)"), seconds, h("p", { class: "hint" }, "The scanline flashes red for a device that goes offline and green for one that comes back. 0 switches the flash off.")),
    scope.field, forWhom.field,
    h("div", { class: "field" }, h("label", {}, "Try it"), h("span", { class: "inline-actions" }, preview("bad"), " ", preview("good"))),
    h("h3", {}, "HUD traffic graph"),
    wan.field,
    h("h3", {}, "HUD effects"),
    h("label", { class: "check" }, sweep, " The slow scanline that runs down the screen"),
    h("label", { class: "check" }, lines, " The fine scanline texture over the screen"),
    h("div", { class: "form-actions" }, h("button", { class: "btn primary", type: "submit" }, "Save")));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const out = await put("/api/interface", { default_look: look.el.value, pulse_seconds: Number(seconds.value), pulse_scope: scope.el.value, pulse_for: forWhom.el.value, hud_sweep: sweep.checked, hud_lines: lines.checked, wan: wan.el.value });
      document.dispatchEvent(new CustomEvent("netlens:interface", { detail: out.settings }));
      toast("Saved", "success");
    } catch (err) { toast(err.message || "Could not save", "error"); }
  });
  card.appendChild(form);
  return card;
}
