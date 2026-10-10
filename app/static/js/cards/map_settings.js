import { get, put } from "../api.js";
import { h, clear, toast, setDomainSuffix } from "../util.js";

const LAYOUT_LABELS = {
  free: "Free layout (drag devices where you like)",
  tree: "Tree layout (top to bottom)",
  horizontal: "Horizontal layout (left to right, like Omada)",
};

function browserChoice() {
  try {
    return localStorage.getItem("netlens.map.layout");
  } catch (e) {
    return null;
  }
}

function forgetBrowserChoice() {
  try {
    localStorage.removeItem("netlens.map.layout");
  } catch (e) {
    // nothing stored, nothing to forget
  }
}

function fillMapCard(card, cfg) {
  clear(card);
  card.appendChild(h("h2", {}, "Map"));
  const form = h("form", { class: "edit-form" });

  const select = h("select", { name: "default_layout" });
  for (const key of cfg.layouts) select.appendChild(h("option", { value: key }, LAYOUT_LABELS[key] || key));
  select.value = cfg.default_layout;
  const field = h("div", { class: "field" });
  field.appendChild(h("label", {}, "Layout the map opens with"));
  field.appendChild(select);
  field.appendChild(h("p", { class: "hint" },
    "Used in every browser where nobody picked a layout in the map's own layout menu. A layout chosen in the map is remembered per browser and wins over this setting."));
  form.appendChild(field);

  const guestsBox = h("input", { type: "checkbox", name: "show_guests", checked: !!cfg.show_guests });
  const guestsField = h("div", { class: "field" });
  guestsField.appendChild(h("label", {}, "Containers on the map"));
  guestsField.appendChild(h("label", { class: "check" }, guestsBox, " Show containers and apps under their host"));
  guestsField.appendChild(h("p", { class: "hint" },
    "Draws the running containers and apps that are not a device themselves (a bridge container, a TrueNAS app) as small dashed dots under the host they run on. Virtual machines are devices and are always on the map. The map's own menu can override this per browser."));
  form.appendChild(guestsField);

  const suffixInput = h("input", { type: "text", name: "domain_suffix", placeholder: "home.example.com", value: cfg.domain_suffix || "", autocomplete: "off" });
  const suffixField = h("div", { class: "field" });
  suffixField.appendChild(h("label", {}, "Domain suffix to hide"));
  suffixField.appendChild(suffixInput);
  suffixField.appendChild(h("p", { class: "hint" },
    "Names ending in this suffix are shown without it (blueiris.home.example.com becomes blueiris) on the map, the device list and the other pages. The full name is kept and shown as a tooltip and on the device page. Leave empty to show full names."));
  form.appendChild(suffixField);

  const saveBtn = h("button", { type: "submit", class: "btn" }, "Save");
  form.appendChild(saveBtn);

  const mine = browserChoice();
  if (mine) {
    const forgetBtn = h("button", { type: "button", class: "btn" }, "Forget this browser's choice");
    forgetBtn.addEventListener("click", () => {
      forgetBrowserChoice();
      toast("This browser now follows the default layout", "success");
      fillMapCard(card, cfg);
    });
    form.appendChild(forgetBtn);
    form.appendChild(h("p", { class: "hint" }, `This browser has its own choice: ${LAYOUT_LABELS[mine] || mine}.`));
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    saveBtn.disabled = true;
    try {
      const updated = await put("/api/map-settings", { default_layout: select.value, domain_suffix: suffixInput.value, show_guests: guestsBox.checked });
      setDomainSuffix(updated.domain_suffix);
      toast("Map settings saved", "success");
      fillMapCard(card, updated);
    } catch (err) {
      toast(err.message || "Failed to save", "error");
      saveBtn.disabled = false;
    }
  });

  card.appendChild(form);
}

export async function buildMapCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Map"));
  card.appendChild(h("p", { class: "hint" }, "Loading..."));
  try {
    fillMapCard(card, await get("/api/map-settings"));
  } catch (err) {
    clear(card);
    card.appendChild(h("h2", {}, "Map"));
    card.appendChild(h("p", { class: "error" }, err.message || "Failed to load"));
  }
  return card;
}
