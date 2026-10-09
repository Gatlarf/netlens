import { get, put } from "./api.js";
import { h, clear, toast, timeAgo } from "./util.js";

// The little badge next to the version: shown only when a newer Netlens has been published.
export async function initUpdateBadge() {
  const badge = document.getElementById("update-badge");
  if (!badge) return;
  async function refresh() {
    try {
      const u = await get("/api/update");
      badge.hidden = !u.available;
      document.body.classList.toggle("has-update", !!u.available);  // a dot on the menu buttons
      if (u.available) {
        badge.textContent = `Update ${u.latest} available`;
        badge.title = `You run ${u.current}. Click for how to update.`;
      }
    } catch (err) {
      badge.hidden = true;
      document.body.classList.remove("has-update");
    }
  }
  refresh();
  setInterval(refresh, 3600 * 1000);
  document.addEventListener("netlens:update-checked", refresh);
}

// Card for Settings -> About: current and latest version, a check-now button, the on/off switch and how to update.
export async function buildUpdateCard() {
  const card = h("div", { class: "card" });
  async function fill(u) {
    clear(card);
    card.appendChild(h("h2", {}, "Updates"));
    card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, "Running"), h("span", {}, u.current)));
    card.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, "Latest published"), h("span", {}, u.latest || "unknown")));
    if (u.available) {
      card.appendChild(h("p", { class: "update-note" }, `Version ${u.latest} is available. `, h("a", { href: u.changelog_url, target: "_blank", rel: "noopener noreferrer" }, "What changed"), " · ", h("a", { href: u.how_to_url, target: "_blank", rel: "noopener noreferrer" }, "How to update")));
    } else if (u.latest && u.enabled) {
      card.appendChild(h("p", { class: "hint" }, "You are up to date."));
    }
    if (u.error) card.appendChild(h("p", { class: "error" }, `Could not check: ${u.error}`));
    if (u.checked) card.appendChild(h("p", { class: "hint" }, `Last checked ${timeAgo(u.checked)}.`));
    const toggle = h("input", { type: "checkbox", name: "update_check", checked: u.enabled });
    toggle.addEventListener("change", async () => {
      try {
        fill(await put("/api/update", { enabled: toggle.checked }));
        document.dispatchEvent(new CustomEvent("netlens:update-checked"));
      } catch (err) {
        toast(err.message || "Could not change the setting", "error");
      }
    });
    const check = h("button", { class: "btn", type: "button" }, "Check now");
    check.disabled = !u.enabled;
    check.addEventListener("click", async () => {
      check.disabled = true;
      fill(await get("/api/update?refresh=true"));
      document.dispatchEvent(new CustomEvent("netlens:update-checked"));
    });
    card.appendChild(h("div", { class: "field" }, h("label", {}, toggle, " Check for new versions once a day")));
    card.appendChild(h("p", { class: "hint" }, "Only asks the container registry for the list of published version numbers. Nothing is installed automatically."));
    card.appendChild(check);
  }
  await fill(await get("/api/update"));
  return card;
}
