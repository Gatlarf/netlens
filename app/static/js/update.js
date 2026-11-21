import { get, put, post } from "./api.js";
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

    card.appendChild(h("h3", {}, "How to update"));
    card.appendChild(h("p", { class: "hint" },
      "Netlens runs from a read-only container, so it cannot update itself from the inside. You update it by pulling the newest image and recreating the container. " +
      "Your data, settings and plugins live in the data volume and stay as they are; the database upgrades itself when the new version starts."));
    const how = h("ul", { class: "hint" });
    for (const [where, what] of [
      ["Your own docker-compose.yml", "docker compose pull netlens && docker compose up -d netlens"],
      ["Portainer", "open the stack and press Update the stack with Re-pull image switched on"],
      ["Synology", "Container Manager → Project → netlens → Action → Build"],
      ["docker run", "docker pull ghcr.io/gatlarf/netlens:latest, then remove and start the container again with the same options"],
    ]) how.appendChild(h("li", {}, `${where}: `, what.startsWith("docker ") ? h("code", {}, what) : what));
    card.appendChild(how);
    card.appendChild(h("p", { class: "hint" }, "Plugins are the exception: update those under Settings → Plugin store, no new image needed. Take a backup first under Settings → Backup & restore if you like."));
  }
  await fill(await get("/api/update"));
  return card;
}

// Once, for administrators: the project has a new GitHub address and image name. The server only sends the notice when the new image exists;
// a build that already runs the new image never gets one. Waits for the "What's new" window to be closed first.
let movedShown = false;
export async function maybeShowMoved() {
  if (movedShown) return;
  movedShown = true;
  try {
    const { notice } = await get("/api/moved");
    if (!notice) { movedShown = false; return; }
    while (document.querySelector("dialog.whats-new[open]")) await new Promise((r) => setTimeout(r, 500));
    const dialog = h("dialog", { class: "whats-new", "aria-labelledby": "moved-title" });
    const done = async () => { try { await post("/api/moved/seen", {}); } catch (err) { /* it will simply be shown again */ } dialog.close(); dialog.remove(); };
    const link = h("a", { class: "btn", href: notice.github, target: "_blank", rel: "noopener noreferrer" }, "Open the new GitHub page");
    dialog.append(h("h2", { id: "moved-title" }, "Netlens has a new home"),
      h("p", {}, "Netlens moved to a new GitHub organisation and a new container image name. Your installation, your data and your settings are not affected and everything keeps working. To keep receiving updates in the long run, point your container at the new image the next time you update."),
      h("div", { class: "kv" }, h("span", { class: "kv-label" }, "GitHub"), h("a", { href: notice.github, target: "_blank", rel: "noopener noreferrer" }, notice.github)),
      h("div", { class: "kv" }, h("span", { class: "kv-label" }, "Container image"), h("code", {}, notice.image), h("span", { class: "hint" }, ` (was ${notice.old_image})`)),
      h("h3", {}, "How to switch"),
      h("ul", { class: "hint" },
        h("li", {}, "Your own docker-compose.yml: change the ", h("code", {}, "image:"), " line to ", h("code", {}, `${notice.image}:latest`), ", then ", h("code", {}, "docker compose pull netlens && docker compose up -d netlens")),
        h("li", {}, "docker run: ", h("code", {}, `docker pull ${notice.image}:latest`), ", then remove and start the container again with the same options and the new image name"),
        h("li", {}, "Portainer or Synology: change the image name of the stack or project and update it")),
      h("p", { class: "hint" }, "The old image name keeps receiving updates for a transition period, so there is no hurry. Old GitHub links keep working: they are forwarded."),
      h("div", { class: "cl-actions" }, link, h("button", { class: "btn primary", type: "button", autofocus: true, onclick: done }, "Got it")));
    dialog.addEventListener("cancel", (e) => { e.preventDefault(); done(); });
    document.body.appendChild(dialog);
    dialog.showModal();
  } catch (err) {
    movedShown = false;      // a courtesy: never block the app
  }
}
