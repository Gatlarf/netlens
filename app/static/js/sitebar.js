import { get } from "./api.js";
import { currentSite, enterSite, leaveSite } from "./site.js";

// The site switcher in the top bar and the banner while a remote site is shown. Only for administrators, and only when remote sites exist.
export async function initSiteBar(session) {
  const site = currentSite();
  document.body.classList.toggle("site-view", !!site);
  const old = document.getElementById("site-banner");
  if (old) old.remove();
  if (site) {
    const banner = document.createElement("div");
    banner.id = "site-banner";
    banner.className = "site-banner";
    banner.setAttribute("role", "note");
    const text = document.createElement("span");
    text.append("You are looking at ", Object.assign(document.createElement("b"), { textContent: site.name }), ": the pages of that site, live and read only, through this Netlens. ");
    const back = Object.assign(document.createElement("button"), { type: "button", className: "btn", textContent: "Back to this site" });
    back.addEventListener("click", leaveSite);
    banner.append(text, back);
    const header = document.getElementById("topbar");
    header.parentNode.insertBefore(banner, header.nextSibling);
  }
  const existing = document.getElementById("site-switch");
  if (existing) existing.remove();
  if (!session.authenticated || !session.user || session.user.role !== "admin" || session.user.scoped) return;
  let sites = [];
  try {
    sites = (await get("/api/probes")).filter((p) => p.enabled);
  } catch (e) {
    return;
  }
  if (!sites.length) return;
  const select = document.createElement("select");
  select.id = "site-switch";
  select.className = "site-switch";
  select.setAttribute("aria-label", "Site");
  select.title = "Which site to look at: this one, or a remote site (it must allow it)";
  select.append(Object.assign(document.createElement("option"), { value: "", textContent: "This site" }));
  for (const p of sites) {
    const ok = p.view && p.view.allowed;
    select.append(Object.assign(document.createElement("option"), {
      value: String(p.id), textContent: ok ? (p.view.connected ? p.name : `${p.name} (not connected)`) : `${p.name} (not allowed)`, disabled: !ok || !p.view.connected, selected: !!site && site.id === p.id,
    }));
  }
  if (site && !sites.some((p) => p.id === site.id)) select.append(Object.assign(document.createElement("option"), { value: String(site.id), textContent: site.name, selected: true }));
  select.addEventListener("change", () => {
    if (!select.value) leaveSite();
    else enterSite({ id: Number(select.value), name: select.selectedOptions[0].textContent.replace(/ \((not connected|not allowed)\)$/, "") });
  });
  document.querySelector(".topbar-actions").prepend(select);
}
