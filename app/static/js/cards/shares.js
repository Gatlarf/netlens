import { api, get } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";

const MODE_TEXT = { view: "Map and device list", status: "Status page only (counts and services)" };

function linkUrl(link) {
  return `${location.origin}/share/${link.token}`;
}

function fill(card, links) {
  clear(card);
  card.appendChild(h("h2", {}, "Share links"));
  card.appendChild(h("p", { class: "hint" },
    "A share link shows the network read-only to anyone who has the address, without a login: a family member, a landlord, a screen on the wall. " +
    "IP and MAC addresses are left out unless you choose to include them. Delete a link and it stops working at once. " +
    "Only share a link over a connection you trust: Netlens itself should not be reachable from the internet unprotected."));

  if (!links.length) {
    card.appendChild(h("p", { class: "hint" }, "No share links yet."));
  } else {
    const table = h("table", { class: "table shares" });
    table.appendChild(h("thead", {}, h("tr", {}, ["Name", "Shows", "Valid until", "Visits", ""].map((t) => h("th", {}, t)))));
    const body = h("tbody");
    for (const link of links) {
      const copy = h("button", { type: "button", class: "btn" }, "Copy link");
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(linkUrl(link));
          toast("Link copied", "success");
        } catch (e) {
          window.prompt("Copy this link:", linkUrl(link));
        }
      });
      const open = h("a", { class: "btn", href: `/share/${link.token}`, target: "_blank", rel: "noopener" }, "Open");
      const del = h("button", { type: "button", class: "btn danger" }, "Delete");
      del.addEventListener("click", async () => {
        if (!window.confirm(`Delete the link "${link.name}"? Anyone using it loses access.`)) return;
        try {
          fill(card, (await api(`/api/shares/${link.id}`, { method: "DELETE" })).links);
          toast("Link deleted", "success");
        } catch (err) {
          toast(err.message || "Could not delete the link", "error");
        }
      });
      const extra = [link.show_ips ? "IPs" : null, link.show_macs ? "MACs" : null].filter(Boolean);
      body.appendChild(h("tr", {},
        h("td", {}, h("strong", {}, link.name)),
        h("td", {}, MODE_TEXT[link.mode] || link.mode, extra.length ? h("span", { class: "hint" }, ` + ${extra.join(" and ")}`) : null),
        h("td", {}, link.expired ? h("span", { class: "error" }, "expired") : link.expires ? fmtTime(link.expires) : "no end"),
        h("td", {}, `${link.views}`, link.last_used ? h("span", { class: "hint" }, ` (last ${fmtTime(link.last_used)})`) : null),
        h("td", {}, open, " ", copy, " ", del)));
    }
    table.appendChild(body);
    card.appendChild(table);
  }

  const form = h("form", { class: "edit-form", id: "new-share-form" });
  const name = h("input", { type: "text", name: "name", required: true, maxlength: "60", placeholder: "Family" });
  const mode = h("select", { name: "mode" });
  for (const [key, text] of Object.entries(MODE_TEXT)) mode.appendChild(h("option", { value: key }, text));
  const ips = h("input", { type: "checkbox", name: "show_ips" });
  const macs = h("input", { type: "checkbox", name: "show_macs" });
  const expires = h("select", { name: "expires" });
  for (const [value, text] of [["", "Never"], ["1", "1 day"], ["7", "7 days"], ["30", "30 days"], ["90", "90 days"]]) expires.appendChild(h("option", { value }, text));
  form.appendChild(h("h3", {}, "New link"));
  form.appendChild(h("div", { class: "field" }, h("label", {}, "Name (for you, so you know who has it)"), name));
  form.appendChild(h("div", { class: "field" }, h("label", {}, "What it shows"), mode));
  form.appendChild(h("div", { class: "field" }, h("label", { class: "check" }, ips, " Show IP addresses"), h("label", { class: "check" }, macs, " Show MAC addresses")));
  form.appendChild(h("div", { class: "field" }, h("label", {}, "Valid for"), expires));
  form.appendChild(h("button", { type: "submit", class: "btn" }, "Create link"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const res = await api("/api/shares", { method: "POST", body: { name: name.value, mode: mode.value, show_ips: ips.checked, show_macs: macs.checked, expires_days: expires.value ? Number(expires.value) : null } });
      toast("Link created", "success");
      fill(card, res.links);
    } catch (err) {
      toast(err.message || "Could not create the link", "error");
    }
  });
  card.appendChild(form);
}

export async function buildSharesCard() {
  const card = h("div", { class: "card" });
  fill(card, (await get("/api/shares")).links);
  return card;
}
