import { get, del } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

// Card "Ignored devices": devices that were deleted with "ignore", which scans skip.
export async function buildIgnoredCard() {
  const card = h("div", { class: "card" });

  async function load() {
    clear(card);
    card.appendChild(h("h2", {}, "Ignored devices"));
    card.appendChild(h("p", { class: "hint" },
      "Scans skip these devices. Use it for things you never want in the list, such as container bridges or a neighbour's phone. " +
      "Delete a device and tick \"ignore\" to add one here."));
    let rows;
    try {
      rows = await get("/api/ignored");
    } catch (err) {
      card.appendChild(h("p", { class: "error" }, err.message || "Could not load the list"));
      return;
    }
    if (rows.length === 0) {
      card.appendChild(h("p", { class: "hint" }, "Nothing is ignored."));
      return;
    }
    const table = h("table", { class: "data" });
    const head = h("tr");
    ["Device", "Address", "Ignored", ""].forEach((c) => head.appendChild(h("th", {}, c)));
    table.appendChild(h("thead", {}, head));
    const body = h("tbody");
    for (const r of rows) {
      const remove = h("button", { class: "btn", type: "button" }, "Stop ignoring");
      remove.addEventListener("click", async () => {
        remove.disabled = true;
        try {
          await del(`/api/ignored/${r.id}`);
          toast("No longer ignored. The next scan adds it again if it is on the network.", "success");
          await load();
        } catch (err) {
          toast(err.message || "Could not remove it", "error");
          remove.disabled = false;
        }
      });
      body.appendChild(h("tr", {},
        h("td", {}, r.label),
        h("td", { class: "mono" }, r.mac || r.ip || ""),
        h("td", {}, timeAgo(r.added)),
        h("td", {}, remove)));
    }
    table.appendChild(body);
    card.appendChild(table);
  }

  await load();
  return card;
}
