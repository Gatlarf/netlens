import { get, post } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";

// Every analysis report the digital engineer wrote (the ones that also arrive by e-mail as AR-<number>): open one again, send it again.
export async function buildAnalysisListCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Analysis reports"));
  const find = h("input", { type: "search", placeholder: "Find by number, device or text (AR-745)", "aria-label": "Find an analysis report", style: "max-width:28em" });
  const out = h("div", {});
  card.append(find, out);
  let rows;
  try {
    rows = (await get("/api/analysis?limit=200")).reports;
  } catch (err) {
    card.appendChild(h("p", { class: "error" }, err.message || "The reports could not be loaded"));
    return card;
  }
  const draw = () => {
    clear(out);
    const q = find.value.trim().toLowerCase().replace(/^ar-?/, "");
    const shown = rows.filter((r) => !q || String(r.report_id) === q || `${r.report_ref} ${r.incident_ref || ""} ${r.title} ${r.probable_cause || ""}`.toLowerCase().includes(find.value.trim().toLowerCase()));
    if (!shown.length) { out.appendChild(h("p", { class: "hint" }, rows.length ? "No report matches." : "No analysis report yet. One is written some minutes after an incident starts, or when you press Analyse on an incident or a device.")); return; }
    const table = h("table", { class: "data" }, h("thead", {}, h("tr", {}, ...["When", "Report", "Incident", "What it found", ""].map((t) => h("th", {}, t)))));
    const body = h("tbody", {});
    for (const r of shown) {
      const send = h("button", { class: "btn", type: "button", title: "Send it again through the alert channels that include it" }, "Send");
      send.addEventListener("click", async () => {
        send.disabled = true;
        try { const x = await post(`/api/analysis/${r.report_id}/send`, {}); toast(x.sent.length ? `Sent through ${x.sent.join(", ")}` : "Not sent", x.sent.length ? "success" : "error"); } catch (err) { toast(err.message || "Not sent", "error"); }
        send.disabled = false;
      });
      body.appendChild(h("tr", {}, h("td", {}, fmtTime(r.created)), h("td", { class: "mono" }, r.report_ref), h("td", { class: "mono" }, r.incident_ref || ""),
        h("td", {}, h("strong", {}, r.title), r.probable_cause ? h("div", { class: "hint" }, r.probable_cause) : null),
        h("td", {}, h("a", { class: "btn", href: `/api/analysis/${r.report_id}/html`, target: "_blank", rel: "noopener" }, "Open"), " ", send)));
    }
    table.appendChild(body);
    out.appendChild(table);
  };
  find.addEventListener("input", draw);
  draw();
  return card;
}
