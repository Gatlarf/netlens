import { get, post } from "../api.js";
import { h, clear, toast, fmtTime, can } from "../util.js";

// Settings -> Access review: who has access and how it is protected, with findings; a CSV, a signed evidence pack, and "mark as reviewed".
export async function buildAccessReviewCard() {
  const card = h("div", { class: "card" });
  let rep = await get("/api/access-review");

  const download = (name, text, type) => { const a = h("a", { href: URL.createObjectURL(new Blob([text], { type })), download: name }); document.body.appendChild(a); a.click(); a.remove(); };

  function draw() {
    clear(card);
    const t = rep.totals;
    card.appendChild(h("h2", {}, "Access review"));
    card.appendChild(h("p", { class: "hint" }, `${t.active} active accounts (${t.administrators} administrators), ${t.without_second_factor} without a second factor, ${t.tokens} API tokens. Generated ${fmtTime(rep.generated)}. ${rep.last_review ? `Last reviewed ${fmtTime(rep.last_review.at)} by ${rep.last_review.by}${rep.last_review.comment ? `: ${rep.last_review.comment}` : ""}.` : "Not reviewed yet."}`));
    const lvl = { bad: "error", warn: "warn-text", info: "hint" };
    card.appendChild(rep.findings.length ? h("ul", {}, rep.findings.map((f) => h("li", { class: lvl[f.level] }, f.text))) : h("p", { class: "hint" }, "No findings."));
    const rows = rep.people.map((p) => h("tr", { class: p.disabled ? "hint" : "" }, h("td", {}, p.username, p.break_glass ? h("span", { class: "tag" }, "break-glass") : null), h("td", {}, p.custom_role ? `${p.role} (${p.custom_role})` : p.role), h("td", {}, p.source),
      h("td", { class: p.has_second_factor ? "" : "error" }, p.second_factor), h("td", { class: "hint" }, p.last_login ? `${fmtTime(p.last_login)}` : "never"), h("td", {}, String(p.tokens.length)), h("td", {}, p.disabled ? "disabled" : "")));
    card.appendChild(h("div", { class: "table-wrap" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["User", "Role", "Source", "Second factor", "Last sign-in", "Tokens", ""].map((x) => h("th", {}, x)))), h("tbody", {}, rows))));
    const buttons = [h("button", { class: "btn", type: "button", onclick: async () => { try { download("netlens-access-review.csv", await (await fetch("/api/access-review.csv", { credentials: "same-origin" })).text(), "text/csv"); } catch (err) { toast(err.message || "Failed", "error"); } } }, "Download CSV")];
    if (can("access_review") && document.body.dataset.role === "admin") {
      buttons.push(h("button", { class: "btn", type: "button", onclick: async () => { try { const doc = await post("/api/access-review/pack", {}); download(`netlens-evidence-${doc.report.generated.slice(0, 10)}.json`, JSON.stringify(doc, null, 2), "application/json"); toast("Signed pack made; its hash is in the audit log", "success"); } catch (err) { toast(err.message || "Failed", "error"); } } }, "Download signed evidence pack"));
      buttons.push(h("button", { class: "btn primary", type: "button", onclick: async () => {
        const comment = window.prompt("Mark the review as done. A note for the record (what you checked, what you changed):", "") ;
        if (comment === null) return;
        try { await post("/api/access-review/complete", { comment }); rep = await get("/api/access-review"); draw(); toast("Review recorded", "success"); } catch (err) { toast(err.message || "Failed", "error"); }
      } }, "Mark as reviewed"));
    }
    card.appendChild(h("div", { class: "btn-row" }, ...buttons));
  }
  draw();
  return card;
}
