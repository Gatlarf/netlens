import { get, post } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";

// Settings -> Approvals: requests from other administrators that wait for a decision, your own requests, and what was decided lately.
export async function buildApprovalsCard() {
  const card = h("div", { class: "card admin-only" });
  let data;
  try { data = await get("/api/approvals"); } catch (err) {
    card.append(h("h2", {}, "Approvals"), h("p", { class: "hint" }, err.message || "Approvals could not be loaded. They are for people signed in with a user account, not the access token."));
    return card;
  }

  async function decide(item, approve) {
    const comment = approve ? "" : (window.prompt("Why not? (they see this)", "") || "");
    try { await post(`/api/approvals/${item.id}/decide`, { approve, comment }); toast(approve ? "Approved" : "Denied", "success"); data = await get("/api/approvals"); draw(); } catch (err) { toast(err.message || "Could not decide", "error"); }
  }

  function table(rows, extra) {
    return h("div", { class: "table-wrap" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["Who", "What", "Why", "When", extra ? "" : "Result"].map((t) => h("th", {}, t)))),
      h("tbody", {}, rows.map((r) => h("tr", {}, h("td", {}, r.requester), h("td", {}, `${r.action_text}${r.label ? ` · ${r.label}` : ""}`), h("td", {}, r.reason), h("td", { class: "hint" }, timeAgo(r.created)),
        h("td", {}, extra ? extra(r) : `${r.status}${r.decided_by ? ` by ${r.decided_by}` : ""}${r.comment ? ` (${r.comment})` : ""}`))))));
  }

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Approvals"));
    const on = data.policy.actions.map((a) => data.actions[a]).join(", ");
    card.appendChild(h("p", { class: "hint" }, on ? `Four-eyes approval is on for: ${on}. An approval is good for one use, for ${data.policy.minutes} minutes. Switch it on or off under Sign-in security.` : "Four-eyes approval is off (Settings → Sign-in security). When it is on, the actions you choose need a second administrator to say yes first."));
    card.appendChild(h("h3", {}, "Waiting for you"));
    card.appendChild(data.waiting.length ? table(data.waiting, (r) => h("div", { class: "row-actions" }, h("button", { class: "btn primary", type: "button", onclick: () => decide(r, true) }, "Approve"), h("button", { class: "btn danger", type: "button", onclick: () => decide(r, false) }, "Deny")))
      : h("p", { class: "hint" }, "Nothing is waiting."));
    if (data.mine.length) { card.appendChild(h("h3", {}, "Your requests")); card.appendChild(table(data.mine)); }
    if (data.recent.length) { card.appendChild(h("h3", {}, "Decided lately")); card.appendChild(table(data.recent)); }
  }
  draw();
  return card;
}
