import { post, put, del } from "./api.js";
import { formDialog } from "./formdialog.js";
import { h, toast, isAdmin, timeAgo } from "./util.js";

// "I know about this": a small menu that snoozes one problem for a while, and the button that ends it.
const CHOICES = [[60, "1 hour"], [240, "4 hours"], [1440, "24 hours"], [10080, "7 days"]];
const changed = () => document.dispatchEvent(new CustomEvent("netlens:snoozed"));

export function snoozeMenu(subject) {
  if (!subject || !isAdmin()) return null;
  const select = h("select", { class: "snooze-menu act-only", "aria-label": "Snooze this problem", title: "I know about it: do not tell me again for a while (it ends by itself when the problem is over)" },
    h("option", { value: "" }, "Snooze…"), ...CHOICES.map(([m, t]) => h("option", { value: String(m) }, t)));
  select.addEventListener("click", (e) => e.stopPropagation());
  select.addEventListener("change", async () => {
    const minutes = Number(select.value);
    select.value = "";
    if (!minutes) return;
    try {
      await post("/api/snoozes", { subject, minutes });
      toast(`Snoozed for ${CHOICES.find(([m]) => m === minutes)[1]}. It ends sooner if the problem is over, and you hear of it again if it is still there.`, "success");
      changed();
    } catch (err) {
      toast(err.message || "Could not snooze", "error");
    }
  });
  return select;
}

// A recommendation about a router's or controller's settings is not snoozed but accepted (it is a choice, not an event): with a reason, until it is undone.
export function acceptButton(accept) {
  if (!accept || !isAdmin()) return null;
  const b = h("button", { class: "btn act-only", type: "button", title: "This is intended: keep it out of the problem list (Undo on the device page, Network tab, Gateway recommendations)" }, "Accept…");
  b.addEventListener("click", async (e) => {
    e.preventDefault();
    e.stopPropagation();
    const v = await formDialog({ title: "Accept this recommendation", fields: [{ key: "reason", label: "Why is this intended?", type: "textarea", required: true }], ok: "Accept" });
    if (!v || !v.reason.trim()) return;
    try {
      await put(`/api/devices/${accept.device_id}/config/advice/${encodeURIComponent(accept.finding)}`, { reason: v.reason });
      toast("Accepted. It stays out of the problem list until you undo it.", "success");
      changed();
    } catch (err) {
      toast(err.message || "Could not accept", "error");
    }
  });
  return b;
}

export function wakeButton(subject) {
  if (!isAdmin()) return null;
  const b = h("button", { class: "btn snooze-wake act-only", type: "button", title: "Stop the snooze: tell me again if it is still a problem" }, "Wake");
  b.addEventListener("click", async (e) => {
    e.stopPropagation();
    try {
      await del(`/api/snoozes?subject=${encodeURIComponent(subject)}`);
      changed();
    } catch (err) {
      toast(err.message || "Could not end the snooze", "error");
    }
  });
  return b;
}

export const untilText = (iso) => {
  const ms = Date.parse(iso) - Date.now();
  if (!(ms > 0)) return "ending";
  const m = Math.round(ms / 60000);
  return m < 90 ? `${m} min` : m < 2 * 1440 ? `${Math.round(m / 60)} h` : `${Math.round(m / 1440)} days`;
};

export function snoozedList(items, subjectOf = (i) => i.snooze) {
  if (!items || !items.length) return null;
  const rows = items.map((i) => h("li", { class: "d-snoozed" },
    h("a", { href: i.href }, i.text), " ",
    h("span", { class: "hint" }, `for another ${untilText(i.until)}${i.by ? ` · by ${i.by}` : ""}`), " ",
    wakeButton(subjectOf(i))));
  return h("details", { class: "snoozed-list" }, h("summary", {}, `Snoozed (${items.length})`), h("ul", { class: "d-attention" }, rows));
}
