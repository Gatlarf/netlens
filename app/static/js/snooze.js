import { post, del } from "./api.js";
import { h, toast, isAdmin, timeAgo } from "./util.js";

// "I know about this": a small menu that snoozes one problem for a while, and the button that ends it.
const CHOICES = [[60, "1 hour"], [240, "4 hours"], [1440, "24 hours"], [10080, "7 days"]];
const changed = () => document.dispatchEvent(new CustomEvent("netlens:snoozed"));

export function snoozeMenu(subject) {
  if (!subject || !isAdmin()) return null;
  const select = h("select", { class: "snooze-menu admin-only", "aria-label": "Snooze this problem", title: "I know about it: do not tell me again for a while (it ends by itself when the problem is over)" },
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

export function wakeButton(subject) {
  if (!isAdmin()) return null;
  const b = h("button", { class: "btn snooze-wake admin-only", type: "button", title: "Stop the snooze: tell me again if it is still a problem" }, "Wake");
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
