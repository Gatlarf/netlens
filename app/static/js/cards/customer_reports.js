import { get, post } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";
import { formDialog } from "../formdialog.js";
import { scheduleText } from "./report_templates.js";

// Reports -> Customer reports: make a report from a template now (to look at, to download as a PDF, or to e-mail). The templates are made under Settings → Notifications → Customer reports.
export async function buildCustomerReportsCard() {
  const card = h("div", { class: "card customer-reports" });
  const data = await get("/api/report-templates");
  const monthIso = () => { const d = new Date(); d.setMonth(d.getMonth() - 1); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`; };

  function row(t) {
    const period = h("select", { "aria-label": `Period for ${t.name}` }, h("option", { value: "" }, `As set: ${data.periods.find((p) => p.key === t.period).label.toLowerCase()}`),
      ...data.periods.map((p) => h("option", { value: p.key }, p.label)), h("option", { value: "pick" }, "A month…"));
    const month = h("input", { type: "month", value: monthIso(), hidden: true, "aria-label": "Month" });
    period.addEventListener("change", () => { month.hidden = period.value !== "pick"; });
    const query = () => {
      const q = new URLSearchParams();
      if (period.value === "pick") q.set("month", month.value); else if (period.value) q.set("period", period.value);
      return q;
    };
    const url = (format) => { const q = query(); q.set("format", format); return `/api/report-templates/${t.id}/render?${q}`; };
    const pdf = h("a", { class: "btn primary", href: "#", onclick: (e) => { e.preventDefault(); const a = h("a", { href: url("pdf"), download: "" }); document.body.appendChild(a); a.click(); a.remove(); } }, "Download PDF");
    const look = h("a", { class: "btn", href: "#", onclick: (e) => { e.preventDefault(); window.open(url("html"), "_blank", "noopener"); } }, "Look at it");
    const mail = h("button", { type: "button", class: "btn", onclick: async () => {
      const got = await formDialog({ title: `E-mail “${t.name}”`, text: t.recipients.length ? `It goes to ${t.recipients.join(", ")}. Give another address to send it only there (a test to yourself).` : "Give the address to send it to (it has no recipients of its own).",
        fields: [{ key: "to", label: "Send it only to", value: "", placeholder: t.recipients.length ? "leave empty for its recipients" : "me@example.com", required: !t.recipients.length }], ok: "Send" });
      if (!got) return;
      mail.disabled = true;
      try {
        const body = { period: period.value && period.value !== "pick" ? period.value : null, month: period.value === "pick" ? month.value : null, to: got.to.trim() ? got.to.split(/[,;\s]+/).filter(Boolean) : null };
        const r = await post(`/api/report-templates/${t.id}/send`, body);
        toast(`Sent to ${r.sent_to.join(", ")}`, "success");
      } catch (err) {
        toast(err.message || "Could not send the report", "error");
      }
      mail.disabled = false;
    } }, "E-mail it…");
    return h("tr", {}, h("td", {}, h("strong", {}, t.name), h("div", { class: "hint" }, t.scope.type === "group" ? "some groups" : "the whole network", " · ", scheduleText(t.schedule), t.last_result && t.last_result.ok ? ` · last sent ${fmtTime(t.last_result.at)}` : "")),
      h("td", {}, h("div", { class: "ar-inline" }, period, month)), h("td", {}, h("div", { class: "row-actions" }, pdf, look, mail)));
  }

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Customer reports"));
    if (!data.templates.length) {
      card.appendChild(h("p", { class: "hint" }, "No reports yet. Make one under Settings → Notifications → Customer reports: your logo and colour, the sections you want, the whole network or one customer's groups."));
      card.appendChild(h("a", { class: "btn primary", href: "#/settings/reporttemplates" }, "Make a report"));
      return;
    }
    card.appendChild(h("div", { class: "table-wrap" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["Report", "Period", ""].map((x) => h("th", {}, x)))), h("tbody", {}, data.templates.map(row)))));
    card.appendChild(h("p", { class: "hint" }, "“Look at it” opens the report as a web page you can print. Change a report, its logo or its schedule under Settings → Notifications → Customer reports."));
    card.appendChild(h("a", { class: "btn", href: "#/settings/reporttemplates" }, "Change the reports"));
  }
  draw();
  return card;
}
