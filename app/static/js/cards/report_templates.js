import { get, post, put, del } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";
import { formDialog } from "../formdialog.js";

// Settings -> Notifications -> Customer reports: report templates (look, content, subject, period, schedule, recipients). The reports themselves are made and downloaded on the Reports page.
const DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const pad = (n) => String(n).padStart(2, "0");

export function scheduleText(s) {
  if (!s || s.frequency === "off") return "Not scheduled";
  return s.frequency === "weekly" ? `Every ${DAYS[s.weekday]} at ${pad(s.hour)}:00` : `On day ${s.monthday} of every month at ${pad(s.hour)}:00`;
}

export async function buildReportTemplatesCard() {
  const card = h("div", { class: "card admin-only report-templates" });
  let data = await get("/api/report-templates");
  let editing = null;                                       // null (the list), or the template being made or changed
  const refresh = async () => { data = await get("/api/report-templates"); };

  // ---------- the list ----------
  function list() {
    if (!data.templates.length) {
      return h("p", { class: "hint" }, "No reports yet. A report is a branded PDF (your logo and colour) with the sections you choose, for the whole network or for one customer's groups, made on demand or sent by e-mail on a schedule.");
    }
    const rows = data.templates.map((t) => h("tr", { class: t.enabled ? "" : "ar-off" },
      h("td", {}, h("strong", {}, t.name), h("div", { class: "hint" }, `${t.sections.length} sections · ${data.periods.find((p) => p.key === t.period).label.toLowerCase()}${t.scope.type === "group" ? " · some groups" : ""}`)),
      h("td", {}, scheduleText(t.schedule), h("div", { class: "hint" }, t.schedule.frequency === "off" ? "" : t.recipients.length ? `to ${t.recipients.length} address${t.recipients.length === 1 ? "" : "es"}` : "to the channel's addresses")),
      h("td", {}, !t.last_result ? h("span", { class: "hint" }, "never sent") : t.last_result.ok ? h("span", { class: "hint" }, `sent ${fmtTime(t.last_result.at)}`) : h("span", { class: "error", title: t.last_result.error }, `failed ${fmtTime(t.last_result.at)}`)),
      h("td", {}, h("div", { class: "row-actions" },
        h("button", { type: "button", class: "btn", onclick: () => { editing = JSON.parse(JSON.stringify(t)); draw(); } }, "Change"),
        h("button", { type: "button", class: "btn danger", onclick: async () => {
          if (!window.confirm(`Delete the report “${t.name}”?`)) return;
          try { await del(`/api/report-templates/${t.id}`); await refresh(); draw(); } catch (err) { toast(err.message || "Could not delete", "error"); }
        } }, "Delete")))));
    return h("div", { class: "table-wrap" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["Report", "Sent", "Last", ""].map((x) => h("th", {}, x)))), h("tbody", {}, rows)));
  }

  // ---------- the form ----------
  function form(t) {
    const isNew = !t.id;
    const f = h("form", { class: "ar-form" });
    const text = (value, placeholder, label, max = 120) => h("input", { type: "text", value: value || "", placeholder, maxlength: max, "aria-label": label });
    const name = text(t.name, "for example: Acme monthly report", "Name of the report", 60);
    const title = text(t.title, "The title on the first page", "Title", 80);
    const subtitle = text(t.subtitle, "for example: Managed by Example IT", "Subtitle");
    const preparedFor = text(t.prepared_for, "for example: Acme BV", "Prepared for", 80);
    const footer = text(t.footer, "for example: Example IT · support@example.com · 555 0100", "Footer", 160);
    const accent = h("input", { type: "color", value: t.accent || "#2563eb", "aria-label": "Colour" });
    const showNetlens = h("input", { type: "checkbox", checked: t.show_netlens !== false });

    // the logo: chosen here, stored when the report is saved
    let logoFile = null, removeLogo = false;
    const preview = h("img", { class: "rt-logo", alt: "", hidden: true });
    const logoInput = h("input", { type: "file", accept: "image/png,image/jpeg", "aria-label": "Logo" });
    const logoNote = h("span", { class: "hint" }, `PNG or JPEG, up to ${Math.round(data.max_logo / 1000)} KB. It is shown on the first page.`);
    const removeBtn = h("button", { type: "button", class: "btn", hidden: !(t.has_logo) }, "Remove the logo");
    if (t.has_logo) { preview.src = `/api/report-templates/${t.id}/logo?${Date.now()}`; preview.hidden = false; }
    logoInput.addEventListener("change", () => {
      const file = logoInput.files && logoInput.files[0];
      if (!file) return;
      if (file.size > data.max_logo) { toast(`That picture is larger than ${Math.round(data.max_logo / 1000)} KB`, "error"); logoInput.value = ""; return; }
      logoFile = file; removeLogo = false;
      preview.src = URL.createObjectURL(file); preview.hidden = false; removeBtn.hidden = false;
    });
    removeBtn.addEventListener("click", () => { logoFile = null; removeLogo = true; logoInput.value = ""; preview.hidden = true; removeBtn.hidden = true; });

    const sections = new Set(t.sections || ["summary", "availability", "incidents", "changes", "capacity"]);
    const sectionBoxes = data.sections.map((s) => h("label", { class: "check-row" }, h("input", { type: "checkbox", checked: sections.has(s.key), onchange: (e) => { if (e.target.checked) sections.add(s.key); else sections.delete(s.key); } }), ` ${s.label}`));
    const period = h("select", { "aria-label": "Period" }, data.periods.map((p) => h("option", { value: p.key }, p.label)));
    period.value = t.period || "7d";

    const scopeSel = h("select", { "aria-label": "What the report is about" }, h("option", { value: "all" }, "The whole network"), h("option", { value: "group" }, "Only some groups (for one customer)"));
    scopeSel.value = (t.scope || {}).type || "all";
    const picked = new Set((t.scope || {}).type === "group" ? t.scope.ids : []);
    const groupBox = h("div", { class: "event-boxes" }, data.groups.length ? data.groups.map((g) => h("label", { class: "check-row" }, h("input", { type: "checkbox", checked: picked.has(g.id), onchange: (e) => { if (e.target.checked) picked.add(g.id); else picked.delete(g.id); } }), ` ${g.name}`)) : h("p", { class: "hint" }, "There are no groups yet. Put a customer's devices in a group under Devices."));
    const showScope = () => { groupBox.hidden = scopeSel.value !== "group"; };
    scopeSel.addEventListener("change", showScope);
    showScope();

    const sched = t.schedule || { frequency: "off", weekday: 0, hour: 7, monthday: 1 };
    const freq = h("select", { "aria-label": "How often" }, [["off", "Only when I ask for it"], ["weekly", "Every week"], ["monthly", "Every month"]].map(([v, x]) => h("option", { value: v }, x)));
    freq.value = sched.frequency;
    const weekday = h("select", { "aria-label": "Weekday" }, DAYS.map((d, i) => h("option", { value: String(i) }, d)));
    weekday.value = String(sched.weekday);
    const monthday = h("select", { "aria-label": "Day of the month" }, Array.from({ length: 28 }, (_, i) => h("option", { value: String(i + 1) }, `day ${i + 1}`)));
    monthday.value = String(sched.monthday);
    const hour = h("select", { "aria-label": "Hour" }, Array.from({ length: 24 }, (_, i) => h("option", { value: String(i) }, `${pad(i)}:00`)));
    hour.value = String(sched.hour);
    const when = h("div", { class: "ar-inline" }, weekday, monthday, " at ", hour, h("span", { class: "hint" }, " (the time of the server; the first report comes at the next slot)"));
    const showWhen = () => { when.hidden = freq.value === "off"; weekday.hidden = freq.value !== "weekly"; monthday.hidden = freq.value !== "monthly"; };
    freq.addEventListener("change", showWhen);
    showWhen();

    const recipients = h("textarea", { rows: 2, placeholder: "customer@example.com, boss@example.com", "aria-label": "Recipients" });
    recipients.value = (t.recipients || []).join(", ");
    const channel = h("select", { "aria-label": "Send through" }, h("option", { value: "" }, data.channels.length ? "The first e-mail channel that is on" : "No e-mail channel yet"), ...data.channels.map((c) => h("option", { value: c.id }, c.name + (c.enabled ? "" : " (off)"))));
    channel.value = t.channel_id || "";
    const attach = h("input", { type: "checkbox", checked: t.attach_pdf !== false });
    const error = h("p", { class: "error", role: "alert", hidden: true });

    const read = () => ({
      ...(t.id ? { id: t.id } : {}), name: name.value, title: title.value, subtitle: subtitle.value, prepared_for: preparedFor.value, footer: footer.value, accent: accent.value, show_netlens: showNetlens.checked,
      sections: data.sections.map((s) => s.key).filter((k) => sections.has(k)), period: period.value, scope: scopeSel.value === "group" ? { type: "group", ids: [...picked] } : { type: "all" },
      schedule: { frequency: freq.value, weekday: Number(weekday.value), hour: Number(hour.value), monthday: Number(monthday.value) },
      recipients: recipients.value.split(/[,;\s]+/).filter(Boolean), channel_id: channel.value || null, attach_pdf: attach.checked, enabled: t.enabled !== false,
    });
    const save = h("button", { type: "submit", class: "btn primary" }, isNew ? "Add the report" : "Save the report");
    const cancel = h("button", { type: "button", class: "btn", onclick: () => { editing = null; draw(); } }, "Cancel");
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      error.hidden = true;
      try {
        const saved = isNew ? await post("/api/report-templates", read()) : await put(`/api/report-templates/${t.id}`, read());
        if (logoFile) {
          const response = await fetch(`/api/report-templates/${saved.id}/logo`, { method: "PUT", body: logoFile, headers: { "Content-Type": logoFile.type || "application/octet-stream" }, credentials: "same-origin" });
          if (!response.ok) toast((await response.json().catch(() => ({}))).detail || "The report is saved, but the logo could not be used", "error");
        } else if (removeLogo && t.has_logo) {
          await del(`/api/report-templates/${saved.id}/logo`);
        }
        await refresh();
        editing = null;
        toast("Saved", "success");
        draw();
      } catch (err) {
        error.textContent = err.message || "Could not save the report";
        error.hidden = false;
      }
    });
    const row = (label, ...controls) => h("div", { class: "ar-row" }, h("label", {}, label), ...controls);
    f.append(
      row("Name", name, h("p", { class: "hint" }, "Only you see this name.")),
      h("div", { class: "rt-look" }, row("Title", title), row("Subtitle", subtitle), row("Prepared for", preparedFor), row("Footer", footer),
        row("Colour", accent), row("Logo", h("div", { class: "ar-inline" }, preview, logoInput, removeBtn), logoNote)),
      h("div", { class: "ar-row" }, h("label", { class: "check-row" }, showNetlens, " Say “Made with Netlens” in the footer when it has no text of its own")),
      row("Sections", h("div", { class: "rt-sections" }, sectionBoxes)),
      row("Period", period),
      row("What it is about", scopeSel, groupBox),
      row("When it is sent", freq, when),
      row("E-mail it to", recipients, h("p", { class: "hint" }, "Separate the addresses with commas. Leave it empty to use the addresses of the e-mail channel.")),
      row("Send through", channel),
      h("div", { class: "ar-row" }, h("label", { class: "check-row" }, attach, " Attach the PDF")),
      error, h("div", { class: "form-actions" }, save, " ", cancel));
    return f;
  }

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Customer reports"));
    card.appendChild(h("p", { class: "hint" }, "Reports with your logo and colour, for the whole network or one customer. Make one now, or have it e-mailed as a PDF every week or month. They are made and downloaded on the Reports page."));
    if (editing) {
      card.appendChild(h("h3", {}, editing.id ? `Change “${editing.name}”` : "Add a report"));
      card.appendChild(form(editing));
      return;
    }
    card.appendChild(list());
    const bar = h("div", { class: "form-actions" });
    if (data.templates.length < data.max_templates) bar.appendChild(h("button", { type: "button", class: "btn primary", onclick: () => { editing = { sections: ["summary", "availability", "incidents", "changes", "capacity"], period: "7d", scope: { type: "all" } }; draw(); } }, "Add a report"));
    if (data.templates.length) bar.appendChild(h("a", { class: "btn", href: "#/reports" }, "Make a report now"));
    card.appendChild(bar);
  }
  draw();
  void formDialog;
  return card;
}
