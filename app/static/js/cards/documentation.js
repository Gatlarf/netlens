// The network documentation: who it is for, what it shows, and the buttons to preview and download it (a page without anything external, ready to print to PDF).
import { get, put } from "../api.js";
import { h, toast } from "../util.js";
import { previewHtml } from "../ui.js";

const MAX_LOGO = 150 * 1024;

export async function buildDocumentationCard() {
  const doc = await get("/api/documentation");
  const s = doc.settings;
  const field = (label, input, hint) => h("div", { class: "field" }, h("label", {}, label), input, hint ? h("p", { class: "hint" }, hint) : null);
  const text = (name, value, placeholder = "") => h("input", { type: "text", name, value, placeholder, maxlength: "100", autocomplete: "off" });
  const customer = text("customer", s.customer, "Bakery Janssens");
  const company = text("company", s.company, "Your company");
  const prepared = text("prepared_by", s.prepared_by, "Your name");
  const contact = text("contact", s.contact, "support@yourcompany.com · 012 34 56 78");
  const footer = h("input", { type: "text", name: "footer", value: s.footer, placeholder: "Confidential", maxlength: "300" });
  const accent = h("input", { type: "color", name: "accent", value: s.accent });
  let logo = s.logo;
  const preview = h("img", { class: "doc-logo", alt: "", src: logo || "" });
  preview.hidden = !logo;
  const file = h("input", { type: "file", accept: "image/png,image/jpeg,image/gif,image/webp" });
  file.addEventListener("change", () => {
    const f = file.files[0];
    if (!f) return;
    if (f.size > MAX_LOGO) { toast("The logo is larger than 150 KB: use a smaller image", "error"); file.value = ""; return; }
    const reader = new FileReader();
    reader.onload = () => { logo = String(reader.result); preview.src = logo; preview.hidden = false; };
    reader.readAsDataURL(f);
  });
  const clearLogo = h("button", { class: "btn", type: "button", onclick: () => { logo = ""; preview.hidden = true; file.value = ""; } }, "Remove the logo");
  const boxes = doc.sections.map((sec) => h("label", { class: "check-row" }, h("input", { type: "checkbox", "data-section": sec.id, checked: s.sections.includes(sec.id) }), " ", sec.label));
  const save = h("button", { class: "btn primary", type: "button" }, "Save");
  const body = () => ({ customer: customer.value, company: company.value, prepared_by: prepared.value, contact: contact.value, footer: footer.value, accent: accent.value, logo,
    sections: boxes.map((l) => l.firstChild).filter((i) => i.checked).map((i) => i.dataset.section) });
  save.addEventListener("click", async () => {
    try { await put("/api/documentation", body()); toast("Saved", "success"); } catch (err) { toast(err.message || "Could not save", "error"); }
  });
  const open = (download) => async () => {
    try { await put("/api/documentation", body()); } catch (err) { toast(err.message || "Could not save", "error"); return; }
    if (download) location.href = "/api/documentation/export?download=true";
    else previewHtml(s.customer || "Network documentation", "/api/documentation/export", "/api/documentation/export?download=true").catch((err) => toast(err.message || "Could not show the preview", "error"));
  };
  return h("div", { class: "card" }, h("h2", {}, "Network documentation"),
    h("p", { class: "hint" }, "One page about this network for a customer or for your own records: devices, subnets, gateway and DNS, monitored services, certificates, backups, security and the open points. It is made from what Netlens knows right now, contains no scripts and no external files, and prints to PDF from the browser."),
    h("div", { class: "grid-2" }, h("div", {}, field("For (customer or site)", customer), field("Prepared by", prepared), field("Company", company), field("Contact", contact), field("Footer line", footer)),
      h("div", {}, field("Accent colour", accent), field("Logo", h("div", {}, preview, file, clearLogo), "PNG, JPEG, GIF or WebP, up to 150 KB."), h("div", { class: "field" }, h("label", {}, "What to include"), h("div", { class: "event-boxes" }, boxes)))),
    h("div", { class: "form-actions" }, save, h("button", { class: "btn", type: "button", onclick: open(false) }, "Preview"), h("button", { class: "btn", type: "button", onclick: open(true) }, "Download")));
}
