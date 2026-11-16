import { get } from "./api.js";
import { h, clear } from "./util.js";

const SEEN_KEY = "netlens.whatsNewSeen";

function remembered() {
  try { return localStorage.getItem(SEEN_KEY); } catch (err) { return null; }
}

function remember(version) {
  try { localStorage.setItem(SEEN_KEY, version); } catch (err) { /* the popup may then show again, which is harmless */ }
}

// `code` and **bold** inside a change; everything else is plain text
function inline(text) {
  const out = [];
  const re = /`([^`]+)`|\*\*([^*]+)\*\*|\*([^*\s][^*]*)\*/g;
  let last = 0;
  for (const m of text.matchAll(re)) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(m[1] !== undefined ? h("code", {}, m[1]) : m[2] !== undefined ? h("b", {}, m[2]) : h("i", {}, m[3]));
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function renderItem(item) {
  return h("li", { class: item.notable ? "cl-item cl-notable" : "cl-item" },
    item.notable ? h("span", { class: "cl-star", title: "Notable change" }, "★") : null,
    item.title ? h("b", { class: "cl-title" }, item.title.replace(/[.:]+$/, "")) : null, item.title && item.text ? (/^[(\[]/.test(item.text) ? " " : ": ") : null, ...inline(item.text));
}

function releaseHead(release) {
  return [h("span", { class: "cl-version" }, `v${release.version}`),
    release.date ? h("span", { class: "cl-date" }, release.date) : null,
    release.note ? h("span", { class: "cl-note" }, release.note) : null];
}

function renderBody(release, keep) {
  const body = h("div", { class: "cl-body" });
  for (const section of release.sections) {
    const items = keep ? section.items.filter(keep) : section.items;
    if (!items.length) continue;
    body.appendChild(h("h4", {}, section.title));
    body.appendChild(h("ul", {}, ...items.map(renderItem)));
  }
  return body;
}

const notableOf = (release) => release.sections.some((s) => s.items.some((i) => i.notable));

// Settings → About: every release, the newest open, with a switch for notable changes only
export async function buildChangelogCard() {
  const data = await get("/api/changelog");
  const card = h("div", { class: "card changelog-card" });
  const only = h("input", { type: "checkbox", name: "cl_notable" });
  const list = h("div", { class: "cl-list" });
  function fill() {
    clear(list);
    const shown = data.releases.filter((r) => !only.checked || notableOf(r));
    if (!shown.length) list.appendChild(h("p", { class: "hint" }, "Nothing to show."));
    shown.forEach((release, i) => {
      list.appendChild(h("details", { class: "cl-release", open: i === 0 }, h("summary", {}, ...releaseHead(release)), renderBody(release, only.checked ? (i) => i.notable : null)));
    });
  }
  only.addEventListener("change", fill);
  card.append(h("h2", {}, "Changelog"),
    h("p", { class: "hint" }, "What changed in every release. ★ marks the notable changes, the ones the “What’s new” window shows after an update."),
    h("div", { class: "field" }, h("label", {}, only, " Notable changes only")), list);
  fill();
  return card;
}

// After an update: a window with the notable changes since the version this browser last saw.
// When nothing in that range is marked notable, the new and changed things are listed instead (never fixes only), so an update is never silent.
// The version counts as seen when the window is closed, not when it opens: a reload in between shows it again.
let showing = false;
export async function maybeShowWhatsNew() {
  if (showing) return;
  try {
    const current = (await get("/api/health")).version;          // not the whole changelog, only to learn the version
    if (!current || current.includes("dev")) return;
    const seen = remembered();
    if (!seen) { remember(current); return; }        // first visit of this browser: nothing to compare with
    if (seen === current) return;
    const data = await get(`/api/changelog?since=${encodeURIComponent(seen)}`);
    let keep = (i) => i.notable;
    let releases = data.releases.filter(notableOf);
    if (!releases.length) {
      releases = data.releases.map((r) => ({ ...r, sections: r.sections.filter((s) => !/^fixed$/i.test(s.title)) })).filter((r) => r.sections.length);
      keep = null;
    }
    if (!releases.length) { remember(current); return; }
    showing = true;
    const dialog = h("dialog", { class: "whats-new", "aria-labelledby": "whats-new-title" });
    const close = () => { remember(current); showing = false; dialog.close(); dialog.remove(); };
    const all = h("a", { class: "btn", href: "#/settings/about" }, "Full changelog");
    all.addEventListener("click", close);
    const body = h("div", { class: "cl-scroll" });
    for (const release of releases) {
      body.appendChild(h("section", { class: "cl-release-block" }, h("h3", {}, ...releaseHead(release)), renderBody(release, keep)));
    }
    dialog.append(h("h2", { id: "whats-new-title" }, "What’s new in Netlens"),
      h("p", { class: "hint" }, `Updated from v${seen} to v${current}.`), body,
      h("div", { class: "cl-actions" }, all, h("button", { class: "btn primary", type: "button", autofocus: true, onclick: close }, "Got it")));
    dialog.addEventListener("cancel", close);
    document.body.appendChild(dialog);
    dialog.showModal();
  } catch (err) {
    showing = false;      // the window is a courtesy: never block the app
  }
}

// A tab that stayed open while Netlens was updated: look again when it comes back into view
export function watchForUpdates() {
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") maybeShowWhatsNew(); });
  setInterval(() => { if (document.visibilityState === "visible") maybeShowWhatsNew(); }, 10 * 60 * 1000);
}
