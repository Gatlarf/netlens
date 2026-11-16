// Export and import of a dashboard layout: a small JSON file that carries which cards, in which order, how wide, and the cards somebody made.
// No DOM in here (tests/test_js_logic.py runs it with node). The server still checks every card when the layout is saved.
export const FORMAT = "netlens-dashboard";
export const VERSION = 1;
export const MAX_BYTES = 512 * 1024;
const BOUND_TO_THIS_INSTALLATION = new Set(["device", "service"]);       // these name a device or a check by its number, which means nothing elsewhere
const SIZES = new Set(["s", "w", "f"]);

// The document for the dashboard as it is now. `cardOf(id)` gives the definition of a card somebody made (own or shared), or null for a built-in one.
export function buildExport({ order, sizes, cardOf, name = "", appVersion = "", now = new Date() }) {
  const custom = [];
  for (const id of order) {
    const def = id.startsWith("c-") ? cardOf(id) : null;
    if (def && !custom.some((c) => c.id === def.id)) custom.push(JSON.parse(JSON.stringify(def)));        // a shared card travels as a card of its own
  }
  return {
    format: FORMAT, version: VERSION, app: appVersion, exported: now.toISOString().replace(/\.\d+Z$/, "Z"), name: String(name).slice(0, 80),
    layout: { order: [...order], sizes: Object.fromEntries(Object.entries(sizes || {}).filter(([id]) => order.includes(id))) },
    custom,
  };
}

export function exportFileName(now = new Date()) {
  return `netlens-dashboard-${now.toISOString().slice(0, 10)}.json`;
}

// Read a file the person chose. `known` = the ids of the cards this Netlens has (built in and from the plugins that are on); `newId()` makes an id for a card of their own.
// Returns {ok: true, name, order, sizes, custom, skipped: [{id, why}], counts} or {ok: false, error}.
export function parseImport(text, { known, newId }) {
  if (typeof text !== "string" || text.length > MAX_BYTES) return { ok: false, error: "That file is too large to be a dashboard." };
  let doc;
  try { doc = JSON.parse(text); } catch (err) { return { ok: false, error: "That is not a dashboard file (it is not valid JSON)." }; }
  if (!doc || typeof doc !== "object" || doc.format !== FORMAT) return { ok: false, error: "That is not a Netlens dashboard file." };
  if (typeof doc.version !== "number" || doc.version > VERSION) return { ok: false, error: "That file comes from a newer Netlens. Update Netlens to import it." };
  const layout = doc.layout && typeof doc.layout === "object" ? doc.layout : null;
  if (!layout || !Array.isArray(layout.order) || layout.order.length > 100 || !layout.order.every((x) => typeof x === "string" && /^[a-z0-9_.-]{1,48}$/.test(x))) return { ok: false, error: "The list of cards in that file is not valid." };
  if (doc.custom !== undefined && (!Array.isArray(doc.custom) || doc.custom.length > 40 || !doc.custom.every((c) => c && typeof c === "object" && typeof c.id === "string"))) return { ok: false, error: "The cards of your own in that file are not valid." };

  const skipped = [];
  const renamed = new Map();                // the id a card had in the file -> the id it gets here, so it can never replace one of your own
  const custom = [];
  for (const raw of doc.custom || []) {
    if (BOUND_TO_THIS_INSTALLATION.has(raw.type)) { skipped.push({ id: raw.id, title: raw.title || raw.id, why: raw.type === "device" ? "it shows one device, which has another number here" : "it shows one service check, which has another number here" }); continue; }
    if (renamed.has(raw.id)) continue;
    const id = newId();
    renamed.set(raw.id, id);
    custom.push({ ...raw, id });
  }
  const order = [];
  for (const id of layout.order) {
    const target = renamed.get(id) || (known.has(id) ? id : null);
    if (target === null) {
      if (!skipped.some((s) => s.id === id)) skipped.push({ id, title: id, why: id.startsWith("c-") ? "the file does not contain it" : "this Netlens has no such card (a plugin that is not installed or switched on)" });
      continue;
    }
    if (!order.includes(target)) order.push(target);
  }
  const used = new Set(order);
  const kept = custom.filter((c) => used.has(c.id));                 // a card that is in the file but not on its dashboard is not brought in
  const sizes = {};
  for (const [id, size] of Object.entries(layout.sizes || {})) {
    const target = renamed.get(id) || id;
    if (used.has(target) && SIZES.has(size)) sizes[target] = size;
  }
  if (!order.length) return { ok: false, error: "None of the cards in that file exist in this Netlens." };
  return { ok: true, name: typeof doc.name === "string" ? doc.name.slice(0, 80) : "", from: typeof doc.app === "string" ? doc.app.slice(0, 20) : "", exported: typeof doc.exported === "string" ? doc.exported.slice(0, 20) : "",
    order, sizes, custom: kept, skipped, counts: { cards: order.length, own: kept.length, skipped: skipped.length } };
}
