// The arithmetic of table views (which columns, in which order, how wide, sorted how). No DOM, so it is tested on its own (tests/test_js_logic.py).
// A view is {columns: [keys], widths: {key: px}, sort: {key, dir} | null, filters: {name: text}}.

export const MIN_WIDTH = 48;

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// What a view means once it is held to what the table offers: unknown columns gone, the locked ones first, nothing twice.
export function normalise(view, known, locked) {
  const columns = [];
  for (const key of [...locked, ...(view.columns || [])]) if (known.includes(key) && !columns.includes(key)) columns.push(key);
  const widths = {};
  for (const [key, value] of Object.entries(view.widths || {})) if (columns.includes(key) && Number.isFinite(value) && value >= MIN_WIDTH && value <= 2000) widths[key] = Math.round(value);
  const sort = view.sort && known.includes(view.sort.key) ? { key: view.sort.key, dir: view.sort.dir === "desc" ? "desc" : "asc" } : null;
  const filters = {};
  for (const [key, value] of Object.entries(view.filters || {})) if (typeof value === "string" && value) filters[key] = value;
  return { columns, widths, sort, filters };
}

// Have the two views the same columns, widths, sort and filters? (the name and id do not count)
export function sameView(a, b, known, locked) {
  return same(normalise(a, known, locked), normalise(b, known, locked));
}

// Move one column a step left (-1) or right (+1); the locked ones at the front stay where they are, and nothing moves in front of them.
export function moveColumn(columns, key, delta, locked) {
  const i = columns.indexOf(key);
  const j = i + delta;
  if (i < 0 || locked.includes(key) || j < locked.length || j >= columns.length) return columns.slice();
  const out = columns.slice();
  [out[i], out[j]] = [out[j], out[i]];
  return out;
}

// Drop the column `key` where the column `before` is (or at the end when `before` is null).
export function dropColumn(columns, key, before, locked) {
  if (locked.includes(key) || key === before) return columns.slice();
  const out = columns.filter((c) => c !== key);
  let at = before === null ? out.length : out.indexOf(before);
  if (at < 0) at = out.length;
  at = Math.max(at, locked.length);
  out.splice(at, 0, key);
  return out;
}

// Show or hide a column. A shown column is added at the end; a locked one cannot be hidden.
export function toggleColumn(columns, key, on, locked) {
  if (on) return columns.includes(key) ? columns.slice() : [...columns, key];
  return locked.includes(key) ? columns.slice() : columns.filter((c) => c !== key);
}

// Sort rows by a column; `value(row, key)` gives what to compare (a number or text). Rows without a value (null) go last, whichever way it is sorted.
export function sortRows(rows, sort, value) {
  if (!sort) return rows.slice();
  const sign = sort.dir === "desc" ? -1 : 1;
  return rows.slice().sort((a, b) => {
    const va = value(a, sort.key), vb = value(b, sort.key);
    const na = va === null || va === undefined || va === "", nb = vb === null || vb === undefined || vb === "";
    if (na || nb) return na === nb ? 0 : na ? 1 : -1;
    const c = typeof va === "number" && typeof vb === "number" ? va - vb : String(va).localeCompare(String(vb), undefined, { numeric: true, sensitivity: "base" });
    return c * sign;
  });
}

// CSV of the rows in the columns of the view. `text(row, key)` gives the plain text of a cell; `label(key)` the heading.
export function tableCsv(rows, columns, text, label) {
  const esc = (v) => (/[",\n\r]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
  return [columns.map((k) => esc(label(k))).join(","), ...rows.map((r) => columns.map((k) => esc(text(r, k) ?? "")).join(","))].join("\r\n") + "\r\n";
}
