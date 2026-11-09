// One answer to "is somebody editing here?", so that nothing refreshes or rebuilds under the hands of a user who has not finished.
//
//   editing(root)      true while a field in `root` has the focus, a change was typed that is not saved yet, a dialog or a row menu is open
//   unsaved(root)      true when something typed in `root` is not saved yet (focus alone does not count): used before leaving the page
//   clean(box)         the changes in `box` are saved (done by itself after a successful save, see settled())
//   livePoll(fn, ms)   a timer for a page that skips a round while somebody edits and catches up as soon as they are done
//   keepDrafts(root, rebuild)   rebuild a card (after a save or an action) without losing what was typed in the other fields of it
//
// No imports: api.js, util.js and app.js all use this module.

const FIELDS = "input, select, textarea";
const SKIP_TYPES = new Set(["button", "submit", "reset", "image", "file", "hidden"]);
const looksLikeFilter = (el) => el.type === "search" || el.closest("[data-filter], [data-nosave], .toolbar, .filters") !== null
  || /\b(filter|search|find|zoek)/i.test(`${el.placeholder || ""} ${el.getAttribute("aria-label") || ""}`);

// the option a select starts on: the one marked selected, or the first (a select without a marked option shows its first, which is not a change)
function startOption(el) {
  const marked = [...el.options].findIndex((o) => o.defaultSelected);
  return marked >= 0 ? marked : 0;
}

function differs(el) {
  if (el.tagName === "SELECT") return el.multiple ? [...el.options].some((o) => o.selected !== o.defaultSelected) : el.selectedIndex !== startOption(el);
  if (el.type === "checkbox" || el.type === "radio") return el.checked !== el.defaultChecked;
  return el.value !== el.defaultValue;
}

function viewOf(root) { return root || document.getElementById("view") || document.body; }

// a field the user changed that has not been saved (a filter or search box does not count: it acts at once)
function dirtyFields(root) {
  return [...viewOf(root).querySelectorAll(FIELDS)].filter((el) => el.dataset.dirty === "1" && el.isConnected && !SKIP_TYPES.has(el.type) && !looksLikeFilter(el) && differs(el));
}

export function unsaved(root) { return dirtyFields(root).length > 0; }

export function editing(root) {
  const scope = viewOf(root);
  const a = document.activeElement;
  if (a && a !== document.body && scope.contains(a) && a.matches(FIELDS) && !SKIP_TYPES.has(a.type) && a.type !== "checkbox" && a.type !== "radio") return true;
  if (scope.querySelector("dialog[open], details.row-menu[open], [data-busy='1']")) return true;
  return unsaved(scope);
}

export function clean(box) {
  if (!box) return;
  for (const el of [box, ...box.querySelectorAll(FIELDS)]) if (el.dataset && el.dataset.dirty) {
    delete el.dataset.dirty;
    // what is on screen is now what is saved: it is the new starting point
    if (el.matches && el.matches(FIELDS)) {
      if (el.tagName === "SELECT") for (const o of el.options) o.defaultSelected = o.selected;
      else if (el.type === "checkbox" || el.type === "radio") el.defaultChecked = el.checked;
      else el.defaultValue = el.value;
    }
  }
}

// ---- the page tells nothing: the listeners find the changes themselves
let lastBox = null, lastAt = 0;
document.addEventListener("input", (e) => { const t = e.target; if (t instanceof Element && t.matches(FIELDS) && t.closest("#view")) t.dataset.dirty = "1"; }, true);
document.addEventListener("change", (e) => { const t = e.target; if (t instanceof Element && t.matches(FIELDS) && t.closest("#view")) t.dataset.dirty = "1"; }, true);
const remember = (e) => {
  const t = e.target instanceof Element ? e.target : null;
  if (!t) return;
  const hit = e.type === "submit" ? t : t.closest("button, [type=submit], a, summary");
  if (hit) { lastBox = hit.closest("form, tr, .edit-form, .card, [data-edit]"); lastAt = Date.now(); }
};
document.addEventListener("click", remember, true);
document.addEventListener("submit", remember, true);

// called when a request that changes something succeeded: what was typed in the box of the button that was pressed is saved now
export function settled() {
  if (lastBox && Date.now() - lastAt < 120000) { clean(lastBox); }
  lastBox = null;
}

// ---- timers that stop with the page
const scope = new Set();
export function stopPageTimers() { for (const stop of [...scope]) stop(); scope.clear(); }

export function livePoll(fn, ms, { root } = {}) {
  let stopped = false, owed = false, gen = 0;
  const run = async () => {
    if (stopped || document.hidden) return;
    if (editing(root && root.isConnected ? root : undefined)) { owed = true; return; }
    const mine = ++gen;
    owed = false;
    try { await fn(() => mine === gen && !stopped); } catch (err) { /* the page shows its own errors */ }
  };
  const timer = setInterval(run, ms);
  const later = () => { if (owed && !stopped) setTimeout(run, 400); };
  document.addEventListener("focusout", later);
  document.addEventListener("visibilitychange", later);
  const stop = () => { if (stopped) return; stopped = true; clearInterval(timer); document.removeEventListener("focusout", later); document.removeEventListener("visibilitychange", later); scope.delete(stop); };
  scope.add(stop);
  return { stop, now: run };
}

// ---- a rebuild that must happen, without losing the rest of what was typed
function keyOf(el, seen) {
  const base = `${el.tagName}|${el.type || ""}|${el.name || el.getAttribute("aria-label") || el.id || el.dataset.key || el.placeholder || ""}`;
  const n = (seen.get(base) || 0) + 1;
  seen.set(base, n);
  return `${base}#${n}`;
}

export function keepDrafts(root, rebuild) {
  const drafts = new Map(), seen = new Map();
  let focusKey = null, selection = null;
  const openKeys = new Set();
  [...root.querySelectorAll(FIELDS)].forEach((el) => {
    const key = keyOf(el, seen);
    if (el === document.activeElement) { focusKey = key; try { selection = [el.selectionStart, el.selectionEnd]; } catch (err) { selection = null; } }
    if (SKIP_TYPES.has(el.type) || el.type === "password" || !differs(el)) return;
    drafts.set(key, el.tagName === "SELECT" ? { value: el.value, was: el.options[startOption(el)]?.value }
      : el.type === "checkbox" || el.type === "radio" ? { checked: el.checked, was: el.defaultChecked } : { value: el.value, was: el.defaultValue });
  });
  [...root.querySelectorAll("details")].forEach((d, i) => { if (d.open) openKeys.add(i); });
  const out = rebuild();
  const seen2 = new Map();
  [...root.querySelectorAll(FIELDS)].forEach((el) => {
    const key = keyOf(el, seen2), d = drafts.get(key);
    if (d) {
      const server = el.tagName === "SELECT" ? el.options[startOption(el)]?.value : el.type === "checkbox" || el.type === "radio" ? el.defaultChecked : el.defaultValue;
      if (server === d.was) {                                   // the server did not change this field: the typed value stays
        if ("checked" in d) el.checked = d.checked; else el.value = d.value;
        el.dataset.dirty = "1";
      }
    }
    if (key === focusKey) { el.focus(); try { if (selection && selection[0] != null) el.setSelectionRange(selection[0], selection[1]); } catch (err) { /* not a text field */ } }
  });
  [...root.querySelectorAll("details")].forEach((d, i) => { if (openKeys.has(i)) d.open = true; });
  return out;
}
