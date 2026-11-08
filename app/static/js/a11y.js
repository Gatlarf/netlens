// Every form label points at its control, whatever code built the form: a click on the label focuses the field and a screen reader reads it.
// Cards build `<div class="field"><label>Text</label><input></div>` in many places; this connects the two afterwards, once per change of the page.

let counter = 0;
const CONTROL = "input, select, textarea";

export function labelFields(root) {
  for (const label of root.querySelectorAll("label:not([for])")) {
    if (label.querySelector(CONTROL)) continue;                                  // the control is inside the label
    let control = null;
    for (let node = label.nextElementSibling; node && !control; node = node.nextElementSibling) {
      control = node.matches(CONTROL) ? node : node.querySelector(CONTROL);      // the next control after the label, also inside a wrapper
      if (node.tagName === "LABEL") break;                                       // the next label starts another field
    }
    if (!control || control.type === "hidden") continue;
    if (!control.id) control.id = `lf-${++counter}`;
    label.setAttribute("for", control.id);
  }
}

const watched = new WeakSet();

export function watchLabels(root) {
  if (!root || watched.has(root)) return;                                        // once per page container, however often the page is drawn
  watched.add(root);
  let queued = false;
  const run = () => { queued = false; labelFields(root); };
  new MutationObserver(() => { if (!queued) { queued = true; requestAnimationFrame(run); } }).observe(root, { childList: true, subtree: true });
  labelFields(root);
}
