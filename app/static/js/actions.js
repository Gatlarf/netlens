// One look for the buttons of every page: the button that saves is blue and filled, cancel/reset/close are plain, delete is red. Pages build
// their buttons in many places; this runs over every button as it appears so none of them can drift (see docs/UI-RULES.md).
const SAVE = /^(save|apply|opslaan)\b/i;
const PLAIN = /^(cancel|close|discard|reset|back|undo|annuleer)\b/i;
const DANGER = /^(delete|remove all|forget|erase)\b/i;

function fix(button) {
  if (button.dataset.actionChecked === button.textContent) return;
  button.dataset.actionChecked = button.textContent;
  if (!button.classList.contains("btn")) return;             // icon buttons, menu items, tabs and so on keep their own look
  const text = button.textContent.trim();
  if (SAVE.test(text) || (button.getAttribute("type") === "submit" && !PLAIN.test(text) && !DANGER.test(text))) { button.classList.add("primary"); button.classList.remove("danger", "ghost"); }
  else if (PLAIN.test(text)) button.classList.remove("primary", "danger");
  else if (DANGER.test(text)) { button.classList.add("danger"); button.classList.remove("primary"); }
}

function scan(root) {
  if (root.nodeType !== 1) return;
  if (root.matches && root.matches("button, a.btn")) fix(root);
  for (const b of root.querySelectorAll("button.btn, a.btn")) fix(b);
}

export function initActions() {
  scan(document.body);
  new MutationObserver((records) => {
    for (const r of records) {
      for (const n of r.addedNodes) scan(n);
      if (r.type === "characterData" && r.target.parentElement) scan(r.target.parentElement);
    }
  }).observe(document.body, { childList: true, subtree: true, characterData: true });
}
