// Columns of a table that the reader can resize: drag the right edge of a column heading (double-click it to go back to automatic widths).
// The widths are remembered in the browser per table. Without a stored width the browser sizes the columns itself, so text uses the space there is.
const STORE = "netlens.colwidths.";
const MIN = 48;

function load(key) {
  try {
    const v = JSON.parse(localStorage.getItem(STORE + key) || "null");
    return Array.isArray(v) && v.every((n) => typeof n === "number" && n >= MIN && n < 4000) ? v : null;
  } catch (e) {
    return null;
  }
}

function save(key, widths) {
  try {
    if (widths) localStorage.setItem(STORE + key, JSON.stringify(widths)); else localStorage.removeItem(STORE + key);
  } catch (e) { /* not remembered */ }
}

export function makeResizable(table, key) {
  const heads = [...table.querySelectorAll("thead th")];
  if (!heads.length) return table;
  table.classList.add("resizable");

  const apply = (widths) => {
    if (!widths || widths.length !== heads.length) {
      table.style.tableLayout = "";
      table.style.width = "";
      heads.forEach((th) => { th.style.width = ""; });
      return;
    }
    table.style.tableLayout = "fixed";
    table.style.width = `${widths.reduce((a, b) => a + b, 0)}px`;
    heads.forEach((th, i) => { th.style.width = `${widths[i]}px`; });
  };
  apply(load(key));

  heads.forEach((th, i) => {
    if (i === heads.length - 1 && heads.length > 1 && !th.textContent.trim()) return;       // an empty last column has nothing to resize
    const grip = document.createElement("span");
    grip.className = "col-grip";
    grip.title = "Drag to resize the column; double-click for automatic widths";
    grip.setAttribute("aria-hidden", "true");
    th.appendChild(grip);
    grip.addEventListener("dblclick", (e) => { e.stopPropagation(); save(key, null); apply(null); });
    grip.addEventListener("pointerdown", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const widths = heads.map((x) => Math.round(x.getBoundingClientRect().width));       // freeze what is on screen, then change only this column
      apply(widths);
      const startX = e.clientX, startW = widths[i];
      grip.setPointerCapture(e.pointerId);
      grip.classList.add("dragging");
      const move = (ev) => {
        widths[i] = Math.max(MIN, Math.round(startW + ev.clientX - startX));
        apply(widths);
      };
      const stop = () => {
        grip.classList.remove("dragging");
        grip.removeEventListener("pointermove", move);
        grip.removeEventListener("pointerup", stop);
        grip.removeEventListener("pointercancel", stop);
        save(key, widths);
      };
      grip.addEventListener("pointermove", move);
      grip.addEventListener("pointerup", stop);
      grip.addEventListener("pointercancel", stop);
    });
    grip.addEventListener("click", (e) => e.stopPropagation());                             // a heading may sort: resizing must not
  });
  return table;
}

// Every ordinary table gets resizable columns by itself: this watches the page and prepares each table that appears (also after a page redraws it).
// A table opts out with the class "no-resize"; tables with merged heading cells or several heading rows, and tables of one column, are left alone.
const SELECTOR = "table.data, table.table, table.rep-table";
let scheduled = false;

function prepare(table) {
  if (table.classList.contains("no-resize") || table.querySelector("thead .col-grip")) return;
  const rows = table.querySelectorAll("thead tr");
  const heads = table.querySelectorAll("thead th");
  if (rows.length !== 1 || heads.length < 2 || table.querySelector("thead th[colspan]")) return;
  const key = `${location.hash.split("?")[0] || "#/"}|${[...heads].map((th) => th.textContent.trim()).join("|")}`.slice(0, 200);
  makeResizable(table, key);
}

export function autoResizable() {
  const run = () => { scheduled = false; document.querySelectorAll(SELECTOR).forEach(prepare); };
  new MutationObserver(() => {
    if (!scheduled) { scheduled = true; requestAnimationFrame(run); }
  }).observe(document.body, { childList: true, subtree: true });
  run();
}
