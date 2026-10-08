import { get } from "../api.js";
import { h, clear, toast, statusDot, typeBadge } from "../util.js";

const SOURCE_LABEL = {
  manual: "set manually",
  proxmox: "Proxmox",
  uplink: "uplink",
  guess: "guess",
  route: "traceroute",
  gateway: "gateway",
  none: "",
};
const COLLAPSED_KEY = "netlens.hierarchy.collapsed";

function loadCollapsed() {
  try {
    const raw = JSON.parse(localStorage.getItem(COLLAPSED_KEY) || "[]");
    return new Set(Array.isArray(raw) ? raw : []);
  } catch (e) {
    return new Set();
  }
}

function saveCollapsed(set) {
  try {
    localStorage.setItem(COLLAPSED_KEY, JSON.stringify([...set]));
  } catch (e) {
    // storage unavailable: the state is only kept while the page is open
  }
}

// children first (they matter most), then by name
function byImportance(a, b) {
  if ((b.children > 0) !== (a.children > 0)) return b.children > 0 ? 1 : -1;
  return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
}

export async function render(container, params) {
  let disposed = false;
  let loading = false;
  let failing = false;
  let data = null;
  const collapsed = loadCollapsed();
  let filterText = "";

  clear(container);
  container.appendChild(h("h1", {}, "Network hierarchy"));
  container.appendChild(h("p", { class: "hint" },
    "Which device depends on which. A device's parent comes from Proxmox, the traceroute path or the default gateway, " +
    "or you set it by hand on the device page."));

  const card = h("div", { class: "card" });
  const summary = h("p", { class: "hint" }, "Loading...");
  const filterInput = h("input", {
    type: "text",
    class: "uptime-filter",
    placeholder: "Filter by name or IP",
    oninput: (e) => {
      filterText = e.target.value;
      draw();
    },
  });
  const expandBtn = h("button", { class: "btn", type: "button", onclick: () => { collapsed.clear(); saveCollapsed(collapsed); draw(); } }, "Expand all");
  const collapseBtn = h("button", { class: "btn", type: "button", onclick: () => {
    if (data) for (const n of data.nodes) if (n.children > 0) collapsed.add(n.id);
    saveCollapsed(collapsed);
    draw();
  } }, "Collapse all");
  card.appendChild(h("div", { class: "toolbar" }, filterInput, expandBtn, collapseBtn));
  card.appendChild(summary);
  const treeHolder = h("div", {});
  card.appendChild(treeHolder);
  container.appendChild(card);

  function buildRow(node, kids, byParent, matches, depth) {
    const li = h("li", { class: "tree-item", "data-id": String(node.id) });
    const open = filterText ? true : !collapsed.has(node.id);

    const line = h("div", { class: `tree-line${node.online ? "" : " offline"}` });
    if (kids.length > 0) {
      line.appendChild(h("button", {
        class: "tree-toggle",
        type: "button",
        "aria-expanded": String(open),
        title: open ? "Collapse" : "Expand",
        onclick: () => {
          if (collapsed.has(node.id)) collapsed.delete(node.id);
          else collapsed.add(node.id);
          saveCollapsed(collapsed);
          draw();
        },
      }, open ? "▾" : "▸"));
    } else {
      line.appendChild(h("span", { class: "tree-toggle placeholder" }, ""));
    }
    line.appendChild(statusDot(node.online));
    line.appendChild(h("a", { href: `#/device/${node.id}`, class: "tree-name" }, node.name));
    line.appendChild(typeBadge(node.type));
    if (node.ip && node.ip !== node.name) line.appendChild(h("span", { class: "mono hint" }, node.ip));
    if (node.descendants > 0) {
      line.appendChild(h("span", { class: "tree-count", title: `${node.children} directly below, ${node.descendants} in total` },
        `${node.descendants} below`));
    }
    if (node.parent_id !== null && SOURCE_LABEL[node.source]) {
      line.appendChild(h("span", { class: `tree-source src-${node.source}`, title: node.reason }, SOURCE_LABEL[node.source]));
    }
    li.appendChild(line);

    if (kids.length > 0 && open) {
      const ul = h("ul", { class: "tree" });
      for (const kid of kids) ul.appendChild(buildRow(kid, (byParent.get(kid.id) || []).filter((c) => matches.has(c.id)).sort(byImportance), byParent, matches, depth + 1));
      li.appendChild(ul);
    }
    return li;
  }

  function draw() {
    if (!data) return;
    const q = filterText.trim().toLowerCase();
    const byId = new Map(data.nodes.map((n) => [n.id, n]));
    const byParent = new Map();
    for (const n of data.nodes) {
      if (n.parent_id !== null) {
        if (!byParent.has(n.parent_id)) byParent.set(n.parent_id, []);
        byParent.get(n.parent_id).push(n);
      }
    }

    // with a filter: matching devices plus the chain above each, so the path stays visible
    const matches = new Set();
    for (const n of data.nodes) {
      if (!q || n.name.toLowerCase().includes(q) || (n.ip || "").toLowerCase().includes(q)) {
        let cur = n;
        while (cur && !matches.has(cur.id)) {
          matches.add(cur.id);
          cur = cur.parent_id !== null ? byId.get(cur.parent_id) : null;
        }
      }
    }

    const roots = data.nodes.filter((n) => n.parent_id === null && matches.has(n.id));
    const tops = roots.filter((n) => n.children > 0).sort((a, b) => b.descendants - a.descendants || byImportance(a, b));
    const lone = roots.filter((n) => n.children === 0).sort(byImportance);

    const fresh = h("div", {});
    if (data.nodes.length === 0) {
      fresh.appendChild(h("p", {}, "No devices yet. Run a scan first."));
    } else if (roots.length === 0) {
      fresh.appendChild(h("p", { class: "hint" }, "Nothing matches the filter."));
    }
    if (tops.length > 0) {
      const ul = h("ul", { class: "tree tree-root" });
      for (const root of tops) {
        ul.appendChild(buildRow(root, (byParent.get(root.id) || []).filter((c) => matches.has(c.id)).sort(byImportance), byParent, matches, 0));
      }
      fresh.appendChild(ul);
    }
    if (lone.length > 0) {
      fresh.appendChild(h("h3", {}, `Without a known parent (${lone.length})`));
      fresh.appendChild(h("p", { class: "hint" }, "Nothing says what these depend on yet. Open one and choose its parent under Network position."));
      const ul = h("ul", { class: "tree tree-root" });
      for (const n of lone) ul.appendChild(buildRow(n, [], byParent, matches, 0));
      fresh.appendChild(ul);
    }
    clear(treeHolder);
    treeHolder.appendChild(fresh);

    const s = data.stats;
    summary.textContent = `${s.devices} devices · ${s.with_parent} with a parent · ${s.manual} set manually · ${s.max_depth + 1} level${s.max_depth === 0 ? "" : "s"} deep`;
  }

  async function load() {
    if (loading || disposed) return;
    loading = true;
    try {
      const fresh = await get("/api/hierarchy");
      if (disposed) return;
      failing = false;
      data = fresh;
      draw();
    } catch (err) {
      if (disposed) return;
      if (!failing) toast("Failed to load the hierarchy", "error");
      failing = true;
    } finally {
      loading = false;
    }
  }

  await load();

  const interval = setInterval(load, 30000);
  const onScanFinished = () => load();
  document.addEventListener("netlens:scan-finished", onScanFinished);

  return () => {
    disposed = true;
    clearInterval(interval);
    document.removeEventListener("netlens:scan-finished", onScanFinished);
  };
}
