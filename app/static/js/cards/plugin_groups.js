// How plugin lists are grouped: by display category (see app/plugins/categories.py). The backend sends the ordered list of categories
// and every plugin's category; this file only turns that into groups, and remembers which groups the user opened.

const FALLBACK = [
  { id: "virtualization", label: "Virtualization & containers", short: "Virtualization" },
  { id: "network", label: "Network devices", short: "Network devices" },
  { id: "dns", label: "DNS", short: "DNS" },
  { id: "backup", label: "Backups", short: "Backups" },
  { id: "proxy", label: "Reverse proxies", short: "Reverse proxies" },
  { id: "storage", label: "Storage & NAS", short: "Storage & NAS" },
  { id: "documentation", label: "Documentation", short: "Documentation" },
];

// Items grouped in the order of `categories`; a plugin with an unknown category goes to the end under its own name.
export function groupByCategory(items, categories) {
  const list = categories && categories.length ? categories : FALLBACK;
  const groups = list.map((c) => ({ id: c.id, label: c.label, short: c.short || c.label, items: [] }));
  const byId = new Map(groups.map((g) => [g.id, g]));
  for (const item of items) {
    let g = byId.get(item.category);
    if (!g) {
      g = { id: item.category || "other", label: item.category || "Other", short: item.category || "Other", items: [] };
      byId.set(g.id, g);
      groups.push(g);
    }
    g.items.push(item);
  }
  return groups.filter((g) => g.items.length);
}

// Which groups are open, per list, kept while the page is in use (not stored anywhere).
const OPEN = new Map();
export function openSet(listName) {
  if (!OPEN.has(listName)) OPEN.set(listName, new Set());
  return OPEN.get(listName);
}

// A <details> element that remembers its state in `set` under `id`.
export function remember(details, set, id) {
  details.addEventListener("toggle", () => {
    if (details.open) set.add(id);
    else set.delete(id);
  });
  return details;
}
