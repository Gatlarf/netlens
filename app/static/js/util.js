import { decorate } from "./actions.js";

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);

  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") {
      el.className = value;
    } else if (key === "dataset") {
      for (const [dk, dv] of Object.entries(value)) {
        el.dataset[dk] = dv;
      }
    } else if (key.startsWith("on") && typeof value === "function") {
      el.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (value === true) {
      el.setAttribute(key, "");
    } else if (value === false || value === null || value === undefined) {
      // skip
    } else {
      el.setAttribute(key, String(value));
    }
  }

  function appendChildren(nodes) {
    for (const child of nodes) {
      if (child === null || child === false || child === undefined) {
        continue;
      }
      if (Array.isArray(child)) {
        appendChildren(child);
      } else if (child instanceof Node) {
        el.appendChild(child);
      } else {
        el.appendChild(document.createTextNode(String(child)));
      }
    }
  }

  appendChildren(children);

  return el;
}

// Refreshing without flicker: put `nodes` (freshly built) into `parent`, but keep every element that is already there and looks exactly the same, and replace
// only what differs. Scroll position, focus, typed text, open sections, running animations and drawn graphs survive a refresh that changed nothing.
// (A node that is already inside `parent`, such as a map that lives on, is moved, not copied.)
export function patch(parent, ...nodes) {
  const incoming = [];
  for (const n of nodes.flat(Infinity)) {
    if (n === null || n === undefined || n === false) continue;
    const node = n instanceof Node ? n : document.createTextNode(String(n));
    if (node instanceof DocumentFragment) incoming.push(...node.childNodes); else incoming.push(node);
  }
  // what an element looks like, leaving out what fills in later by itself (marked data-live: a graph that loads when a row is opened)
  // (and what the page adds to tables by itself afterwards: the grips to resize a column and the widths that go with them)
  const DECO = [[/<span class="col-grip"[^>]*><\/span>/g, ""], [/<(table|th)\b[^>]*>/g, (tag) => tag.replace(/ style="[^"]*"/, "").replace(/ resizable/, "")]];
  const plain = (html) => DECO.reduce((t, [re, to]) => t.replace(re, to), html);
  const sig = (el) => {
    if (!el.querySelector || !el.querySelector("[data-live]")) return plain(el.outerHTML);
    const copy = el.cloneNode(true);
    for (const live of copy.querySelectorAll("[data-live]")) live.textContent = "";
    return plain(copy.outerHTML);
  };
  const KEEP = (el, name) => name === "data-action-checked" || ((el.tagName === "TABLE" || el.tagName === "TH") && (name === "style" || name === "class"));
  // inside an element marked data-morph (a table of readings, for instance) a change is made in place: the same rows and cells stay, only the text or attribute that differs changes
  const morph = (a, b) => {
    for (const at of [...a.attributes]) if (!b.hasAttribute(at.name) && !KEEP(a, at.name)) a.removeAttribute(at.name);
    for (const at of [...b.attributes]) if (a.getAttribute(at.name) !== at.value && !KEEP(a, at.name)) a.setAttribute(at.name, at.value);
    const old = [...a.childNodes].filter((n) => !(n.nodeType === 1 && n.classList.contains("col-grip"))), fresh = [...b.childNodes];
    fresh.forEach((nb, i) => {
      const na = old[i];
      if (!na) a.appendChild(nb);
      else if (na.nodeType === nb.nodeType && na.nodeName === nb.nodeName) {
        if (na.nodeType === 1) { if (sig(na) !== sig(nb)) morph(na, nb); } else if (na.textContent !== nb.textContent) na.textContent = nb.textContent;
      } else a.replaceChild(nb, na);
    });
    for (const extra of old.slice(fresh.length)) a.removeChild(extra);
  };
  const alike = (a, b) => a.nodeType === b.nodeType && (a.nodeType === 1 ? sig(a) === sig(b) : a.textContent === b.textContent);
  for (const node of incoming) if (node.nodeType === 1 && node.parentNode !== parent) decorate(node);
  incoming.forEach((node, i) => {
    const cur = parent.childNodes[i];
    if (cur === node) return;
    if (cur && node.parentNode !== parent && alike(cur, node)) return;      // the same picture: keep the element that is on screen
    if (cur && node.parentNode !== parent && cur.nodeType === 1 && node.nodeType === 1 && cur.nodeName === node.nodeName && cur.hasAttribute("data-morph")) return morph(cur, node);
    if (cur) parent.replaceChild(node, cur); else parent.appendChild(node);
  });
  while (parent.childNodes.length > incoming.length) parent.removeChild(parent.lastChild);
}

export function clear(el) {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

export function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  const hours = String(d.getHours()).padStart(2, "0");
  const minutes = String(d.getMinutes()).padStart(2, "0");
  return `${year}-${month}-${day} ${hours}:${minutes}`;
}

export function timeAgo(iso, now = Date.now()) {
  if (!iso) return "never";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "never";
  const diff = now - d.getTime();
  if (diff < 45000) return "just now";
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  if (minutes < 60) return `${minutes} min ago`;
  if (hours < 24) return `${hours} h ago`;
  return `${days} d ago`;
}

export function debounce(fn, ms) {
  let timer;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), ms);
  };
}

export function toast(message, kind = "info") {
  let container = document.getElementById("toasts");
  if (!container) {
    container = document.createElement("div");
    container.id = "toasts";
    document.body.appendChild(container);
  }
  const t = h("div", { class: `toast ${kind}` }, message);
  container.appendChild(t);
  setTimeout(() => {
    if (t.parentNode) {
      t.parentNode.removeChild(t);
    }
  }, 4000);
}

export function el(selector, root = document) {
  return root.querySelector(selector);
}

export const TYPE_LABELS = {
  container: "Container",
  app: "App",
  router: "Router",
  switch: "Switch",
  ap: "Access point",
  server: "Server",
  pc: "Computer",
  phone: "Phone",
  tablet: "Tablet",
  tv: "TV / media",
  speaker: "Speaker",
  console: "Game console",
  appliance: "Appliance",
  printer: "Printer",
  iot: "IoT",
  camera: "Camera",
  nas: "NAS",
  vm: "Virtual machine",
  unknown: "Unknown",
};

// The vendor of a device. Without one: a private (randomized) Wi-Fi address is explained instead of called unknown.
export function vendorText(device) {
  if (device.vendor) return device.vendor;
  if (device.mac_kind === "randomized") return "Private address";
  return device.mac ? "Unknown" : "—";
}

export function vendorTitle(device) {
  return !device.vendor && device.mac_kind === "randomized"
    ? "This device uses a private (randomized) address, so the manufacturer cannot be read from its MAC address"
    : null;
}

export function typeBadge(type) {
  return h("span", { class: `badge type-${type}` }, TYPE_LABELS[type] || type);
}

export function statusDot(online) {
  return h("span", {
    class: `dot ${online ? "on" : "off"}`,
    title: online ? "online" : "offline",
  });
}
// Domain suffix hidden in displayed names ("blueiris.home.example.com" shows as "blueiris").
// The stored name is untouched; the full name stays available as a tooltip where a name is shown.
let domainSuffix = "";

export function setDomainSuffix(value) {
  domainSuffix = String(value || "").trim().toLowerCase().replace(/^\.+|\.+$/g, "");
}

export function shortName(name) {
  if (!name || !domainSuffix) return name;
  const text = String(name);
  const tail = "." + domainSuffix;
  if (text.length > tail.length && text.toLowerCase().endsWith(tail)) return text.slice(0, -tail.length);
  return text;
}

// Who is signed in (set from /api/session). The server enforces the role; the page only hides what would be refused.
let sessionUser = null;

export function setSessionUser(user) {
  sessionUser = user || null;
  try {
    document.body.dataset.role = sessionUser ? sessionUser.role : "";
  } catch (e) {
    // no document: nothing to mark
  }
}

export function sessionInfo() {
  return sessionUser;
}

export function isAdmin() {
  return !sessionUser || sessionUser.role === "admin";
}

// On a phone a toolbar with many controls folds behind one button (the first control, usually the search box, stays;
// so does anything marked class "keep"). The button is hidden on wider screens, see css/phone.css.
export function foldToolbarOnPhone(toolbar, label = "Filters & options") {
  const toggle = h("button", { class: "btn toolbar-toggle", type: "button", "aria-expanded": "false" }, label + " ▾");
  toggle.addEventListener("click", () => {
    const open = toolbar.classList.toggle("open");
    toggle.setAttribute("aria-expanded", String(open));
    toggle.textContent = label + (open ? " ▴" : " ▾");
  });
  toolbar.classList.add("has-toggle");
  toolbar.insertBefore(toggle, toolbar.children[1] || null);
}
