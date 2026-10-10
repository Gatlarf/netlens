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
