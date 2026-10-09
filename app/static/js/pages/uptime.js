import { get } from "../api.js";
import { h, clear, toast, statusDot, shortName } from "../util.js";
import { heartbeatBar, uptimeText, uptimeClass } from "../heartbeat.js";

export async function render(container, params) {
  let disposed = false;
  let inFlight = false;
  let timer = null;
  let filterText = "";
  let tableBody = null;
  let filterInput = null;

  function applyFilter() {
    if (!tableBody) return;
    const q = filterText.toLowerCase();
    for (const row of tableBody.children) {
      if (row.dataset && row.dataset.search) {
        row.style.display = q && !row.dataset.search.includes(q) ? "none" : "";
      }
    }
  }

  function buildRow(item) {
    const tr = h("tr", {
      dataset: {
        search: `${(item.name || "").toLowerCase()} ${(item.ip || "").toLowerCase()}`,
      },
    });

    const tdStatus = h("td", {}, statusDot(item.online));
    tr.appendChild(tdStatus);

    const tdDevice = h("td", {});
    tdDevice.appendChild(h("a", { href: `#/device/${item.id}`, title: item.name || null }, shortName(item.name) || ""));
    if (item.ip && item.ip !== item.name) {
      tdDevice.appendChild(h("div", { class: "mono hint" }, item.ip));
    }
    tr.appendChild(tdDevice);

    tr.appendChild(h("td", {}, heartbeatBar(item.bars || [], 60)));
    tr.appendChild(h("td", {}, h("span", { class: uptimeClass(item.up_24h) }, uptimeText(item.up_24h))));
    tr.appendChild(h("td", {}, h("span", { class: uptimeClass(item.up_7d) }, uptimeText(item.up_7d))));

    return tr;
  }

  function buildBody(items) {
    const body = h("tbody", {});
    if (!items || items.length === 0) {
      const tr = h("tr", {});
      tr.appendChild(h("td", { colspan: "5" }, "No devices yet. Run a scan first."));
      body.appendChild(tr);
    } else {
      for (const item of items) {
        body.appendChild(buildRow(item));
      }
    }
    return body;
  }

  async function load() {
    if (disposed || inFlight) return;
    inFlight = true;
    try {
      const data = await get("/api/uptime?bars=60");
      if (disposed) return;
      const newBody = buildBody(data);
      if (tableBody) {
        tableBody.replaceWith(newBody);
      }
      tableBody = newBody;
      applyFilter();
    } catch (err) {
      if (!disposed) {
        toast("Failed to load uptime", "error");
      }
    } finally {
      inFlight = false;
    }
  }

  clear(container);
  container.appendChild(h("h1", {}, "Uptime"));
  container.appendChild(h("p", { class: "hint" },
    "Every scan records whether each device answered. Green = up, red = down. " +
    "The bars show the most recent scans, newest on the right."));

  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Uptime"));

  filterInput = h("input", {
    type: "text",
    placeholder: "Filter by name or IP",
    value: filterText,
    oninput: (e) => {
      filterText = e.target.value;
      applyFilter();
    },
  });
  card.appendChild(filterInput);

  const table = h("table", { class: "data" });
  const thead = h("thead", {});
  const headRow = h("tr", {});
  headRow.appendChild(h("th", {}, "Status"));
  headRow.appendChild(h("th", {}, "Device"));
  headRow.appendChild(h("th", {}, "Last 60 scans"));
  headRow.appendChild(h("th", {}, "24 h"));
  headRow.appendChild(h("th", {}, "7 days"));
  thead.appendChild(headRow);
  table.appendChild(thead);

  tableBody = h("tbody", {});
  tableBody.appendChild(h("tr", {}, h("td", { colspan: "5" }, "Loading...")));
  table.appendChild(tableBody);
  card.appendChild(table);
  container.appendChild(card);

  load();
  timer = setInterval(load, 30000);

  return function cleanup() {
    disposed = true;
    if (timer) clearInterval(timer);
  };
}