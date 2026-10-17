// Speed tests: the internet (Cloudflare), iperf3 (a server inside Netlens and a client) and a test from this browser.
import { get, post, put, del, ApiError } from "../api.js";
import { h, clear, toast, timeAgo, isAdmin } from "../util.js";
import { pageHead, tabbed } from "../ui.js";
import { emptyNote, lineChart, tile } from "../charts.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const mbps = (v) => (v === null || v === undefined ? "–" : v >= 1000 ? `${(v / 1000).toFixed(2)} Gbps` : `${v >= 100 ? Math.round(v) : v.toFixed(1)} Mbps`);
const ms = (v) => (v === null || v === undefined ? "–" : `${v.toFixed(v < 10 ? 1 : 0)} ms`);
const PHASES = { starting: "Starting…", latency: "Measuring delay…", download: "Measuring download…", upload: "Measuring upload…", running: "Testing…" };

// ---------- the browser test ----------

async function pingTest(count = 12) {
  const times = [];
  for (let i = 0; i < count; i++) {
    const t0 = performance.now();
    await fetch(`api/speedtest/ping?r=${Math.random()}`, { cache: "no-store" });
    if (i) times.push(performance.now() - t0);
  }
  const sorted = [...times].sort((a, b) => a - b);
  const jitter = times.slice(1).reduce((s, t, i) => s + Math.abs(t - times[i]), 0) / Math.max(1, times.length - 1);
  return { latency: sorted[Math.floor(sorted.length / 2)], jitter };
}

// run `streams` workers for `seconds`; `counter()` is the bytes moved so far; the first 1.5 s (TCP slow start) is not counted
function timed({ seconds, startWorker, stopAll, counter, onRate }) {
  return new Promise((resolve) => {
    const start = performance.now();
    let warm = null, lastBytes = 0, lastTime = start;
    for (const worker of startWorker) worker();
    const timer = setInterval(() => {
      const now = performance.now(), total = counter();
      onRate(((total - lastBytes) * 8) / ((now - lastTime) / 1000) / 1e6);
      lastBytes = total; lastTime = now;
      if (warm === null && now - start >= 1500) warm = { bytes: total, time: now };
      if (now - start >= seconds * 1000) {
        clearInterval(timer);
        stopAll();
        resolve(warm ? ((total - warm.bytes) * 8) / ((now - warm.time) / 1000) / 1e6 : 0);
      }
    }, 300);
  });
}

function downloadTest(seconds, onRate, streams = 4) {
  const ctl = new AbortController();
  let total = 0;
  const worker = async () => {
    while (!ctl.signal.aborted) {
      try {
        const res = await fetch(`api/speedtest/down?bytes=50000000&r=${Math.random()}`, { cache: "no-store", signal: ctl.signal });
        const reader = res.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.length;
        }
      } catch (err) {
        if (ctl.signal.aborted) return;
        await sleep(250);
      }
    }
  };
  return timed({ seconds, startWorker: Array.from({ length: streams }, () => worker), stopAll: () => ctl.abort(), counter: () => total, onRate });
}

function uploadTest(seconds, onRate, streams = 3) {
  const payload = new Blob([new Uint8Array(4_000_000)]);
  const requests = new Set();
  let total = 0, stopped = false;
  const worker = async () => {
    while (!stopped) {
      await new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        let last = 0;
        requests.add(xhr);
        xhr.open("POST", "api/speedtest/up");
        xhr.upload.onprogress = (e) => { total += e.loaded - last; last = e.loaded; };
        xhr.onloadend = () => { requests.delete(xhr); resolve(); };
        xhr.send(payload);
      });
    }
  };
  return timed({ seconds, startWorker: Array.from({ length: streams }, () => worker), stopAll: () => { stopped = true; requests.forEach((x) => x.abort()); }, counter: () => total, onRate });
}

// ---------- the page ----------

function kindLabel(r) {
  const d = r.detail || {};
  if (r.kind === "internet") return "Internet";
  if (r.kind === "iperf-in") return "iperf3 from a host";
  if (r.kind === "iperf-out") return "iperf3 to a host";
  return d.label ? `Browser: ${d.label}` : "Browser";
}

export async function render(container) {
  let disposed = false, data = null, pollTimer = null, browserRunning = false;
  const admin = isAdmin();
  const page = h("div", { class: "speed-page" });
  container.append(page);

  const sections = { internet: h("div", { class: "card" }), browser: h("div", { class: "card" }), iperf: h("div", { class: "card" }), history: h("div", { class: "card" }) };
  page.append(pageHead("Speed tests", "How fast the internet connection and your own network are: a test against Cloudflare, tests between machines with iperf3, and the history."), tabbed("netlens.speed.tab", [["internet", "Internet", sections.internet], ["local", "Your network", [sections.browser, sections.iperf]], ["results", "All results", sections.history]]));

  const busy = () => !!(data && data.current);

  async function load() {
    try {
      data = await get("/api/speedtest");
    } catch (err) {
      if (!data) sections.internet.replaceChildren(h("p", { class: "error" }, err.message));
      return;
    }
    if (disposed) return;
    draw();
    if (busy()) schedulePoll();
  }

  function schedulePoll() {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(async () => {
      if (disposed) return;
      try {
        const { current } = await get("/api/speedtest/status");
        if (current) { data.current = current; drawProgress(); schedulePoll(); }
        else { data.current = null; await load(); }
      } catch (err) { schedulePoll(); }
    }, 1000);
  }

  async function start(path, body) {
    try {
      await post(path, body);
      data.current = { phase: "starting", live_mbps: null };
      draw();
      schedulePoll();
    } catch (err) {
      toast(err.message || "Could not start the test", "error");
    }
  }

  // ----- progress line shared by internet and iperf client -----
  const progress = { internet: h("div", { class: "speed-progress" }), iperf: h("div", { class: "speed-progress" }) };
  function drawProgress() {
    const c = data.current;
    for (const [key, box] of Object.entries(progress)) {
      const mine = c && (key === "internet" ? c.kind === "internet" || !c.kind : c.kind === "iperf-out");
      clear(box);
      if (c && !mine) box.append(h("span", { class: "hint" }, "Another test is running…"));
      else if (c) box.append(h("span", { class: "speed-live" }, c.live_mbps !== null && c.live_mbps !== undefined ? mbps(c.live_mbps) : ""), h("span", { class: "hint" }, ` ${PHASES[c.phase] || "Testing…"}`));
    }
  }

  // ----- internet -----
  function drawInternet() {
    const s = sections.internet, last = data.internet.last, sched = data.internet.schedule;
    clear(s);
    s.append(h("h2", {}, "Internet speed"), h("p", { class: "hint" }, "Measures delay, download and upload against Cloudflare's nearest test server. A test takes about 20 seconds and, on a fast line, downloads a few hundred megabytes."));
    s.append(last
      ? h("div", { class: "speed-tiles" }, tile(mbps(last.down_mbps), "Download"), tile(mbps(last.up_mbps), "Upload"), tile(ms(last.latency_ms), "Ping"), tile(ms(last.jitter_ms), "Jitter"))
      : emptyNote("No internet test yet."));
    if (last) s.append(h("p", { class: "hint" }, `${timeAgo(last.ts)} · ${[last.detail.server && `server ${last.detail.server}`, last.detail.isp].filter(Boolean).join(" · ")}`));
    const run = h("button", { class: "btn primary admin-only", type: "button", disabled: busy(), onclick: () => start("/api/speedtest/internet") }, "Run test now");
    s.append(h("div", { class: "speed-actions" }, admin ? run : null, progress.internet));
    const points = data.history.filter((r) => r.kind === "internet" && r.ok).slice(0, 40).reverse();
    s.append(h("h3", {}, "History"), points.length > 1
      ? lineChart(points.map((r) => ({ x: r.ts.slice(5, 10), down: r.down_mbps, up: r.up_mbps })), [{ key: "down", label: "Download (Mbps)" }, { key: "up", label: "Upload (Mbps)" }], { height: 150 })
      : emptyNote("The chart appears after two tests."));
    if (admin) {
      const on = h("input", { type: "checkbox", checked: sched.enabled });
      const every = h("select", {}, [1, 3, 6, 12, 24].map((n) => h("option", { value: n, selected: n === sched.every_hours }, n === 1 ? "every hour" : `every ${n} hours`)));
      const save = h("button", { class: "btn", type: "button", onclick: async () => {
        try { await put("/api/speedtest/schedule", { enabled: on.checked, every_hours: Number(every.value) }); toast("Saved", "success"); await load(); }
        catch (err) { toast(err.message, "error"); }
      } }, "Save");
      s.append(h("div", { class: "field speed-schedule" }, h("label", { class: "check" }, on, " Test automatically "), every, save),
        h("p", { class: "hint" }, "Automatic tests use your internet data allowance; every 6 hours is plenty."));
    }
    drawProgress();
  }

  // ----- browser -----
  function drawBrowser(result) {
    const s = sections.browser;
    clear(s);
    s.append(h("h2", {}, "Test from this device"),
      h("p", { class: "hint" }, "Measures the line between this device and Netlens: download, upload and delay, using Netlens as the other end. Open Netlens by its local address (not through a reverse proxy) to measure only your local network. Works on any device with a browser."));
    const label = h("input", { type: "text", maxlength: "60", placeholder: "Label, for example Wi-Fi in the kitchen (optional)", "aria-label": "Label for this test", class: "speed-label" });
    const live = h("div", { class: "speed-progress" });
    const out = h("div", {});
    const button = h("button", { class: "btn primary", type: "button", disabled: browserRunning }, "Start test");
    button.addEventListener("click", async () => {
      browserRunning = true; button.disabled = true; clear(out);
      const res = { down: null, up: null, latency: null, jitter: null };
      const show = (text, rate) => live.replaceChildren(h("span", { class: "speed-live" }, rate === null ? "" : mbps(rate)), h("span", { class: "hint" }, ` ${text}`));
      try {
        show("Measuring delay…", null);
        const p = await pingTest();
        res.latency = p.latency; res.jitter = p.jitter;
        res.down = await downloadTest(8, (r) => show("Measuring download…", r));
        res.up = await uploadTest(8, (r) => show("Measuring upload…", r));
        live.replaceChildren();
        out.append(h("div", { class: "speed-tiles" }, tile(mbps(res.down), "Download"), tile(mbps(res.up), "Upload"), tile(ms(res.latency), "Ping"), tile(ms(res.jitter), "Jitter")));
        try { await post("/api/speedtest/browser", { down_mbps: res.down, up_mbps: res.up, latency_ms: res.latency, jitter_ms: res.jitter, label: label.value.trim() }); load(); } catch (err) { /* the result is shown anyway */ }
      } catch (err) {
        live.replaceChildren(h("span", { class: "error" }, "The test could not be completed."));
      }
      browserRunning = false; button.disabled = false;
    });
    s.append(h("div", { class: "speed-actions" }, label, button, live), out);
  }

  // ----- iperf3 -----
  function drawIperf() {
    const s = sections.iperf, ip = data.iperf;
    clear(s);
    s.append(h("h2", {}, "iperf3"), h("p", { class: "hint" }, "iperf3 measures the raw speed between two machines. Run the server inside Netlens and test from any host, or let Netlens test against an iperf3 server elsewhere."));
    if (!ip.installed) { s.append(h("p", { class: "error" }, "iperf3 is not installed in this container, so these tests are not available. Use the official Netlens image.")); return; }

    // the server
    s.append(h("h3", {}, "Server in Netlens"));
    const badge = h("span", { class: `badge ${ip.running ? "ok" : ""}` }, ip.running ? `Listening on port ${ip.port}` : "Off");
    const port = h("input", { type: "number", min: "1", max: "65535", value: String(ip.configured_port), "aria-label": "Port", class: "speed-port", disabled: !admin });
    const toggle = h("button", { class: `btn ${ip.running ? "" : "primary"} admin-only`, type: "button", onclick: async () => {
      try { data.iperf = await put("/api/speedtest/iperf/server", { enabled: !ip.running, port: Number(port.value) }); toast(ip.running ? "iperf3 server stopped" : "iperf3 server started", "success"); load(); }
      catch (err) { toast(err.message || "Could not change the server", "error"); }
    } }, ip.running ? "Stop server" : "Start server");
    s.append(h("div", { class: "speed-actions" }, badge, admin ? h("label", {}, "Port ", port) : null, admin ? toggle : null));
    if (ip.error && !ip.running) s.append(h("p", { class: "error" }, ip.error));
    if (ip.running) {
      const addrs = ip.addresses.length ? ip.addresses : [location.hostname];
      s.append(h("p", { class: "hint" }, "On any other computer with iperf3, run one of these (add ", h("code", {}, "-R"), " to test the other direction and ", h("code", {}, "-P 4"), " for four parallel streams):"),
        h("div", { class: "speed-cmds" }, addrs.slice(0, 4).map((a) => {
          const cmd = `iperf3 -c ${a}${ip.port === 5201 ? "" : ` -p ${ip.port}`}`;
          const copy = h("button", { class: "btn", type: "button", onclick: async () => { try { await navigator.clipboard.writeText(cmd); toast("Copied", "success"); } catch (e) { toast("Select the text and copy it", "info"); } } }, "Copy");
          return h("div", { class: "speed-cmd" }, h("code", {}, cmd), copy);
        })),
        h("p", { class: "hint" }, "Anyone on your network can use this server while it is on. Switch it off when you are done."));
    }

    // the client
    if (admin) {
      s.append(h("h3", {}, "Test from Netlens to a host"), h("p", { class: "hint" }, "The other host must run ", h("code", {}, "iperf3 -s"), "."));
      const host = h("input", { type: "text", list: "speed-hosts", placeholder: "Host name or address", "aria-label": "Host", class: "speed-host" });
      const list = h("datalist", { id: "speed-hosts" });
      get("/api/devices").then((devs) => { for (const d of devs.filter((x) => x.primary_ip && x.online)) list.append(h("option", { value: d.primary_ip }, d.custom_name || d.hostname || d.primary_ip)); }).catch(() => {});
      const cport = h("input", { type: "number", min: "1", max: "65535", value: "5201", "aria-label": "Port", class: "speed-port" });
      const dir = h("select", { "aria-label": "Direction" }, h("option", { value: "both" }, "Both directions"), h("option", { value: "up" }, "Netlens sends"), h("option", { value: "down" }, "Netlens receives"));
      const secs = h("input", { type: "number", min: "3", max: "60", value: "10", "aria-label": "Seconds", class: "speed-port" });
      const streams = h("input", { type: "number", min: "1", max: "16", value: "4", "aria-label": "Parallel streams", class: "speed-port" });
      const run = h("button", { class: "btn primary", type: "button", disabled: busy(), onclick: () => {
        if (!host.value.trim()) { toast("Enter a host first", "error"); return; }
        start("/api/speedtest/iperf/run", { host: host.value.trim(), port: Number(cport.value), seconds: Number(secs.value), direction: dir.value, streams: Number(streams.value) });
      } }, "Run test");
      s.append(h("div", { class: "speed-form" }, host, list, h("label", {}, "Port ", cport), dir, h("label", {}, "Seconds ", secs), h("label", {}, "Streams ", streams), run), progress.iperf);
    }
    drawProgress();
  }

  // ----- history -----
  function drawHistory() {
    const s = sections.history;
    clear(s);
    const filter = h("select", { "aria-label": "Show" }, [["", "All tests"], ["internet", "Internet"], ["iperf-in", "iperf3 from a host"], ["iperf-out", "iperf3 to a host"], ["browser", "Browser"]].map(([v, t]) => h("option", { value: v }, t)));
    const body = h("tbody", {});
    const fill = () => {
      clear(body);
      const rows = data.history.filter((r) => !filter.value || r.kind === filter.value).slice(0, 60);
      if (!rows.length) body.append(h("tr", {}, h("td", { colspan: "6" }, "No results yet.")));
      for (const r of rows) {
        body.append(h("tr", { class: r.ok ? "" : "speed-failed" }, h("td", {}, timeAgo(r.ts)), h("td", {}, kindLabel(r)), h("td", {}, r.target || ""),
          h("td", { class: "num" }, r.ok ? mbps(r.down_mbps) : ""), h("td", { class: "num" }, r.ok ? mbps(r.up_mbps) : ""),
          h("td", {}, r.ok ? ms(r.latency_ms) : h("span", { class: "error" }, r.error || "failed"))));
      }
    };
    filter.addEventListener("change", fill);
    const clearBtn = h("button", { class: "btn danger admin-only", type: "button", onclick: async () => {
      if (clearBtn.dataset.sure !== "1") { clearBtn.dataset.sure = "1"; clearBtn.textContent = "Press again to clear all results"; return; }
      try { await del("/api/speedtest/history"); await load(); } catch (err) { toast(err.message, "error"); }
    } }, "Clear history");
    s.append(h("div", { class: "toolbar" }, h("h2", {}, "Results"), filter, admin ? clearBtn : null),
      h("div", { class: "table-wrap" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["When", "Test", "Target", "Download", "Upload", "Ping"].map((t) => h("th", {}, t)))), body)),
      h("p", { class: "hint" }, "Download and upload are seen from the device that tests; for iperf3 from a host, upload means that host sent data to Netlens."));
    fill();
  }

  function draw() { drawInternet(); drawIperf(); drawHistory(); if (!browserRunning && !sections.browser.firstChild) drawBrowser(); }

  sections.internet.append(h("p", { class: "hint" }, "Loading…"));
  await load();
  if (!browserRunning && !sections.browser.firstChild) drawBrowser();
  return () => { disposed = true; clearTimeout(pollTimer); };
}
