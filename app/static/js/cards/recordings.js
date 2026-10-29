import { get, del } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";
import { loadXterm } from "../terminal.js";

// Settings -> Session recordings: what the host sent to the screen during web-terminal sessions (what is typed is not recorded). Watching or downloading is an audit line.
export async function buildRecordingsCard() {
  const card = h("div", { class: "card admin-only" });
  let data = await get("/api/recordings");
  let player = null;

  async function play(rec) {
    if (player) player.dispose();
    let full;
    try { full = await get(`/api/recordings/${rec.id}`); } catch (err) { toast(err.message || "Could not open it", "error"); return; }
    await loadXterm();
    const box = h("div", { class: "terminal-wrap", style: "height:26rem" });
    const status = h("p", { class: full.verified ? "hint" : "error" }, full.verified ? "Verified: every piece is authentic and the file matches the hash in the audit log." : `NOT VERIFIED: ${full.problem}`);
    const speed = h("select", { "aria-label": "Speed" }, [["1", "real time"], ["4", "4× faster"], ["20", "20× faster"]].map(([v, t]) => h("option", { value: v }, t)));
    const view = h("div", {}, h("h3", {}, `Session #${full.id}: ${full.user} on ${full.device}`), status, box, h("div", { class: "btn-row" }, speed, h("button", { class: "btn", type: "button", onclick: () => run() }, "Play again")));
    card.querySelector(".player-slot").replaceChildren(view);
    const term = new Terminal({ convertEol: false, rows: 30, cols: 120, disableStdin: true, scrollback: 5000 });
    term.open(box);
    player = term;
    let timers = [];
    function run() {
      timers.forEach(clearTimeout); timers = []; term.reset();
      const factor = Number(speed.value) || 1;
      for (const [t, kind, text] of full.frames) timers.push(setTimeout(() => term.write(kind === "x" ? `\r\n\x1b[33m${text}\x1b[0m\r\n` : text), Math.min(t * 1000 / factor, 600000)));
    }
    run();
  }

  // the recording as an asciinema (.cast) file, made here from the verified pieces so that a confirmation prompt (step-up) works like everywhere else
  async function save(rec) {
    try {
      const full = await get(`/api/recordings/${rec.id}`);
      const lines = [JSON.stringify({ version: 2, width: 120, height: 30, title: `${full.user} on ${full.device}` }), ...full.frames.filter((f) => f[1] === "o").map((f) => JSON.stringify([f[0], "o", f[2]]))];
      const a = h("a", { href: URL.createObjectURL(new Blob([lines.join("\n") + "\n"], { type: "text/plain" })), download: `netlens-session-${rec.id}.cast` });
      document.body.appendChild(a); a.click(); a.remove();
    } catch (err) { toast(err.message || "Could not download it", "error"); }
  }

  function draw() {
    clear(card);
    card.appendChild(h("h2", {}, "Session recordings"));
    card.appendChild(h("p", { class: "hint" }, data.enabled ? `Web-terminal sessions are recorded and kept ${data.days} days. What the host sends to the screen is kept, encrypted; what is typed is not (it would hold passwords).` : "Recording is off. Switch it on under Sign-in security (Enterprise). When it is on, every web-terminal session is recorded: what the host shows, encrypted, with its timing."));
    const rows = data.recordings.map((r) => h("tr", {}, h("td", {}, `#${r.id}`), h("td", {}, r.user), h("td", {}, r.device), h("td", {}, fmtTime(r.started)), h("td", { class: "hint" }, `${r.bytes} bytes${r.truncated ? " (cut)" : ""}${r.status !== "done" ? ` · ${r.status}` : ""}`),
      h("td", {}, h("div", { class: "row-actions" }, h("button", { class: "btn", type: "button", onclick: () => play(r) }, "Watch"), h("button", { class: "btn", type: "button", onclick: () => save(r) }, "Download"),
        h("button", { class: "btn danger", type: "button", onclick: async () => { if (!window.confirm(`Delete the recording #${r.id}?`)) return; try { await del(`/api/recordings/${r.id}`); data = await get("/api/recordings"); draw(); } catch (err) { toast(err.message || "Failed", "error"); } } }, "Delete")))));
    card.appendChild(rows.length ? h("div", { class: "table-wrap" }, h("table", { class: "data" }, h("thead", {}, h("tr", {}, ["Session", "Who", "Host", "Started", "Output", ""].map((t) => h("th", {}, t)))), h("tbody", {}, rows))) : h("p", { class: "hint" }, "No recordings."));
    card.appendChild(h("div", { class: "player-slot" }));
  }
  draw();
  return card;
}
