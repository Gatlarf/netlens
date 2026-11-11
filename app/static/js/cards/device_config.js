import { get, post, put, del } from "../api.js";
import { h, fmtTime, clear } from "../util.js";
import { formDialog } from "../formdialog.js";

// The settings of a router, firewall or controller as its plugin reports them: recommendations from Netlens' rules (accept with a reason), an optional review by the
// language model, and what changed. Returns null when no plugin reports settings for this device (or the viewer is not an administrator).
export async function buildDeviceConfigCard(device) {
  const data = await get(`/api/devices/${device.id}/config?limit=30`).catch(() => null);
  if (!data || !data.plugin) return null;
  const card = h("div", { class: "card device-config-card" });
  card.appendChild(h("h2", {}, "Configuration"));
  card.appendChild(h("p", { class: "hint", title: `Read by the ${data.plugin} plugin. Netlens never writes to the device.` }, `${data.items} settings, last read ${fmtTime(data.updated)}.`));
  const advice = h("div", { class: "config-advice" });
  card.appendChild(advice);
  const history = h("div", {});
  card.appendChild(history);

  async function loadAdvice() {
    const a = await get(`/api/devices/${device.id}/config/advice`).catch(() => null);
    clear(advice);
    if (!a || !a.plugin) return;
    if (a.rules) {
      advice.appendChild(h("h3", {}, "Recommendations"));
      if (!a.findings.length) advice.appendChild(h("p", { class: "hint" }, `Nothing to recommend (${a.checked} checks).`));
      for (const f of a.findings) advice.appendChild(findingRow(f, false));
      if (a.accepted.length) {
        const det = h("details", { class: "config-accepted" }, h("summary", {}, `${a.accepted.length} accepted`));
        for (const f of a.accepted) det.appendChild(findingRow(f, true));
        advice.appendChild(det);
      }
    }
    advice.appendChild(reviewBlock(a));
  }

  function findingRow(f, isAccepted) {
    const row = h("div", { class: `exposure-item st-${f.status === "risk" ? "risk" : "warn"}` });
    row.appendChild(h("p", {}, h("strong", {}, f.title), f.accepted ? ` · accepted by ${f.accepted.who}: ${f.accepted.reason}` : ""));
    row.appendChild(h("p", { class: "hint" }, f.evidence));
    if (f.steps.length) row.appendChild(h("details", {}, h("summary", {}, `How to fix · ${f.steps.length} step${f.steps.length === 1 ? "" : "s"}`), h("ol", {}, ...f.steps.map((s) => h("li", {}, s)))));
    const btn = h("button", { class: "btn", type: "button", title: isAccepted ? "Show it as a recommendation again" : "This is intended: keep it out of the problem list" }, isAccepted ? "Undo" : "Accept…");
    btn.addEventListener("click", async () => {
      if (isAccepted) await del(`/api/devices/${device.id}/config/advice/${encodeURIComponent(f.id)}`);
      else {
        const v = await formDialog({ title: "Accept this recommendation", fields: [{ key: "reason", label: "Why is this intended?", type: "textarea", required: true }], ok: "Accept" });
        if (!v || !v.reason.trim()) return;
        await put(`/api/devices/${device.id}/config/advice/${encodeURIComponent(f.id)}`, { reason: v.reason });
      }
      await loadAdvice();
    });
    row.appendChild(btn);
    return row;
  }

  function reviewBlock(a) {
    const box = h("div", { class: "config-review" });
    box.appendChild(h("h3", {}, "Second opinion"));
    const out = h("div", {});
    function show(r) {
      clear(out);
      if (!r) return;
      if (!r.items.length) out.appendChild(h("p", { class: "hint" }, "The AI found nothing more."));
      for (const x of r.items) out.appendChild(h("div", { class: `exposure-item st-${x.severity === "high" ? "risk" : "warn"}` }, h("p", {}, h("strong", {}, x.title), h("span", { class: "mono" }, `  ${x.key}`)), h("p", { class: "hint" }, `${x.why} ${x.fix}`)));
      out.appendChild(h("p", { class: "hint" }, `Written by the AI on ${fmtTime(r.ts)}${r.outdated ? "; the settings changed since" : ""}. Advice only.`));
    }
    show(a.review);
    const btn = h("button", { class: "btn", type: "button", disabled: !a.review_available, title: a.review_available ? "Send the settings (addresses anonymised) to the language model for a second opinion" : "Needs the digital engineer (Settings → AI) and Insights" },
      a.review ? "Review again" : "Review with AI");
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        show(await post(`/api/devices/${device.id}/config/review?force=${a.review ? "true" : "false"}`, {}));
      } catch (err) {
        clear(out);
        out.appendChild(h("p", { class: "error" }, err.message || "The review failed"));
      }
      btn.disabled = false;
    });
    box.append(btn, out);
    return box;
  }

  await loadAdvice();
  if (!data.changes.length) {
    history.appendChild(h("p", { class: "hint" }, "No change since Netlens started recording."));
    return card;
  }
  history.appendChild(h("h3", {}, "Changes"));
  for (const c of data.changes) {
    const rows = [
      ...c.changed.map((x) => h("li", {}, h("span", { class: "mono" }, x.key), `: ${x.before || "(empty)"} → ${x.after || "(empty)"}`)),
      ...c.added.map((x) => h("li", {}, "Added ", h("span", { class: "mono" }, x.key), `: ${x.value || "(empty)"}`)),
      ...c.removed.map((x) => h("li", {}, "Removed ", h("span", { class: "mono" }, x.key), `: ${x.value || "(empty)"}`)),
    ];
    history.appendChild(h("div", { class: "config-change" }, h("p", {}, h("strong", {}, fmtTime(c.ts)), ` ${c.changed.length} changed, ${c.added.length} added, ${c.removed.length} removed`), h("ul", {}, ...rows)));
  }
  return card;
}
