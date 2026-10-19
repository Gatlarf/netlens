import { get, put } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

function multi(options, chosen) {
  return h("select", { multiple: true, size: String(Math.min(4, Math.max(2, options.length))) }, ...options.map((o) => h("option", { value: o.id, selected: chosen.includes(o.id) }, o.name)));
}
const picked = (select) => [...select.selectedOptions].map((o) => o.value);

// Settings page: who is on call, by day and hour. Escalation can tell "whoever is on call" (see app/oncall.py).
export async function buildOncallCard() {
  const card = h("div", { class: "card", id: "oncall-card" });
  function draw(info) {
    clear(card);
    const p = info.policy;
    card.appendChild(h("h2", {}, "On-call schedule"));
    card.appendChild(h("p", { class: "hint" },
      "Decide who is notified, by day and hour. Add the people (each with the alert channels that reach them), the shifts (days, hours, and who shares them, taking turns weekly or daily if you like), overrides for swaps and holidays, and a fallback for the hours no shift covers. Then choose **Whoever is on call** in a level of the escalation policy: the alert goes to the channels of the people on call at that moment. Part of every licence and the free trial."));
    if (!info.allowed) card.appendChild(h("p", { class: "warn-text" }, "Needs a licence or the free trial (Settings → Licence)."));

    const enabled = h("input", { type: "checkbox" });
    enabled.checked = p.enabled;
    const tz = h("input", { type: "text", value: p.tz === "UTC" && !p.people.length ? Intl.DateTimeFormat().resolvedOptions().timeZone : p.tz, style: "width:16em", placeholder: "Europe/Brussels" });
    const now = info.now;
    const nowText = !p.enabled ? "The schedule is off." : now.people.length ? `On call now: ${now.people.map((x) => x.name).join(", ")}${now.until ? `, until ${fmtTime(now.until)}` : ""}${now.source && now.source !== "fallback" ? ` (${now.source})` : now.source === "fallback" ? " (fallback)" : ""}.` : "Nobody is on call now.";

    // people
    const people = [];
    const peopleBox = h("div", {});
    const addPerson = (person) => {
      const name = h("input", { type: "text", value: person.name, placeholder: "Name", style: "width:12em" });
      const chans = multi(info.channels, person.channels);
      const row = h("div", { class: "field oncall-row" }, name, h("label", {}, "Reached through"), chans);
      const rm = h("button", { class: "btn danger", type: "button" }, "Remove");
      const entry = { id: person.id || `p${Math.random().toString(36).slice(2, 8)}`, name, chans, row };
      rm.addEventListener("click", () => { people.splice(people.indexOf(entry), 1); row.remove(); refreshPeople(); });
      row.appendChild(rm);
      people.push(entry);
      peopleBox.appendChild(row);
    };
    const idOf = (e) => e.id;
    const peopleOptions = () => people.map((e) => ({ id: idOf(e), name: e.name.value.trim() || "(unnamed)" }));
    const refreshers = [];
    const refreshPeople = () => refreshers.forEach((f) => f());
    p.people.forEach(addPerson);
    const addPersonBtn = h("button", { class: "btn", type: "button" }, "Add a person");
    addPersonBtn.addEventListener("click", () => { addPerson({ id: "", name: "", channels: [] }); refreshPeople(); });

    // shifts
    const shifts = [];
    const shiftsBox = h("div", {});
    const addShift = (s) => {
      const name = h("input", { type: "text", value: s.name, style: "width:10em" });
      const days = DAYS.map((d, i) => h("label", { class: "check-row" }, h("input", { type: "checkbox", checked: s.days.includes(i), "data-day": i }), ` ${d}`));
      const start = h("input", { type: "time", value: s.start });
      const end = h("input", { type: "time", value: s.end });
      const rotate = h("select", {}, [["none", "Everyone chosen is on call"], ["weekly", "Take turns every week"], ["daily", "Take turns every day"]].map(([v, l]) => h("option", { value: v, selected: v === s.rotate }, l)));
      const who = h("div", {});
      const entry = { name, days, start, end, rotate, who, sel: null, chosen: s.people.slice() };
      const draw = () => { const keep = entry.sel ? picked(entry.sel) : entry.chosen; clear(who); entry.sel = multi(peopleOptions(), keep); who.appendChild(entry.sel); };
      refreshers.push(draw);
      draw();
      const rm = h("button", { class: "btn danger", type: "button" }, "Remove");
      const row = h("div", { class: "oncall-shift" }, h("div", { class: "field" }, name), h("div", { class: "event-boxes" }, days),
        h("div", { class: "field" }, h("label", {}, "From ", start, " until ", end, " (an end before the start runs past midnight)")),
        h("div", { class: "field" }, h("label", {}, "Who"), who), h("div", { class: "field" }, rotate), rm);
      rm.addEventListener("click", () => { shifts.splice(shifts.indexOf(entry), 1); refreshers.splice(refreshers.indexOf(draw), 1); row.remove(); });
      shifts.push(entry);
      shiftsBox.appendChild(row);
    };
    p.shifts.forEach(addShift);
    const addShiftBtn = h("button", { class: "btn", type: "button" }, "Add a shift");
    addShiftBtn.addEventListener("click", () => addShift({ name: `Shift ${shifts.length + 1}`, days: [0, 1, 2, 3, 4], start: "08:00", end: "18:00", people: [], rotate: "none" }));

    // overrides
    const overrides = [];
    const overridesBox = h("div", {});
    const addOverride = (o) => {
      const who = h("select", {});
      const from = h("input", { type: "datetime-local", value: o.from });
      const to = h("input", { type: "datetime-local", value: o.to });
      const note = h("input", { type: "text", value: o.note || "", placeholder: "Swap, holiday ...", style: "width:12em" });
      const entry = { who, from, to, note, chosen: o.person };
      const draw = () => { const keep = who.value || entry.chosen; clear(who); for (const x of peopleOptions()) who.appendChild(h("option", { value: x.id, selected: x.id === keep }, x.name)); };
      refreshers.push(draw);
      draw();
      const rm = h("button", { class: "btn danger", type: "button" }, "Remove");
      const row = h("div", { class: "field oncall-row" }, who, h("label", {}, "from"), from, h("label", {}, "until"), to, note, rm);
      rm.addEventListener("click", () => { overrides.splice(overrides.indexOf(entry), 1); refreshers.splice(refreshers.indexOf(draw), 1); row.remove(); });
      overrides.push(entry);
      overridesBox.appendChild(row);
    };
    p.overrides.forEach(addOverride);
    const addOverrideBtn = h("button", { class: "btn", type: "button" }, "Add an override");
    addOverrideBtn.addEventListener("click", () => addOverride({ person: "", from: "", to: "", note: "" }));

    const fallback = h("div", {});
    let fallbackSel = null;
    const drawFallback = () => { const keep = fallbackSel ? picked(fallbackSel) : p.fallback; clear(fallback); fallbackSel = multi(peopleOptions(), keep); fallback.appendChild(fallbackSel); };
    refreshers.push(drawFallback);
    drawFallback();

    const save = h("button", { class: "btn primary", type: "button" }, "Save");
    save.addEventListener("click", async () => {
      save.disabled = true;
      try {
        const body = {
          enabled: enabled.checked, tz: tz.value.trim() || "UTC",
          people: people.map((e) => ({ id: idOf(e), name: e.name.value.trim(), channels: picked(e.chans) })),
          shifts: shifts.map((s) => ({ name: s.name.value.trim(), days: s.days.map((l) => l.firstChild).filter((i) => i.checked).map((i) => Number(i.dataset.day)), start: s.start.value, end: s.end.value, people: picked(s.sel), rotate: s.rotate.value })),
          overrides: overrides.map((o) => ({ person: o.who.value, from: o.from.value, to: o.to.value, note: o.note.value.trim() })),
          fallback: fallbackSel ? picked(fallbackSel) : [],
        };
        draw(await put("/api/oncall", body));
        toast("Saved", "success");
      } catch (err) { toast(err.message || "Could not save", "error"); save.disabled = false; }
    });

    const upcoming = h("div", {});
    for (const u of info.upcoming.slice(0, 14)) {
      upcoming.appendChild(h("div", { class: "kv" }, h("span", { class: "kv-label" }, `${u.from.replace("T", " ")} → ${u.to.replace("T", " ")}`), h("span", {}, `${u.name}: ${u.people.join(", ") || "nobody"}`, u.kind === "override" ? h("span", { class: "tag" }, "override") : null)));
    }
    card.append(
      h("label", { class: "check" }, enabled, " Use the on-call schedule"),
      h("p", { class: "hint" }, nowText),
      h("div", { class: "field" }, h("label", {}, "Time zone"), tz, h("p", { class: "hint" }, "All shift times are local time in this zone.")),
      h("h3", {}, "People"), peopleBox, addPersonBtn,
      h("h3", {}, "Shifts"), shiftsBox, addShiftBtn,
      h("h3", {}, "Overrides"), overridesBox, addOverrideBtn,
      h("h3", {}, "Fallback"), h("p", { class: "hint" }, "Told when no shift covers the moment."), fallback,
      h("div", { class: "form-actions" }, save),
      h("h3", {}, "Coming up"), info.upcoming.length ? upcoming : h("p", { class: "hint" }, "No shifts in the next seven days."));
  }
  draw(await get("/api/oncall"));
  return card;
}
