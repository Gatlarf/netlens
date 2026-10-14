// Getting-started guide: a short walk through the things a new install needs, one plain question at a time.
// The steps live in wizard_steps.js. Every step has the recommended answer filled in and can be skipped; moving on
// saves the step. Progress is kept on the server (GET/PUT /api/wizard), so closing it halfway loses nothing.
import { get, put } from "../api.js";
import { h, clear, isAdmin } from "../util.js";
import { STEPS } from "../wizard_steps.js";

export async function render(container) {
  if (!isAdmin()) {
    container.append(h("div", { class: "card" }, h("p", {}, "Only an administrator can use the setup guide.")));
    return;
  }
  let state = { status: "new", step: 0 };
  try { state = await get("/api/wizard"); } catch (err) { /* open at the first step */ }
  let step = Math.min(Math.max(state.step || 0, 0), STEPS.length - 1);
  let disposed = false;
  const body = h("div", { class: "wiz-body" });
  const nav = h("div", { class: "wiz-nav" });
  const dots = h("ol", { class: "wiz-dots", "aria-label": "Steps" });
  const title = h("h1", {});
  const intro = h("p", { class: "hint" });
  container.append(h("div", { class: "wiz" }, h("div", { class: "wiz-head" }, title, intro, dots), body, nav));

  let status = state.status;
  let current = null; // { el, commit } of the step on screen
  const error = h("p", { class: "error", role: "alert" });
  const save = (next) => { status = next; return put("/api/wizard", { status, step }).catch(() => {}); };

  // leave the step on screen: saves what was filled in; a message from the step keeps the user here
  async function leave() {
    error.textContent = "";
    if (!current || !current.commit) return true;
    try {
      await current.commit();
      return true;
    } catch (err) {
      error.textContent = err.message || "That could not be saved.";
      error.scrollIntoView({ block: "center" });
      return false;
    }
  }

  async function go(n) {
    if (n !== step && !(await leave())) return;
    await show(n);
  }

  async function show(n) {
    step = n;
    current = null;
    save(step === STEPS.length - 1 || status === "done" ? "done" : "pending");
    const s = STEPS[step];
    title.textContent = s.title;
    intro.textContent = `Step ${step + 1} of ${STEPS.length}. ${s.intro}`;
    clear(dots);
    STEPS.forEach((t, i) => dots.append(h("li", { class: i === step ? "now" : i < step ? "past" : "" },
      h("button", { type: "button", title: t.title, "aria-current": i === step ? "step" : null, onclick: () => go(i) }, String(i + 1)))));
    clear(body);
    clear(nav);
    error.textContent = "";
    body.append(h("p", { class: "hint" }, "Loading\u2026"));
    try {
      const built = await s.build();
      if (disposed || step !== n) return;
      current = built;
      clear(body);
      body.append(built.el);
      if (s.more && s.more.length) {
        body.append(h("p", { class: "hint wiz-more" }, "More options in Settings: ",
          ...s.more.flatMap(([href, label], i) => [i ? " \u00b7 " : "", h("a", { href }, label)])));
      }
    } catch (err) {
      if (disposed || step !== n) return;
      clear(body);
      body.append(h("div", { class: "card" }, h("p", { class: "error" }, err.message || "Could not load this step"),
        s.more && s.more.length ? h("p", {}, h("a", { href: s.more[0][0] }, `Open ${s.more[0][1]} in Settings`)) : null));
    }
    if (disposed || step !== n) return;
    const last = step === STEPS.length - 1;
    nav.append(
      step > 0 ? h("button", { class: "btn", type: "button", onclick: () => go(step - 1) }, "Back") : h("span", {}),
      h("span", { class: "wiz-nav-end" },
        last ? null : h("button", { class: "btn", type: "button", onclick: async () => { await save(status === "done" ? "done" : "dismissed"); location.hash = "#/dashboard"; } }, "Close for now"),
        h("button", { class: "btn primary", type: "button", onclick: async (e) => {
          e.target.disabled = true;
          if (last) { await save("done"); location.hash = "#/dashboard"; } else await go(step + 1);
          e.target.disabled = false;
        } }, last ? "Open the dashboard" : step === 0 ? "Start" : "Next")));
    window.scrollTo(0, 0);
  }

  body.after(error);
  await show(step);
  return () => { disposed = true; };
}
