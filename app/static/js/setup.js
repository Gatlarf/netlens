// First-run wizard: the first administrator and the networks to scan. Shown only while the server says
// setup is required (no user yet and no NETLENS_TOKEN). Two short steps, nothing is saved until the end.
import { get, post } from "./api.js";
import { h, clear } from "./util.js";

const MIN_USER_LENGTH = 1;

function stepDots(step) {
  return h("p", { class: "setup-steps", "aria-label": `Step ${step} of 2` }, step === 1 ? "Step 1 of 2: your account" : "Step 2 of 2: your network");
}

export async function renderSetup(container, onDone) {
  clear(container);
  let info = { detected_ranges: [], min_password: 8 };
  try {
    info = await get("/api/setup");
  } catch (err) {
    location.reload(); // setup was completed meanwhile (404): show the normal login
    return;
  }
  const state = { username: "admin", password: "", ranges: info.detected_ranges.join(", "), start_scan: true };
  const card = h("div", { class: "card setup-card", id: "setup-card" });
  container.appendChild(h("div", { class: "setup-wrap" }, card));

  function accountStep(error = "") {
    clear(card);
    const user = h("input", { type: "text", name: "username", value: state.username, autocomplete: "username", required: true, maxlength: "32" });
    const pw = h("input", { type: "password", name: "password", autocomplete: "new-password", required: true });
    const pw2 = h("input", { type: "password", name: "password2", autocomplete: "new-password", required: true });
    const errorEl = h("p", { class: "error", id: "setup-error" }, error);
    const form = h("form", { class: "edit-form", id: "setup-account" },
      h("div", { class: "field" }, h("label", {}, "User name"), user),
      h("div", { class: "field" }, h("label", {}, `Password (at least ${info.min_password} characters)`), pw),
      h("div", { class: "field" }, h("label", {}, "Repeat the password"), pw2),
      errorEl,
      h("button", { type: "submit", class: "btn primary" }, "Next"));
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      if (user.value.trim().length < MIN_USER_LENGTH) return void (errorEl.textContent = "Enter a user name.");
      if (pw.value.length < info.min_password) return void (errorEl.textContent = `The password needs at least ${info.min_password} characters.`);
      if (pw.value !== pw2.value) return void (errorEl.textContent = "The two passwords are not the same.");
      state.username = user.value.trim();
      state.password = pw.value;
      networkStep();
    });
    card.append(
      h("h1", {}, "Welcome to Netlens"),
      stepDots(1),
      h("p", {}, "Netlens scans your network and shows what is on it. First, create the administrator account you will sign in with."),
      form);
    user.focus();
  }

  function networkStep(error = "") {
    clear(card);
    const ranges = h("input", { type: "text", name: "ranges", value: state.ranges, placeholder: "192.168.1.0/24", autocomplete: "off" });
    const scan = h("input", { type: "checkbox", name: "start_scan" });
    scan.checked = state.start_scan;
    const errorEl = h("p", { class: "error", id: "setup-error" }, error);
    const back = h("button", { type: "button", class: "btn" }, "Back");
    const finish = h("button", { type: "submit", class: "btn primary" }, "Finish and open Netlens");
    const form = h("form", { class: "edit-form", id: "setup-network" },
      h("div", { class: "field" }, h("label", {}, "Networks to scan"), ranges,
        h("p", { class: "hint" }, info.detected_ranges.length
          ? "These are the networks this device is connected to. Remove the ones you do not want scanned, or add others, separated by commas."
          : "Netlens could not detect your network. Enter it, for example 192.168.1.0/24. Leave it empty to try again automatically at every scan.")),
      h("div", { class: "field" }, h("label", { class: "check" }, scan, " Start the first scan right away")),
      errorEl, back, " ", finish);
    back.addEventListener("click", () => {
      state.ranges = ranges.value;
      state.start_scan = scan.checked;
      accountStep();
    });
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      state.ranges = ranges.value;
      state.start_scan = scan.checked;
      finish.disabled = true;
      try {
        await post("/api/setup", {
          username: state.username,
          password: state.password,
          ranges: state.ranges.split(",").map((r) => r.trim()).filter(Boolean),
          start_scan: state.start_scan,
        });
        await onDone();
      } catch (err) {
        if (err.status === 409) return location.reload();
        finish.disabled = false;
        errorEl.textContent = err.message || "Setup failed";
        if (/user name|password/i.test(err.message || "")) accountStep(err.message);
      }
    });
    card.append(
      h("h1", {}, "Your network"),
      stepDots(2),
      form);
  }

  accountStep();
}
