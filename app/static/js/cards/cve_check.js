// The version-based CVE check: switch, minimum severity, optional NVD key, run now, and what the last run did.
import { get, put, post } from "../api.js";
import { h, toast, timeAgo } from "../util.js";

const SEVERITIES = [["critical", "Critical only"], ["high", "High and critical"], ["medium", "Medium and above"], ["low", "Everything, also low"]];

export function buildCveCheckCard(onChange = () => {}) {
  const card = h("div", { class: "card cve-check" });
  let state = null;
  let timer = null;

  const status = () => {
    const last = state.last;
    if (!state.enabled) return h("p", { class: "hint" }, "Off. Nothing is looked up.");
    if (state.running) return h("p", { class: "hint" }, "Checking now… this can take several minutes without an NVD key.");
    if (!last) return h("p", { class: "hint" }, state.waiting_for_scan ? "Waiting for the next deep scan: the scan has to record what each service is first." : "Waiting for the first run.");
    const parts = [`Last run ${timeAgo(last.at)}: ${last.versions} service version${last.versions === 1 ? "" : "s"} on ${last.services} port${last.services === 1 ? "" : "s"}, ${last.findings} finding${last.findings === 1 ? "" : "s"}.`];
    if (last.left) parts.push(`${last.left} more to look up at the next run.`);
    if (last.vague_cves_ignored) parts.push(`${last.vague_cves_ignored} CVE${last.vague_cves_ignored === 1 ? "" : "s"} that only say "all versions" were left out.`);
    return h("p", { class: last.ok ? "hint" : "error" }, last.ok ? parts.join(" ") : `${last.error} ${parts.join(" ")}`);
  };

  const draw = () => {
    const enabled = h("input", { type: "checkbox", id: "cve-enabled", checked: state.enabled });
    const severity = h("select", { id: "cve-sev" }, SEVERITIES.map(([k, v]) => h("option", { value: k, selected: k === state.min_severity }, v)));
    const key = h("input", { type: "password", id: "cve-key", placeholder: state.has_api_key ? "key saved (type to replace)" : "optional NVD API key", autocomplete: "off" });
    const save = async () => {
      try {
        state = await put("/api/cve-check", { enabled: enabled.checked, min_severity: severity.value, api_key: key.value || undefined });
        toast("Saved");
        schedule();
        draw();
        onChange();
      } catch (err) {
        toast(err.message || "Could not save", "error");
      }
    };
    card.replaceChildren(
      h("h2", {}, "Check versions against the CVE list"),
      h("p", { class: "hint" }, "A light first look, no scan: Netlens takes the product and version of every service its deep scans found and asks the public NVD which known vulnerabilities (CVE) affect that version. Nothing is sent to your devices, and only the product name and version leave this machine. It sees only what a version number can tell: a distribution (Debian, Ubuntu, Red Hat) often fixes a hole without changing the number, so treat each finding as \"check this\", and a service that hides its version is not checked. For a real scan connect Greenbone or another scanner from the Plugin store."),
      h("div", { class: "form-row" }, h("label", { for: "cve-enabled" }, enabled, " Check the services found by the deep scans")),
      h("div", { class: "form-row" }, h("label", { for: "cve-sev" }, "Report "), severity),
      h("div", { class: "form-row" }, h("label", { for: "cve-key" }, "NVD API key "), key,
        h("span", { class: "hint" }, " Free from nvd.nist.gov; without it the NVD allows about 5 questions per 30 seconds, so the first run is slow. Results are kept for a week.")),
      h("div", { class: "form-row" },
        h("button", { class: "btn primary", type: "button", onclick: save }, "Save"),
        state.enabled ? h("button", { class: "btn", type: "button", disabled: state.running, onclick: async () => {
          try { state = await post("/api/cve-check/run"); draw(); schedule(); } catch (err) { toast(err.message || "Could not start", "error"); }
        } }, "Check now") : null),
      status());
  };

  const schedule = () => {
    clearTimeout(timer);
    if (state && state.running) timer = setTimeout(refresh, 5000);
  };

  async function refresh() {
    try {
      const before = state && state.running;
      state = await get("/api/cve-check");
      if (card.isConnected || !timer) draw();
      if (before && !state.running) onChange();
      schedule();
    } catch (err) {
      card.replaceChildren(h("p", { class: "error" }, err.message || "Could not load the CVE check"));
    }
  }

  refresh();
  return card;
}
