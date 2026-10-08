import { get, put, del } from "../api.js";
import { h, clear, toast, timeAgo } from "../util.js";
import { humanDuration } from "../heartbeat.js";

const PRESET_LABELS = {
  default: "Default",
  fast: "Fast",
  fastest: "Fastest",
};

const PRESET_HINTS = {
  default: "The original behavior.",
  fast: "Aggressive timing, deep scans check the top 200 ports with light version detection.",
  fastest: "Also no OS or version detection, no reverse DNS, quick scans check the top 50 ports, and slow hosts are abandoned after 1 minute (quick) or 2 minutes (deep). You lose OS names, service versions and DNS names.",
};

function kvRow(label, value) {
  const row = h("div", { class: "kv" });
  row.appendChild(h("span", { class: "kv-label" }, label));
  row.appendChild(h("span", {}, value));
  return row;
}

export async function buildScanOptionsCard() {
  const card = h("div", { class: "card", id: "nmap-settings" });
  card.appendChild(h("h2", {}, "Scan performance (nmap)"));
  card.appendChild(h("p", { class: "hint" }, "Loading..."));

  async function load() {
    clear(card);
    card.appendChild(h("h2", {}, "Scan performance (nmap)"));
    card.appendChild(h("p", { class: "hint" }, "Deep scans (service versions, OS detection and traceroute over 1000 ports) are the slow part. Check fewer ports, lighten the detection, or pick a preset."));

    let data;
    try {
      data = await get("/api/scan-options");
    } catch (err) {
      card.appendChild(h("p", { class: "error" }, err.message || "Failed to load scan options"));
      return;
    }

    const options = data.options;
    const defaults = data.defaults;
    const presets = data.presets;
    const preview = data.preview;

    // Last scans line
    try {
      const scans = await get("/api/scans?limit=60");
      const lastQuick = scans.find((s) => s.kind === "quick" && s.status === "done" && s.finished);
      const lastDeep = scans.find((s) => s.kind === "deep" && s.status === "done" && s.finished);

      function scanLine(kind, scan) {
        if (!scan) return `Last ${kind} scan: none yet`;
        const seconds = Math.round((Date.parse(scan.finished) - Date.parse(scan.started)) / 1000);
        return `Last ${kind} scan: ${humanDuration(seconds)} (${scan.hosts_found} hosts)`;
      }

      const line = h("p", { class: "hint" }, `${scanLine("quick", lastQuick)} · ${scanLine("deep", lastDeep)}`);
      card.appendChild(line);
    } catch (err) {
      // omit the line if this request fails
    }

    // Preset buttons
    const presetContainer = h("div", {});
    const presetButtons = {};
    const presetHints = {};

    for (const key of ["default", "fast", "fastest"]) {
      const label = PRESET_LABELS[key];
      const isActive = JSON.stringify(options) === JSON.stringify(presets[key]);
      const btn = h("button", { type: "button", class: "btn" }, isActive ? `${label} (active)` : label);
      btn.addEventListener("click", () => {
        fillForm(presets[key]);
        toast("Preset loaded. Press Save to apply.", "info");
      });
      presetContainer.appendChild(btn);
      presetButtons[key] = btn;

      const hint = h("p", { class: "hint" }, PRESET_HINTS[key]);
      presetContainer.appendChild(hint);
    }
    card.appendChild(presetContainer);

    // Form
    const form = h("form", { class: "edit-form" });
    const errorEl = h("p", { class: "error" }, "");

    // Section 1: Speed
    const h3Speed = h("h3", {}, "Speed");
    form.appendChild(h3Speed);

    const fieldTiming = h("div", { class: "field" });
    fieldTiming.appendChild(h("label", {}, "Timing"));
    const selectTiming = h("select", { name: "timing" });
    const timingOptions = [
      { value: "2", text: "Polite (T2, slowest)" },
      { value: "3", text: "Normal (T3, default)" },
      { value: "4", text: "Aggressive (T4, recommended for a local network)" },
      { value: "5", text: "Insane (T5, can miss hosts)" },
    ];
    for (const opt of timingOptions) {
      const option = h("option", { value: opt.value }, opt.text);
      if (Number(opt.value) === Number(options.timing)) {
        option.selected = true;
      }
      selectTiming.appendChild(option);
    }
    fieldTiming.appendChild(selectTiming);
    form.appendChild(fieldTiming);

    // Section 2: Quick scan
    const h3Quick = h("h3", {}, "Quick scan (runs every few minutes)");
    form.appendChild(h3Quick);

    const fieldQuickMode = h("div", { class: "field" });
    fieldQuickMode.appendChild(h("label", {}, "Method"));
    const selectQuickMode = h("select", { name: "quick_mode" });
    const quickModeOptions = [
      { value: "ports", text: "Check the most common ports" },
      { value: "discovery", text: "Only find which hosts are up (fastest, no port info)" },
    ];
    for (const opt of quickModeOptions) {
      const option = h("option", { value: opt.value }, opt.text);
      if (opt.value === options.quick_mode) {
        option.selected = true;
      }
      selectQuickMode.appendChild(option);
    }
    fieldQuickMode.appendChild(selectQuickMode);
    form.appendChild(fieldQuickMode);

    const fieldQuickTopPorts = h("div", { class: "field" });
    fieldQuickTopPorts.appendChild(h("label", {}, "Number of top ports"));
    const inputQuickTopPorts = h("input", {
      type: "number",
      name: "quick_top_ports",
      min: "1",
      max: "10000",
      step: "1",
      value: String(options.quick_top_ports),
    });
    fieldQuickTopPorts.appendChild(inputQuickTopPorts);
    form.appendChild(fieldQuickTopPorts);

    const fieldQuickPorts = h("div", { class: "field" });
    fieldQuickPorts.appendChild(h("label", {}, "Or these specific ports"));
    const inputQuickPorts = h("input", {
      type: "text",
      name: "quick_ports",
      placeholder: "22,80,443,8000-8100",
      value: options.quick_ports,
    });
    fieldQuickPorts.appendChild(inputQuickPorts);
    fieldQuickPorts.appendChild(h("p", { class: "hint" }, "Overrides the number above."));
    form.appendChild(fieldQuickPorts);

    // Section 3: Deep scan
    const h3Deep = h("h3", {}, "Deep scan (runs daily)");
    form.appendChild(h3Deep);

    const fieldDeepTopPorts = h("div", { class: "field" });
    fieldDeepTopPorts.appendChild(h("label", {}, "Number of top ports"));
    const inputDeepTopPorts = h("input", {
      type: "number",
      name: "deep_top_ports",
      min: "1",
      max: "10000",
      step: "1",
      value: String(options.deep_top_ports),
    });
    fieldDeepTopPorts.appendChild(inputDeepTopPorts);
    form.appendChild(fieldDeepTopPorts);

    const fieldDeepPorts = h("div", { class: "field" });
    fieldDeepPorts.appendChild(h("label", {}, "Or these specific ports"));
    const inputDeepPorts = h("input", {
      type: "text",
      name: "deep_ports",
      placeholder: "22,80,443,8000-8100",
      value: options.deep_ports,
    });
    fieldDeepPorts.appendChild(inputDeepPorts);
    fieldDeepPorts.appendChild(h("p", { class: "hint" }, "Overrides the number. Ports that are not on the list disappear from a device after the next deep scan."));
    form.appendChild(fieldDeepPorts);

    const fieldDeepVersion = h("div", { class: "field" });
    fieldDeepVersion.appendChild(h("label", {}, "Service version detection"));
    const selectDeepVersion = h("select", { name: "deep_version" });
    const deepVersionOptions = [
      { value: "full", text: "Full (most accurate)" },
      { value: "light", text: "Light (faster)" },
      { value: "off", text: "Off (fastest)" },
    ];
    for (const opt of deepVersionOptions) {
      const option = h("option", { value: opt.value }, opt.text);
      if (opt.value === options.deep_version) {
        option.selected = true;
      }
      selectDeepVersion.appendChild(option);
    }
    fieldDeepVersion.appendChild(selectDeepVersion);
    fieldDeepVersion.appendChild(h("p", { class: "hint" }, "Without it, product and version columns are cleared at the next deep scan."));
    form.appendChild(fieldDeepVersion);

    const fieldDeepOs = h("div", { class: "field" });
    fieldDeepOs.appendChild(h("label", {}, "OS detection"));
    const inputDeepOs = h("input", {
      type: "checkbox",
      name: "deep_os",
      checked: options.deep_os,
    });
    fieldDeepOs.appendChild(inputDeepOs);
    fieldDeepOs.appendChild(h("p", { class: "hint" }, "Off keeps the last known OS but stops updating it."));
    form.appendChild(fieldDeepOs);

    const fieldDeepTraceroute = h("div", { class: "field" });
    fieldDeepTraceroute.appendChild(h("label", {}, "Traceroute"));
    const inputDeepTraceroute = h("input", {
      type: "checkbox",
      name: "deep_traceroute",
      checked: options.deep_traceroute,
    });
    fieldDeepTraceroute.appendChild(inputDeepTraceroute);
    fieldDeepTraceroute.appendChild(h("p", { class: "hint" }, "Needed for the route links on the map."));
    form.appendChild(fieldDeepTraceroute);

    // Section 4: Both
    const h3Both = h("h3", {}, "Both");
    form.appendChild(h3Both);

    const fieldSkipDns = h("div", { class: "field" });
    fieldSkipDns.appendChild(h("label", {}, "Skip reverse DNS lookups"));
    const inputSkipDns = h("input", {
      type: "checkbox",
      name: "skip_dns",
      checked: options.skip_dns,
    });
    fieldSkipDns.appendChild(inputSkipDns);
    fieldSkipDns.appendChild(h("p", { class: "hint" }, "Faster, but hostnames that come from DNS are no longer updated. Names from mDNS/SSDP stay."));
    form.appendChild(fieldSkipDns);

    function timeoutField(labelText, name, value, hintText) {
      const field = h("div", { class: "field" });
      field.appendChild(h("label", {}, labelText));
      const input = h("input", { type: "number", name, min: "0", max: "86400", step: "1", value: String(value) });
      field.appendChild(input);
      field.appendChild(h("p", { class: "hint" }, hintText));
      form.appendChild(field);
      return input;
    }
    const inputQuickHostTimeout = timeoutField(
      "Give up on a host in a quick scan after (seconds, 0 = never)",
      "quick_host_timeout",
      options.quick_host_timeout,
      "The host is skipped for that scan only: it stays online and keeps its known ports, and a \"Host timeout\" event is logged. 0 or at least 10."
    );
    const inputDeepHostTimeout = timeoutField(
      "Give up on a host in a deep scan after (seconds, 0 = never)",
      "deep_host_timeout",
      options.deep_host_timeout,
      "Stops one slow or rate-limiting device from holding a deep scan up for an hour. 0 or at least 10."
    );

    form.appendChild(errorEl);

    const saveBtn = h("button", { type: "submit", class: "btn" }, "Save");
    const resetBtn = h("button", { type: "button", class: "btn" }, "Reset to defaults");
    form.appendChild(saveBtn);
    form.appendChild(resetBtn);

    // Resulting nmap commands
    const h3Preview = h("h3", {}, "Resulting nmap commands");
    form.appendChild(h3Preview);
    form.appendChild(h("p", { class: "hint" }, "Quick scan, deep scan, and the full scan of a single host (button on the device page; all 65535 TCP ports, always at least aggressive timing)."));
    const prePreview = h("pre", { class: "mono" }, [preview.quick, preview.deep, preview.full].filter(Boolean).join("\n"));
    form.appendChild(prePreview);

    card.appendChild(form);

    function fillForm(preset) {
      selectTiming.value = String(preset.timing);
      selectQuickMode.value = preset.quick_mode;
      inputQuickTopPorts.value = String(preset.quick_top_ports);
      inputQuickPorts.value = preset.quick_ports;
      inputDeepTopPorts.value = String(preset.deep_top_ports);
      inputDeepPorts.value = preset.deep_ports;
      selectDeepVersion.value = preset.deep_version;
      inputDeepOs.checked = preset.deep_os;
      inputDeepTraceroute.checked = preset.deep_traceroute;
      inputSkipDns.checked = preset.skip_dns;
      inputQuickHostTimeout.value = String(preset.quick_host_timeout);
      inputDeepHostTimeout.value = String(preset.deep_host_timeout);
    }

    function collectValues() {
      return {
        timing: Number(selectTiming.value),
        quick_mode: selectQuickMode.value,
        quick_top_ports: Number(inputQuickTopPorts.value),
        quick_ports: inputQuickPorts.value.trim(),
        deep_top_ports: Number(inputDeepTopPorts.value),
        deep_ports: inputDeepPorts.value.trim(),
        deep_version: selectDeepVersion.value,
        deep_os: inputDeepOs.checked,
        deep_traceroute: inputDeepTraceroute.checked,
        skip_dns: inputSkipDns.checked,
        quick_host_timeout: Number(inputQuickHostTimeout.value),
        deep_host_timeout: Number(inputDeepHostTimeout.value),
      };
    }

    async function submit(body, doneMessage) {
      errorEl.textContent = "";
      saveBtn.disabled = true;
      resetBtn.disabled = true;
      try {
        const updated = await put("/api/scan-options", body);
        toast(doneMessage, "success");
        await load();
      } catch (err) {
        errorEl.textContent = err.message || "Failed to save";
        toast(err.message || "Failed to save", "error");
        saveBtn.disabled = false;
        resetBtn.disabled = false;
      }
    }

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      submit(collectValues(), "Scan settings saved. They apply from the next scan.");
    });

    resetBtn.addEventListener("click", async () => {
      errorEl.textContent = "";
      saveBtn.disabled = true;
      resetBtn.disabled = true;
      try {
        const updated = await del("/api/scan-options");
        toast("Scan settings reset to defaults.", "success");
        await load();
      } catch (err) {
        errorEl.textContent = err.message || "Failed to reset";
        toast(err.message || "Failed to reset", "error");
        saveBtn.disabled = false;
        resetBtn.disabled = false;
      }
    });
  }

  load();
  return card;
}