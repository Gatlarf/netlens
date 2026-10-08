import { get, post, patch } from "../api.js";
import { h, toast } from "../util.js";

const KIND_HELP = {
  http: { target: "Path", placeholder: "/", expect: "Expect", expectHint: "empty = any status from 200 to 399; a status code such as 401; or text:words that must appear in the page", port: "80" },
  tcp: { target: null, placeholder: "", expect: null, expectHint: "", port: "22" },
  dns: { target: "Name to look up", placeholder: "example.com", expect: "Expected address", expectHint: "optional: the IP address the answer must contain", port: "53" },
};

function field(label, input, hint) {
  const wrap = h("div", { class: "field" });
  wrap.appendChild(h("label", {}, label));
  wrap.appendChild(input);
  if (hint) wrap.appendChild(h("p", { class: "hint" }, hint));
  return wrap;
}

// Form to add or edit a service check. `check` null = new; `defaults` pre-fills a new one (for example the device).
export async function buildServiceForm({ check = null, defaults = {}, onDone }) {
  const c = check || { kind: "http", name: "", host: "", port: null, path: "", expect: "", interval_s: 60, timeout_s: 5, device_id: null, ...defaults };
  let devices = [];
  try {
    devices = await get("/api/devices");
  } catch (err) {
    devices = [];
  }
  const form = h("form", { class: "edit-form service-form" });
  const name = h("input", { type: "text", name: "name", value: c.name || "", placeholder: "Web interface", required: true });
  const kind = h("select", { name: "kind" });
  for (const [value, label] of [["http", "HTTP(S) page"], ["tcp", "TCP port"], ["dns", "DNS lookup"]]) kind.appendChild(h("option", { value }, label));
  kind.value = c.kind;
  const host = h("input", { type: "text", name: "host", value: c.host || "", placeholder: "192.168.0.10 or name", required: true });
  const port = h("input", { type: "number", name: "port", min: "1", max: "65535", value: c.port ? String(c.port) : "" });
  const path = h("input", { type: "text", name: "path", value: c.path || "" });
  const expect = h("input", { type: "text", name: "expect", value: c.expect || "" });
  const interval = h("input", { type: "number", name: "interval_s", min: "15", max: "86400", step: "1", value: String(c.interval_s) });
  const timeout = h("input", { type: "number", name: "timeout_s", min: "1", max: "30", step: "1", value: String(c.timeout_s) });
  const device = h("select", { name: "device_id" });
  device.appendChild(h("option", { value: "" }, "(no device)"));
  for (const d of devices.slice().sort((a, b) => (a.name || "").localeCompare(b.name || ""))) device.appendChild(h("option", { value: String(d.id) }, `${d.name || d.primary_ip} (${d.primary_ip || ""})`));
  device.value = c.device_id ? String(c.device_id) : "";

  const pathField = h("div", { class: "field" });
  const expectField = h("div", { class: "field" });
  function refreshKind() {
    const help = KIND_HELP[kind.value];
    port.placeholder = help.port;
    pathField.style.display = help.target ? "" : "none";
    expectField.style.display = help.expect ? "" : "none";
    pathField.replaceChildren(h("label", {}, help.target || ""), path);
    path.placeholder = help.placeholder;
    expectField.replaceChildren(h("label", {}, help.expect || ""), expect, h("p", { class: "hint" }, help.expectHint));
  }
  kind.addEventListener("change", refreshKind);
  refreshKind();

  form.append(field("Name", name), field("Type", kind), field("Host", host), field("Port", port), pathField, expectField,
    field("Check every (seconds)", interval), field("Give up after (seconds)", timeout), field("Belongs to device", device));
  const error = h("p", { class: "error" }, "");
  const save = h("button", { type: "submit", class: "btn" }, check ? "Save" : "Add check");
  const cancel = h("button", { type: "button", class: "btn" }, "Cancel");
  form.append(error, save, cancel);
  cancel.addEventListener("click", () => onDone(false));

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    error.textContent = "";
    const body = {
      name: name.value, kind: kind.value, host: host.value, port: port.value === "" ? null : Number(port.value),
      path: path.value, expect: expect.value, interval_s: Number(interval.value), timeout_s: Number(timeout.value),
      device_id: device.value === "" ? null : Number(device.value),
    };
    if (body.port === null) delete body.port;
    save.disabled = true;
    try {
      if (check) await patch(`/api/service-checks/${check.id}`, body);
      else await post("/api/service-checks", body);
      toast(check ? "Check saved" : "Check added", "success");
      onDone(true);
    } catch (err) {
      error.textContent = err.message || "Could not save the check";
      save.disabled = false;
    }
  });
  return form;
}
