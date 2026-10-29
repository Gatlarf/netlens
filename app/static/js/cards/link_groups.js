import { get, post, patch, del, ApiError } from "../api.js";
import { h, toast } from "../util.js";

const STATUS = {
  ok: ["All links up", ""],
  degraded: ["A link is down", "bad"],
  down: ["All links down", "bad"],
  unknown: ["State unknown (the switch has not reported lately)", "muted"],
};

function portLabel(p) {
  return `Port ${p.port}${p.name ? " " + p.name : ""}`;
}

// A list of tick boxes, one per port of the switch, with the link state beside it. `selected` is a Set of port numbers.
function portPicker(ports, selected) {
  const boxes = [];
  const list = h("div", { class: "port-picker" });
  for (const p of ports) {
    const box = h("input", { type: "checkbox", value: String(p.port), checked: selected.has(p.port) });
    boxes.push(box);
    list.appendChild(h("label", { class: "check-row" }, box, ` ${portLabel(p)} `, h("span", { class: p.up ? "hint" : "bad" }, p.up ? "link up" : "no link")));
  }
  return { list, chosen: () => boxes.filter((b) => b.checked).map((b) => Number(b.value)) };
}

function describeError(err) {
  return err instanceof ApiError ? err.message : "That did not work";
}

// "Bonded connection": the switch ports that carry a host's bond (NIC teaming, LACP), so a lost link is reported even though the host stays online.
export async function buildLinkGroupsCard(device, onChange) {
  const [mine, offered] = await Promise.all([get(`/api/link-groups?device_id=${device.id}`), get("/api/link-groups/switches")]);
  const groups = mine.groups;
  const switches = offered.switches.filter((s) => s.id !== device.id);
  const isSwitch = offered.switches.some((s) => s.id === device.id);
  if (!groups.length && (isSwitch || !switches.length)) return null;

  const card = h("div", { class: "card link-groups-card" });
  card.appendChild(h("h2", {}, "Bonded connection"));
  card.appendChild(h("p", { class: "hint" }, "A bond (NIC teaming, LACP) shows up as one network card, so Netlens cannot see that one of its cables went down: the host stays online with less redundancy. Tell Netlens which switch ports carry the bond and it reports a lost link."));

  for (const g of groups) {
    const [text, tone] = STATUS[g.status] || STATUS.unknown;
    const row = h("div", { class: "link-group" });
    row.appendChild(h("div", {}, h("strong", {}, g.name), " ", h("span", { class: tone }, text),
      h("div", { class: "hint" }, `${g.host} on `, h("a", { href: `#/device/${g.switch_device_id}` }, g.switch || "the switch"), `: ${g.up} of ${g.total} links up`)));
    const members = h("ul", { class: "ip-list" });
    for (const m of g.ports) {
      members.appendChild(h("li", {}, h("span", {}, portLabel(m)), " ", h("span", { class: !m.known ? "muted" : m.up ? "hint" : "bad" }, !m.known ? "not reported" : m.up ? "link up" : "no link")));
    }
    row.appendChild(members);
    if (g.host_device_id === device.id) {
      const known = (offered.switches.find((s) => s.id === g.switch_device_id) || { ports: [] }).ports;
      const editor = h("div", {});
      editor.hidden = true;
      const picker = portPicker(known, new Set(g.ports.map((m) => m.port)));
      const nameBox = h("input", { type: "text", value: g.name, maxlength: "60", "aria-label": "Name of the bond" });
      const save = h("button", { type: "button", class: "btn primary" }, "Save ports");
      save.addEventListener("click", async () => {
        try {
          await patch(`/api/link-groups/${g.id}`, { name: nameBox.value, ports: picker.chosen() });
          toast("Saved", "success");
          onChange();
        } catch (err) {
          toast(describeError(err), "error");
        }
      });
      editor.append(nameBox, picker.list, h("div", { class: "btn-row" }, save));
      const change = h("button", { type: "button", class: "btn" }, "Change");
      change.addEventListener("click", () => { editor.hidden = !editor.hidden; });
      const remove = h("button", { type: "button", class: "btn danger" }, "Remove");
      remove.addEventListener("click", async () => {
        try {
          await del(`/api/link-groups/${g.id}`);
          onChange();
        } catch (err) {
          toast(describeError(err), "error");
        }
      });
      row.append(h("div", { class: "btn-row" }, change, remove), editor);
    }
    card.appendChild(row);
  }

  if (!isSwitch && switches.length) {
    const form = h("div", { class: "link-group-new" });
    form.appendChild(h("h3", {}, "Add a bonded connection"));
    const nameBox = h("input", { type: "text", placeholder: "For example: bond0", maxlength: "60", "aria-label": "Name of the bond" });
    const switchSelect = h("select", { "aria-label": "Switch" }, ...switches.map((s) => h("option", { value: String(s.id) }, s.name || `device ${s.id}`)));
    const pickerSlot = h("div", {});
    let picker = null;
    const draw = () => {
      const chosen = switches.find((s) => String(s.id) === switchSelect.value);
      picker = portPicker(chosen ? chosen.ports : [], new Set());
      pickerSlot.replaceChildren(picker.list);
    };
    switchSelect.addEventListener("change", draw);
    draw();
    const add = h("button", { type: "button", class: "btn primary" }, "Add");
    add.addEventListener("click", async () => {
      try {
        await post("/api/link-groups", { name: nameBox.value, host_device_id: device.id, switch_device_id: Number(switchSelect.value), ports: picker.chosen() });
        toast("Added", "success");
        onChange();
      } catch (err) {
        toast(describeError(err), "error");
      }
    });
    form.append(h("div", { class: "edit-grid" }, h("label", {}, "Name", nameBox), h("label", {}, "Switch", switchSelect)),
      h("p", { class: "hint" }, "Tick the ports the bond's cables are plugged into (two or more)."), pickerSlot, h("div", { class: "btn-row" }, add));
    card.appendChild(form);
  }
  return card;
}
