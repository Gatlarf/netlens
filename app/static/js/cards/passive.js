import { get, put } from "../api.js";
import { h, toast } from "../util.js";

function statusText(s) {
  if (!s.enabled) return "Off.";
  if (s.running) return `Listening. ${s.frames} announcement(s) heard, ${s.applied} device(s) updated, ${s.pending} waiting for a scan to find their device.`;
  return s.error ? `Not running: ${s.error}. Give the container the NET_RAW capability (the compose files do).` : "Starting…";
}

export async function buildPassiveCard() {
  const s = await get("/api/passive");
  const card = h("div", { class: "card", id: "passive-card" });
  card.appendChild(h("h2", {}, "Passive listening"));
  card.appendChild(h("p", { class: "hint" },
    "Devices announce themselves when they join the network: a name, an operating system fingerprint (DHCP), a model (mDNS), a kind of device (UPnP). Netlens listens to those broadcasts and sends nothing. It helps most with phones using a private Wi-Fi address, which have no open ports to scan. It only hears broadcasts that reach this machine, so devices on other network segments are not seen."));
  const box = h("input", { type: "checkbox", id: "passive-enabled" });
  box.checked = s.enabled;
  const status = h("p", { class: "hint", id: "passive-status" }, statusText(s));
  card.appendChild(h("div", { class: "field" }, h("label", { class: "check" }, box, " Listen for device announcements")));
  card.appendChild(status);
  box.addEventListener("change", async () => {
    box.disabled = true;
    try {
      const next = await put("/api/passive", { enabled: box.checked });
      status.textContent = statusText(next);
    } catch (err) {
      toast(err.message || "Failed", "error");
      box.checked = !box.checked;
    }
    box.disabled = false;
  });
  return card;
}
