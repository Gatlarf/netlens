import { api } from "../api.js";
import { h, clear, toast, fmtTime } from "../util.js";

const INTERVAL_LABELS = { 6: "every 6 hours", 12: "every 12 hours", 24: "every day", 72: "every 3 days", 168: "every week" };

function fmtSize(bytes) {
  return bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

function fillSchedule(box, data) {
  clear(box);
  box.appendChild(h("h3", {}, "Scheduled backups"));
  box.appendChild(h("p", { class: "hint" },
    "Netlens keeps copies on the server (in the data folder, readable only by Netlens). They are lost if the data disk is lost, so download one now and then as well."));

  const enabled = h("input", { type: "checkbox", name: "enabled" });
  enabled.checked = data.schedule.enabled;
  const every = h("select", { name: "every_hours" });
  for (const hours of data.intervals) every.appendChild(h("option", { value: String(hours) }, INTERVAL_LABELS[hours] || `every ${hours} hours`));
  every.value = String(data.schedule.every_hours);
  const keep = h("input", { type: "number", name: "keep", min: "1", max: "60", value: String(data.schedule.keep) });
  const saveBtn = h("button", { type: "button", class: "btn" }, "Save schedule");
  const runBtn = h("button", { type: "button", class: "btn" }, "Back up now");
  const row = (label, input) => h("div", { class: "field" }, h("label", {}, label), input);
  box.appendChild(h("div", { class: "field" }, h("label", { class: "check" }, enabled, " Make a backup automatically")));
  box.appendChild(row("How often", every));
  box.appendChild(row("Copies to keep", keep));
  box.appendChild(saveBtn);
  box.appendChild(runBtn);

  const last = data.last;
  if (last) {
    box.appendChild(h("p", { class: last.ok ? "hint" : "error", id: "backup-last" },
      last.ok ? `Last backup: ${fmtTime(last.at)} (${last.name})` : `Last backup FAILED at ${fmtTime(last.at)}: ${last.error}`));
  }

  const call = async (btn, request, done) => {
    btn.disabled = true;
    try {
      const updated = await request();
      toast(done, "success");
      fillSchedule(box, updated);
    } catch (err) {
      toast(err.message || "Failed", "error");
      btn.disabled = false;
    }
  };
  saveBtn.addEventListener("click", () => call(saveBtn,
    () => api("/api/backups/schedule", { method: "PUT", body: { enabled: enabled.checked, every_hours: Number(every.value), keep: Number(keep.value) } }),
    "Schedule saved"));
  runBtn.addEventListener("click", () => call(runBtn, () => api("/api/backups/run", { method: "POST" }), "Backup made"));

  if (data.backups.length) {
    const table = h("table", { class: "table backups" });
    table.appendChild(h("thead", {}, h("tr", {}, h("th", {}, "Backup"), h("th", {}, "Size"), h("th", {}, ""))));
    const body = h("tbody");
    for (const b of data.backups) {
      const restore = h("button", { type: "button", class: "btn" }, "Restore");
      const remove = h("button", { type: "button", class: "btn danger" }, "Delete");
      restore.addEventListener("click", async () => {
        if (!window.confirm(`Restore ${b.name}? It REPLACES all current data (devices, history, settings). A safety copy of the current database is kept on the server.`)) return;
        restore.disabled = true;
        try {
          const res = await api(`/api/backups/${b.name}/restore`, { method: "POST" });
          toast(`Restored ${res.devices} devices. Reloading...`, "success");
          setTimeout(() => location.reload(), 1200);
        } catch (err) {
          toast(err.message || "Restore failed", "error");
          restore.disabled = false;
        }
      });
      remove.addEventListener("click", () => call(remove, () => api(`/api/backups/${b.name}`, { method: "DELETE" }), "Backup deleted"));
      body.appendChild(h("tr", {},
        h("td", {}, h("a", { href: `/api/backups/${b.name}`, download: b.name }, b.name)),
        h("td", {}, fmtSize(b.size)),
        h("td", {}, restore, " ", remove)));
    }
    table.appendChild(body);
    box.appendChild(table);
  } else {
    box.appendChild(h("p", { class: "hint" }, "No scheduled backups yet."));
  }
}

export function buildBackupCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Backup and restore"));

  card.appendChild(h("p", { class: "hint" },
    "The backup contains all devices, history and settings, including saved e-mail and plugin credentials. Store it somewhere safe."));

  card.appendChild(h("a", { class: "btn", href: "/api/backup", download: "" }, "Download backup"));

  const scheduleBox = h("div", { class: "schedule-box" }, h("p", { class: "hint" }, "Loading..."));
  card.appendChild(scheduleBox);
  api("/api/backups").then((data) => fillSchedule(scheduleBox, data), (err) => {
    clear(scheduleBox);
    scheduleBox.appendChild(h("p", { class: "error" }, err.message || "Failed to load the schedule"));
  });

  const form = h("form", { class: "edit-form" });

  const field = h("div", { class: "field" });
  field.appendChild(h("label", {}, "Backup file"));
  const fileInput = h("input", {
    type: "file",
    name: "file",
    accept: ".db,.sqlite,.sqlite3,application/octet-stream",
  });
  field.appendChild(fileInput);
  form.appendChild(field);

  const errorEl = h("p", { class: "error" }, "");
  form.appendChild(errorEl);

  const restoreBtn = h("button", { type: "submit", class: "btn", disabled: true }, "Restore from file");
  form.appendChild(restoreBtn);

  fileInput.addEventListener("change", () => {
    restoreBtn.disabled = !fileInput.files.length;
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const file = fileInput.files[0];
    if (!file) return;

    const confirmed = window.confirm(
      "Restore this backup? It REPLACES all current data (devices, history, settings). " +
      "A safety copy of the current database is kept on the server."
    );
    if (!confirmed) return;

    errorEl.textContent = "";
    restoreBtn.disabled = true;
    restoreBtn.textContent = "Restoring...";

    try {
      const res = await fetch("/api/restore", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/octet-stream" },
        body: file,
      });

      let data = null;
      try {
        data = await res.json();
      } catch (e) {
        data = null;
      }

      if (!res.ok) {
        const msg = data && data.detail
          ? data.detail
          : `Restore failed (HTTP ${res.status})`;
        errorEl.textContent = msg;
        toast(msg, "error");
        restoreBtn.disabled = false;
        restoreBtn.textContent = "Restore from file";
        return;
      }

      const devices = data && data.devices != null ? data.devices : 0;
      toast(`Restored ${devices} devices. Reloading...`, "success");
      setTimeout(() => location.reload(), 1200);
    } catch (err) {
      const msg = err.message || "Restore failed";
      errorEl.textContent = msg;
      toast(msg, "error");
      restoreBtn.disabled = false;
      restoreBtn.textContent = "Restore from file";
    }
  });

  card.appendChild(form);
  return card;
}