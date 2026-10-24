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
    const SHOWN = 6;
    for (const [n, b] of data.backups.entries()) {
      const restore = h("button", { type: "button", class: "btn" }, "Restore");
      const remove = h("button", { type: "button", class: "btn danger" }, "Delete");
      restore.addEventListener("click", async () => {
        if (!window.confirm(`Restore ${b.name}? It REPLACES all current data (devices, history, settings). A safety copy of the current database is kept on the server.`)) return;
        restore.disabled = true;
        try {
          const res = await api(`/api/backups/${b.name}/restore`, { method: "POST" });
          toast(`Restored ${res.devices} devices${(res.plugins || []).length ? ` and ${res.plugins.length} plugin(s)` : ""}. Reloading...`, "success");
          if ((res.plugins_failed || []).length) toast(`Could not restore: ${res.plugins_failed.join(", ")}`, "error");
          setTimeout(() => location.reload(), 1200);
        } catch (err) {
          toast(err.message || "Restore failed", "error");
          restore.disabled = false;
        }
      });
      remove.addEventListener("click", () => call(remove, () => api(`/api/backups/${b.name}`, { method: "DELETE" }), "Backup deleted"));
      body.appendChild(h("tr", { class: n >= SHOWN ? "older" : "", hidden: n >= SHOWN },
        h("td", {}, h("a", { href: `/api/backups/${b.name}`, download: b.name }, b.name)),
        h("td", {}, fmtSize(b.size)),
        h("td", {}, restore, " ", remove)));
    }
    table.appendChild(body);
    box.appendChild(table);
    if (data.backups.length > SHOWN) {
      const more = h("button", { type: "button", class: "btn ghost" }, `Show the ${data.backups.length - SHOWN} older backups`);
      more.addEventListener("click", () => {
        const hide = more.dataset.open === "1";
        for (const r of body.querySelectorAll("tr.older")) r.hidden = hide;
        more.dataset.open = hide ? "" : "1";
        more.textContent = hide ? `Show the ${data.backups.length - SHOWN} older backups` : "Show fewer";
      });
      box.appendChild(more);
    }
  } else {
    box.appendChild(h("p", { class: "hint" }, "No scheduled backups yet."));
  }
}

// The key that encrypts the stored passwords: whether everything can be read, a copy of it, and putting one back after a restore
function keyBox() {
  const box = h("div", { class: "key-box" });
  async function draw() {
    clear(box);
    box.appendChild(h("h3", {}, "Encryption key"));
    let state;
    try {
      state = await api("/api/vault");
    } catch (err) {
      box.appendChild(h("p", { class: "error" }, err.message || "Could not read the key status"));
      return;
    }
    const where = state.source === "env" ? "It is set with the NETLENS_SECRET_KEY environment variable." : "It is the file secret.key in the data folder, next to the database.";
    box.appendChild(h("p", { class: "hint" }, `Saved passwords and tokens (plugins, notification channels) are stored encrypted. ${where} Keep a copy of the key: without it a restored backup cannot be read, and the passwords have to be entered again.`));
    if (state.unreadable) {
      box.appendChild(h("p", { class: "error", id: "vault-bad" }, `${state.unreadable} saved password setting(s) cannot be read with this key. This happens after restoring a backup on another machine.`));
      const field = (label, name, type) => { const i = h("input", { type, name, autocomplete: "off", "aria-label": label, placeholder: label }); return [i, h("div", { class: "field" }, h("label", {}, label), i)]; };
      const unlock = async (btn, body) => {
        btn.disabled = true;
        try {
          await api("/api/vault/key", { method: "PUT", body });
          toast("The passwords can be read again", "success");
          draw();
        } catch (err) {
          toast(err.message || "That did not work", "error");
          btn.disabled = false;
        }
      };
      if (state.recovery) {
        const [pass, passRow] = field("Recovery passphrase", "passphrase", "password");
        const go = h("button", { type: "button", class: "btn" }, "Unlock with the passphrase");
        go.addEventListener("click", () => unlock(go, { passphrase: pass.value }));
        box.append(passRow, go);
      }
      const [key, keyRow] = field("Or paste the encryption key of the original installation", "key", "text");
      const use = h("button", { type: "button", class: "btn" }, "Use this key");
      use.addEventListener("click", () => unlock(use, { key: key.value }));
      box.append(keyRow, use);
      return;
    }
    box.appendChild(h("p", { class: "hint" }, `${state.encrypted} saved setting(s) are encrypted and readable.`));
    if (state.source === "file") {
      if (!state.recovery) {
        box.appendChild(h("p", { class: "hint", id: "vault-norecovery" },
          "Backups cannot give back the saved passwords on a new machine yet. Set a recovery passphrase: the key is then kept inside every backup, wrapped with it. Remember the passphrase; Netlens does not store it."));
      } else {
        box.appendChild(h("p", { class: "hint" }, "A recovery passphrase is set: backups carry the key, wrapped with it. Set it again to change it."));
      }
      const pass = h("input", { type: "password", name: "recovery", autocomplete: "new-password", placeholder: "Recovery passphrase (8 characters or more)", "aria-label": "Recovery passphrase" });
      const setBtn = h("button", { type: "button", class: "btn" }, state.recovery ? "Change the passphrase" : "Set the passphrase");
      setBtn.addEventListener("click", async () => {
        setBtn.disabled = true;
        try {
          await api("/api/vault/recovery", { method: "PUT", body: { passphrase: pass.value } });
          toast("The recovery passphrase is set", "success");
          draw();
        } catch (err) {
          toast(err.message || "That did not work", "error");
          setBtn.disabled = false;
        }
      });
      box.append(h("div", { class: "field" }, pass), setBtn);
      const show = h("button", { type: "button", class: "btn" }, "Show the key to keep a copy");
      const out = h("p", { class: "mono", id: "vault-key" });
      show.addEventListener("click", async () => {
        try {
          out.textContent = (await api("/api/vault/key")).key;
        } catch (err) {
          toast(err.message || "The key cannot be shown here", "error");
        }
      });
      box.append(show, out);
    }
  }
  draw();
  return box;
}

export function buildBackupCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Backup and restore"));

  card.appendChild(h("p", { class: "hint" },
    "The backup contains all devices, history and settings. Saved passwords and tokens are in it encrypted; they can only be read with the encryption key below, which is not in the backup. The installed plugins are in it too (their code and settings), so a restore brings everything back as it was. Store it somewhere safe."));

  card.appendChild(h("a", { class: "btn", href: "/api/backup", download: "" }, "Download backup"));

  const scheduleBox = h("div", { class: "schedule-box" }, h("p", { class: "hint" }, "Loading..."));
  card.appendChild(scheduleBox);
  api("/api/backups").then((data) => fillSchedule(scheduleBox, data), (err) => {
    clear(scheduleBox);
    scheduleBox.appendChild(h("p", { class: "error" }, err.message || "Failed to load the schedule"));
  });

  card.appendChild(keyBox());

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
      toast(`Restored ${devices} devices${data && (data.plugins || []).length ? ` and ${data.plugins.length} plugin(s)` : ""}. Reloading...`, "success");
      if (data && (data.plugins_failed || []).length) toast(`Could not restore: ${data.plugins_failed.join(", ")}`, "error");
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