import { h, clear, toast } from "../util.js";

export function buildBackupCard() {
  const card = h("div", { class: "card" });
  card.appendChild(h("h2", {}, "Backup and restore"));

  card.appendChild(h("p", { class: "hint" },
    "The backup contains all devices, history and settings, including saved e-mail and plugin credentials. Store it somewhere safe."));

  card.appendChild(h("a", { class: "btn", href: "/api/backup", download: "" }, "Download backup"));

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