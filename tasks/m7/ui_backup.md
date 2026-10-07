
TASK: write app/static/js/cards/backup.js (full file, under 110 lines). Export `export function buildBackupCard()` (synchronous, returns a div.card).

API:
GET /api/backup downloads the database snapshot (a file download, the session cookie authenticates a normal browser navigation/link).
POST /api/restore: the RAW file bytes as the request body (do NOT use the api.js helpers because they JSON-encode; use fetch("/api/restore", {method: "POST", credentials: "same-origin", headers: {"Content-Type": "application/octet-stream"}, body: file})). Success: JSON {ok: true, backup_schema_version: int, devices: int}. Errors: JSON {detail: "readable text"} with status 409 (a scan is running), 413, 422 (invalid file) or 401.

Card: <h2>Backup and restore</h2>.
- Paragraph <p class="hint">: "The backup contains all devices, history and settings, including saved e-mail and Proxmox credentials. Store it somewhere safe."
- A link styled as button: h("a", {class: "btn", href: "/api/backup", download: ""}, "Download backup").
- A form for restore: file input (accept ".db,.sqlite,.sqlite3,application/octet-stream"), button "Restore from file" (disabled until a file is chosen). On click: window.confirm("Restore this backup? It REPLACES all current data (devices, history, settings). A safety copy of the current database is kept on the server.") ; if confirmed, send the file as described; while running disable the button and show "Restoring..." text; on success toast `Restored ${devices} devices. Reloading...` and after 1200 ms call location.reload(); on failure show the detail in a <p class="error"> inside the card and an error toast; if the response is not JSON show `Restore failed (HTTP ${status})`.
- Keep the chosen file input in the card; clear it after a failed attempt is NOT required.
