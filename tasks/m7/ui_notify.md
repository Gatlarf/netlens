
TASK: write app/static/js/cards/notifications.js (full file, under 190 lines). Export `export async function buildNotificationsCard()`.

API:
GET /api/notifications -> {enabled: bool, smtp_host: str, smtp_port: int, security: "none"|"starttls"|"ssl", username: str, from_addr: str, to_addrs: [str], notify_new: bool, notify_offline: bool, password_set: bool, configured: bool, status: null | {ts: iso, ok: bool, error?: str, sent?: int, subject?: str, pending?: int}}.
PUT /api/notifications with any of {enabled, smtp_host, smtp_port (int), security, username, password, from_addr, to_addrs (comma separated string accepted), notify_new, notify_offline}; only the fields sent change. Omit `password` from the body when the password input is empty (the server then keeps the saved one). Returns the same shape as GET. Errors 422 with a readable detail.
POST /api/notifications/test (no body) -> {ok: true, to: [str]} or error 422/502 with a readable detail. It uses the SAVED settings.

Card: <h2>E-mail notifications</h2> and a form with:
- checkbox "Send e-mail notifications" (enabled)
- inputs: SMTP server (smtp_host), Port (number, smtp_port), select Security with options "STARTTLS (port 587)" = starttls, "SSL/TLS (port 465)" = ssl, "None (port 25)" = none; Username; Password (type password, autocomplete "new-password", placeholder "unchanged" when password_set, else empty); From address; To address(es) (text, comma separated, value to_addrs.join(", ")).
- checkbox "Notify when a new device appears" (notify_new); checkbox "Notify when a device goes offline" (notify_offline) with a hint "You can switch this off for individual devices on their device page."
- Buttons: "Save" (submit) and "Send test email". The test button first saves the current form (PUT) and then calls POST /api/notifications/test; on success toast "Test email sent to a@b.c" (join to) , on failure show the error inline. Disable both buttons while busy.
- A status line at the bottom (<p class="hint">, red via class "error" when failed) built from `status`: ok -> `Last notification mail: ${timeAgo(ts)} (${sent} event(s))`; not ok -> `Last problem (${timeAgo(ts)}): ${error}`; null -> nothing.
- When security changes in the select and the port input still holds the previous default (587/465/25), set the port to the new default.
