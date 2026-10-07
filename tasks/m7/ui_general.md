
TASK: write app/static/js/cards/general.js (full file, under 120 lines). Export `export async function buildGeneralCard()`.

API: GET /api/config returns (among others) {quick_interval: seconds, deep_interval: seconds, quick_interval_source: "ui"|"env", deep_interval_source: "ui"|"env", env_quick_interval: seconds, env_deep_interval: seconds, terminal_enabled: bool, terminal_source: "ui"|"env", env_terminal_enabled: bool}.
PUT /api/config/general accepts any of {quick_interval: int seconds (60..2592000), deep_interval: int seconds, terminal_enabled: bool}; a field set to null resets that setting to its environment default. It returns the same shape as GET /api/config.

Card: <h2>Scan schedule and terminal</h2> with a form:
- number input "Quick scan every (minutes)" showing quick_interval/60 (min 1, step 1) with a hint "From the environment (NETLENS_QUICK_INTERVAL)" when quick_interval_source is "env" or "Changed here; environment default: N min" when "ui".
- number input "Deep scan every (hours)" showing deep_interval/3600 (min 0.05, step any/0.5), same style hint with env_deep_interval.
- checkbox "Enable the web terminal (SSH/Telnet from the device page)" checked = terminal_enabled, hint about source ("From the environment (NETLENS_TERMINAL)" or "Changed here").
- Buttons: Save (submit) and "Reset to defaults".
- Save sends {quick_interval: Math.round(minutes*60), deep_interval: Math.round(hours*3600), terminal_enabled: checkbox}; show an inline error for non-numeric/empty input before sending ("Enter a number of minutes"). Reset sends {quick_interval: null, deep_interval: null, terminal_enabled: null}. Toasts: "Settings saved" / "Settings reset".
- After saving, mention in a hint: "Takes effect from the next scheduler cycle; no restart needed."
