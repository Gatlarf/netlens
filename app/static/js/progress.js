// Turns the /api/scans/current response into header text and a progress-bar value.
import { humanDuration } from "./heartbeat.js";

const PHASE_TEXT = {
  preparing: "Preparing",
  names: "Resolving names",
  saving: "Saving results",
  finishing: "Finishing up",
};

export function describeScan(res) {
  if (!res || !res.running) return { text: "", percent: null };
  const progress = res.progress || {};
  const rawKind = progress.kind || (res.scan && res.scan.kind);
  const kind = rawKind === "deep" ? "Deep" : rawKind === "full" ? "Full" : "Quick";
  const target = progress.target || (res.scan && res.scan.target);
  const parts = [rawKind === "full" && target ? `Full scan of ${target}` : `${kind} scan`];
  let percent = null;

  if (progress.phase === "scanning" || !progress.phase) {
    if (progress.task) {
      const hasPct = typeof progress.percent === "number";
      parts.push(hasPct ? `${progress.task} ${Math.round(progress.percent)}%` : progress.task);
      if (hasPct) percent = progress.percent;
    } else {
      parts.push("scanning");
    }
  } else {
    parts.push(PHASE_TEXT[progress.phase] || progress.phase);
  }
  if (typeof progress.hosts_found === "number" && progress.hosts_found > 0) {
    parts.push(`${progress.hosts_found} host${progress.hosts_found === 1 ? "" : "s"}`);
  }
  return { text: parts.join(" · "), percent };
}

// "1m 12s (typical 7m 26s)": time the running scan has taken so far and the typical (median)
// duration of recent scans of the same kind. `extraSeconds` is the time passed since the response arrived, so the display can tick
// between polls.
export function describeTiming(res, extraSeconds = 0) {
  if (!res || !res.running || typeof res.elapsed_seconds !== "number") return "";
  const elapsed = humanDuration(Math.max(0, Math.round(res.elapsed_seconds + extraSeconds)));
  if (typeof res.typical_seconds !== "number") return elapsed;
  return `${elapsed} (typical ${humanDuration(res.typical_seconds)})`;
}
