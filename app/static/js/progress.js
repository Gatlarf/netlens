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
  const kind = (progress.kind || (res.scan && res.scan.kind)) === "deep" ? "Deep" : "Quick";
  const parts = [`${kind} scan`];
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

// "1m 12s (avg 7m 26s)": time the running scan has taken so far and the mean of recent scans of the
// same kind. `extraSeconds` is the time passed since the response arrived, so the display can tick
// between polls.
export function describeTiming(res, extraSeconds = 0) {
  if (!res || !res.running || typeof res.elapsed_seconds !== "number") return "";
  const elapsed = humanDuration(Math.max(0, Math.round(res.elapsed_seconds + extraSeconds)));
  if (typeof res.average_seconds !== "number") return elapsed;
  return `${elapsed} (avg ${humanDuration(res.average_seconds)})`;
}
