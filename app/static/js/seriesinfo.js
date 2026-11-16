// How a measurement is named and shown (title, unit, fixed scale, limits). Anything not listed gets a plain graph.
const KNOWN = {
  rtt_ms: { title: "Response time", unit: "ms", order: 0 },
  response_ms: { title: "Response time", unit: "ms", order: 0 },
  up: { title: "Availability", unit: "state", order: 1 },
  cpu_pct: { title: "Processor", unit: "%", fixedMax: 100, warn: 85, crit: 95, order: 2 },
  load1: { title: "Load (1 minute)", unit: "", order: 3 },
  mem_pct: { title: "Memory in use", unit: "%", fixedMax: 100, warn: 85, crit: 95, order: 4 },
  swap_pct: { title: "Swap in use", unit: "%", fixedMax: 100, order: 5 },
  disk_pct: { title: "Disk used", unit: "%", fixedMax: 100, warn: 85, crit: 95, order: 6 },
  disk_free_b: { title: "Disk free", unit: "B", order: 6.5 },
  supply_pct: { title: "Supply left", unit: "%", fixedMax: 100, order: 11 },
  battery_pct: { title: "UPS battery", unit: "%", fixedMax: 100, order: 12 },
  battery_minutes: { title: "UPS runtime", unit: "min", order: 12.5 },
  on_battery: { title: "UPS on battery", unit: "state", order: 13 },
  net_rx_bps: { title: "Received", unit: "bps", order: 7 },
  net_tx_bps: { title: "Sent", unit: "bps", order: 8 },
  net_rx_pps: { title: "Received packets", unit: "pps", order: 7.1 },
  net_tx_pps: { title: "Sent packets", unit: "pps", order: 8.1 },
  if_util_pct: { title: "Port busy", unit: "%", fixedMax: 100, warn: 85, crit: 95, order: 8.5 },
  if_err_ps: { title: "Port errors", unit: "/s", warn: 1, crit: 10, order: 8.6 },
  if_up: { title: "Link", unit: "state", order: 8.7 },
  temp_c: { title: "Temperature", unit: "°C", order: 9 },
  ups_load_pct: { title: "UPS load", unit: "%", fixedMax: 100, warn: 80, crit: 95, order: 9.05 },
  fan_rpm: { title: "Fan speed", unit: "rpm", order: 9.1 },
  voltage_v: { title: "Voltage", unit: "V", order: 9.2 },
  sensor_fault: { title: "Fan or power supply", unit: "state", order: 9.3 },
  uptime_s: { title: "Time since start", unit: "s", order: 10 },
  cert_days: { title: "Certificate days left", unit: "days", order: 14 },
};

export function describeSeries(s) {
  const known = KNOWN[s.metric] || { title: s.metric.replace(/_/g, " "), unit: s.unit || "", order: 50 };
  return { ...known, title: s.label ? `${known.title} · ${s.label}` : known.title };
}

