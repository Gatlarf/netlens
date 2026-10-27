// The start page: a grid of cards. Which cards, in what order and the cards a user made are a per-user choice kept on the server.
import { get, put, del } from "../api.js";
import { h, clear, patch, timeAgo, shortName, isAdmin, sessionInfo, toast } from "../util.js";
import { eventLabel } from "../event_labels.js";
import { barList, columnChart, emptyNote, fmtPct, lineChart } from "../charts.js";
import { cssVar } from "../theme.js";
import { big, customCard, linkList, pluginCard, plural, rows, sparkline, toneUp } from "../dashboard_cards.js";
import { openEditor } from "../dashboard_editor.js";
import { layoutHorizontal } from "../layout_horizontal.js";
import { buildHealthCard, healthTone } from "../cards/health_map.js";
import { buildCapacityCard, capacityTone } from "../cards/capacity.js";
import { snoozeMenu, snoozedList } from "../snooze.js";
import { WIDGETS as STAT_WIDGETS } from "./overview.js";
import { controlBar, dragCard, nextSize, openDrawer } from "../board.js";

const REFRESH_MS = 30000;
const KINDS = {
  device_new: "New device", device_online: "Came online", device_offline: "Went offline", device_changed: "Changed", port_opened: "Port opened",
  port_closed: "Port closed", wifi_roamed: "Roamed", login_failed: "Failed sign-ins", cert_expiring: "Certificate", service_down: "Service down", service_up: "Service up",
  llm_model_unavailable: "Language model unavailable", plugin_updated: "Plugin updated", plugin_update_failed: "Plugin update failed", plugin_update_skipped: "Plugin update held back",
  metric_warning: "Health warning", metric_critical: "Health critical", metric_ok: "Health normal", capacity_warning: "Disk filling up", capacity_critical: "Disk almost full", anomaly: "Unusual reading",
  remote_new: "Remote: new device", remote_offline: "Remote: offline", remote_online: "Remote: online", remote_service_down: "Remote: service down", remote_service_up: "Remote: service up", remote_metric_warning: "Remote: health warning", remote_metric_critical: "Remote: health critical", remote_metric_ok: "Remote: health normal", probe_offline: "Remote site silent", probe_online: "Remote site reporting",
};
const kindText = (k) => KINDS[k] || eventLabel(k);
// ---------- the cards ----------
// size: s = one column, w = two, f = the whole row. show(d): has this installation anything for the card? `def` = on the default dashboard.

const CARDS = [
  { id: "devices", title: "Devices online", href: "#/devices", size: "s", def: true, about: "How many devices answer right now, with the 14-day trend.",
    tone: (d) => (d.summary.devices.offline === 0 ? "ok" : ""),
    build: ({ summary: s, trend }) => big(`${s.devices.online} / ${s.devices.total}`, `${s.devices.offline} offline · ${s.devices.new_24h} new today`, { spark: sparkline(trend.map((t) => t.online)) }) },
  { id: "uptime", title: "Uptime", href: "#/uptime", size: "s", def: true, about: "Share of device checks that succeeded: the always-on (core) devices and all devices, over 24 hours, 7 days and 30 days.",
    tone: (d) => toneUp(d.summary.core && d.summary.core.devices ? d.summary.core.uptime["24h"] : d.summary.uptime["24h"]),
    build: ({ summary: s, trend }) => {
      const core = s.core && s.core.devices ? s.core : null, all = s.uptime;
      const pair = (u) => h("div", { class: "d-three" }, [["7 days", u["7d"]], ["30 days", u["30d"]]].map(([label, v]) => h("div", {}, h("small", {}, label), h("strong", { class: `d-${toneUp(v) || "ok"}` }, fmtPct(v)))));
      if (!core) {   // nothing marked yet: all devices, with a nudge
        return big(fmtPct(all["24h"]), "all devices, last 24 hours", { spark: sparkline(trend.map((t) => (t.devices ? (t.online / t.devices) * 100 : null))), extra: [pair(all),
          h("div", { class: "d-mini" }, h("a", { href: "#/uptime" }, "Mark your always-on devices"), " to see them apart from phones and tablets.")] });
      }
      return big(fmtPct(core.uptime["24h"]), `${plural(core.devices, "always-on device")} · last 24 hours`, { extra: [
        pair(core.uptime),
        h("div", { class: "d-mini" }, `All devices: ${fmtPct(all["24h"])} · ${fmtPct(all["7d"])} · ${fmtPct(all["30d"])}`)] });
    } },
  { id: "speed", title: "Internet speed", href: "#/speedtest", size: "s", about: "The latest internet speed test: download, upload and delay.", show: (d) => !!d.speed,
    build: ({ speed: s }) => big(s.down_mbps >= 1000 ? `${(s.down_mbps / 1000).toFixed(2)} Gbps` : `${Math.round(s.down_mbps)} Mbps`, `down · up ${Math.round(s.up_mbps)} Mbps · ping ${Math.round(s.latency_ms)} ms`, { extra: h("div", { class: "d-mini" }, timeAgo(s.ts)) }) },
  { id: "flapping", title: "Unstable devices", href: "#/uptime", size: "s", def: true, about: "Devices that keep going up and down: the always-on ones and the others apart, and the least reliable ones.",
    tone: (d) => ((d.summary.core && d.summary.core.devices ? d.summary.core.flapping : d.summary.devices.flapping) ? "warn" : "ok"),
    build: ({ summary: s, worst }) => {
      const core = s.core && s.core.devices ? s.core : null, others = s.devices.flapping - (core ? core.flapping : 0);
      const lowest = worst.length ? h("div", { class: "d-mini" }, "Lowest 7 days: ", worst.slice(0, 2).map((w, i) => [i ? ", " : "", h("a", { href: `#/device/${w.id}` }, shortName(w.name)), ` ${fmtPct(w.pct)}`])) : null;
      if (!core) return big(s.devices.flapping, s.devices.flapping === 1 ? "device flaps (24 hours)" : "devices flap (24 hours)", { extra: lowest });
      return big(core.flapping, core.flapping === 1 ? "always-on device flaps (24 hours)" : "always-on devices flap (24 hours)", { extra: [
        h("div", { class: "d-mini" }, `${others} other ${others === 1 ? "device flaps" : "devices flap"}`), lowest] });
    } },
  { id: "reliability", title: "Reliability", href: "#/insights", size: "w", def: true, about: "Outages of the things that matter (always-on and critical), the time it took to recover, availability against your target and how good the alerts were.",
    show: (d) => !!(d.reliability && d.reliability.watching && d.reliability.watching.devices + d.reliability.watching.services > 0),
    tone: (d) => (d.reliability.meets_target === false ? "bad" : d.reliability.devices.ongoing || d.reliability.services.ongoing ? "warn" : "ok"),
    build: ({ reliability: r }) => {
      const span = (sec) => (sec === null || sec === undefined ? "–" : sec < 90 ? `${sec} s` : sec < 5400 ? `${Math.round(sec / 60)} min` : `${(sec / 3600).toFixed(1)} h`);
      const outages = r.devices.outages + r.services.outages;
      const det = r.detection.device_seconds;
      return big(r.availability === null ? "–" : `${r.availability}%`, `availability of ${plural(r.watching.devices, "device")}, last ${r.days} days (target ${r.target}%)`, { extra: [
        h("div", { class: "d-three" }, [["outages", String(outages)], ["to recover (average)", span(r.mttr_seconds)], ["longest", span(Math.max(r.devices.longest_seconds || 0, r.services.longest_seconds || 0) || null)]].map(([label, v]) => h("div", {}, h("small", {}, label), h("strong", {}, v)))),
        h("div", { class: "d-mini" }, `Noticed within ${det ? span(det) : "the next scan"} · ${r.alerts.noise_percent === null ? "no alerts cleared yet" : `${r.alerts.noise_percent}% of the outages cleared within 5 minutes`}`)] });
    } },
  { id: "services", title: "Services", href: "#/services", size: "s", def: true, about: "Your HTTP, port and DNS checks.",
    show: (d) => d.summary.services.total > 0, tone: (d) => (d.summary.services.down ? "bad" : "ok"),
    build: ({ summary: s, services_down: down }) => big(`${s.services.up} / ${s.services.up + s.services.down}`, s.services.down ? `down: ${down.slice(0, 2).join(", ")}${down.length > 2 ? "…" : ""}` : "all up") },
  { id: "containers", title: "Containers & guests", href: "#/devices", size: "s", about: "Containers, and separately the virtual machines and LXCs, on your hosts.",
    show: (d) => d.summary.containers.total + d.summary.guests.total > 0,
    tone: (d) => (d.summary.containers.unhealthy || d.summary.containers.restarting ? "warn" : "ok"),
    build: ({ summary: s }) => {
      const bk = s.guests.by_kind || {};
      const sum = (kinds) => kinds.reduce((a, k) => ({ running: a.running + ((bk[k] || {}).running || 0), total: a.total + ((bk[k] || {}).total || 0) }), { running: 0, total: 0 });
      const ctr = sum(["container", "app"]);
      const vms = { running: s.guests.running - ctr.running, total: s.guests.total - ctr.total };
      const warn = s.containers.unhealthy || s.containers.restarting ? h("div", { class: "d-mini d-warn" }, `${s.containers.unhealthy} unhealthy · ${s.containers.restarting} restarting`) : null;
      return big(`${ctr.running} / ${ctr.total}`, `containers running on ${plural(s.guests.hosts, "host")}`, {
        extra: [h("div", { class: "d-mini" }, `${vms.running} / ${vms.total} virtual machines and LXCs running`), warn] });
    } },
  { id: "guestbackups", title: "Guest backups", href: "#/backups", size: "s", def: true, about: "Which guests have a backup, and whether the newest ones worked (needs a backup plugin).",
    show: (d) => !!(d.summary.guest_backups && d.summary.guest_backups.configured),
    tone: (d) => { const g = d.summary.guest_backups; return g.failed ? "bad" : g.late || g.unprotected || g.stores_at_risk ? "warn" : "ok"; },
    build: ({ summary: s }) => { const g = s.guest_backups;
      const notes = [g.failed ? `${g.failed} failed` : null, g.late ? `${g.late} late` : null, g.unprotected ? `${g.unprotected} without a backup` : null, g.stores_at_risk ? `${g.stores_at_risk} store filling up` : null].filter(Boolean);
      return big(`${g.protected} / ${g.guests}`, "guests have a backup", { extra: [h("div", { class: `d-mini${notes.length ? " d-warn" : ""}` }, notes.length ? notes.join(" · ") : "all up to date"),
        g.newest ? h("div", { class: "d-mini" }, `newest backup ${timeAgo(g.newest)}`) : null] }); } },
  { id: "storage", title: "Storage", href: "#/storage?focus=problems", size: "s", def: true, about: "Your storage systems: health, the fullest pool, failed disks and open alerts (needs a storage plugin).",
    show: (d) => !!(d.summary.storage && d.summary.storage.configured),
    tone: (d) => { const g = d.summary.storage; return g.unhealthy || g.failed_disks ? "bad" : g.pools_filling || g.alerts ? "warn" : "ok"; },
    build: ({ summary: s }) => { const g = s.storage;
      const notes = [g.unhealthy ? `${g.unhealthy} not healthy` : null, g.failed_disks ? `${g.failed_disks} failed disk${g.failed_disks === 1 ? "" : "s"}` : null, g.pools_filling ? `${g.pools_filling} pool${g.pools_filling === 1 ? "" : "s"} filling up` : null, g.alerts ? `${g.alerts} alert${g.alerts === 1 ? "" : "s"}` : null].filter(Boolean);
      return big(`${g.systems - g.unhealthy} / ${g.systems}`, `storage system${g.systems === 1 ? "" : "s"} healthy`, { extra: [h("div", { class: `d-mini${notes.length ? " d-warn" : ""}` }, notes.length ? notes.join(" · ") : `${g.pools} pools · ${g.disks} disks · all fine`)] }); } },
  { id: "sites", title: "Sites & certificates", href: "#/stats", size: "s", about: "Reverse-proxy sites and when their certificates end.",
    show: (d) => d.summary.sites.total > 0,
    tone: (d) => (d.summary.sites.down || d.summary.sites.certificates_expired ? "bad" : d.summary.sites.certificates_expiring ? "warn" : "ok"),
    build: ({ summary: s }) => big(s.sites.total, `sites${s.sites.down ? ` · ${s.sites.down} down` : ""}${s.sites.next_expiry_days === null ? "" : ` · next certificate ends in ${plural(s.sites.next_expiry_days, "day")}`}`) },
  { id: "plugins", title: "Plugins", href: "#/settings/plugins", size: "s", about: "Plugins that are switched on, and whether they work.",
    show: (d) => d.summary.plugins.some((p) => p.enabled),
    tone: (d) => (d.summary.plugins.some((p) => p.enabled && p.ok === false) ? "bad" : "ok"),
    build: ({ summary: s }) => {
      const on = s.plugins.filter((p) => p.enabled), failing = on.filter((p) => p.ok === false);
      return big(`${on.length - failing.length} / ${on.length}`, failing.length ? `failing: ${failing.map((p) => p.id).join(", ")}` : "working", {
        extra: s.update.plugin_updates ? h("div", { class: "d-mini" }, plural(s.update.plugin_updates, "update"), " available") : null });
    } },
  { id: "backup", title: "Backup & scans", href: "#/scans", size: "s", about: "When the last backup and the last scan finished.",
    tone: (d) => (d.summary.backup.last_ok === false || d.summary.scans.last?.status === "failed" ? "bad" : "ok"),
    build: ({ summary: s }) => {
      const last = s.scans.last;
      return rows([
        ["Backup", s.backup.last_at ? timeAgo(s.backup.last_at) : s.backup.enabled ? "not yet" : "off", s.backup.last_ok === false ? "bad" : ""],
        ["Last scan", last ? `${last.kind} · ${timeAgo(last.finished)}` : "never", last?.status === "failed" ? "bad" : ""],
        ["Found", last ? plural(last.hosts_found, "host") : "–"],
      ]);
    } },
  { id: "dns", title: "DNS & network checks", href: "#/dns", size: "s", about: "Names registered in your DNS server and the DHCP server check.",
    show: (d) => d.summary.dns.registered + d.summary.dns.pending + d.summary.dns.conflicts > 0 || d.summary.netchecks.enabled,
    tone: (d) => (d.summary.dns.conflicts || d.summary.netchecks.untrusted ? "warn" : "ok"),
    build: ({ summary: s }) => rows([
      ["Registered", s.dns.registered], ["Waiting to register", s.dns.pending, s.dns.pending ? "warn" : ""], ["Conflicts", s.dns.conflicts, s.dns.conflicts ? "warn" : ""],
      ["DHCP servers", !s.netchecks.enabled ? "check is off" : !s.netchecks.last_run ? "not checked yet" : `${s.netchecks.dhcp_servers}${s.netchecks.untrusted ? ` (${s.netchecks.untrusted} untrusted)` : ""}`, s.netchecks.untrusted ? "bad" : ""],
    ]) },
  { id: "security", title: "Security", href: "#/scans", size: "s", about: "Failed sign-ins, devices you have not approved and new versions.",
    tone: (d) => (d.login_failed_24h ? "warn" : "ok"),
    build: ({ summary: s, login_failed_24h: lf }) => rows([
      ["Failed sign-in bursts (24 h)", lf, lf ? "warn" : ""], ["Unknown devices", s.devices.unknown, s.devices.unknown ? "warn" : ""],
      ["New devices (7 days)", s.devices.new_7d], ["Update", s.update.available ? s.update.latest : "up to date", s.update.available ? "warn" : ""],
    ]) },
  { id: "infra", title: "Infrastructure", href: "#/devices", size: "s", about: "Containers, virtual machines, proxy sites and certificates, plugins and backups in one card.",
    show: (d) => d.summary.containers.total + d.summary.guests.total + d.summary.sites.total > 0 || d.summary.plugins.some((p) => p.enabled),
    tone: (d) => { const s = d.summary, g = s.guest_backups, on = s.plugins.filter((p) => p.enabled);
      return s.sites.down || s.sites.certificates_expired || on.some((p) => p.ok === false) || (g && g.failed) || s.backup.last_ok === false ? "bad"
        : s.containers.unhealthy || s.containers.restarting || s.sites.certificates_expiring || (g && (g.late || g.unprotected)) ? "warn" : "ok"; },
    build: ({ summary: s }) => {
      const bk = s.guests.by_kind || {};
      const sum = (kinds) => kinds.reduce((a, k) => ({ running: a.running + ((bk[k] || {}).running || 0), total: a.total + ((bk[k] || {}).total || 0) }), { running: 0, total: 0 });
      const ctr = sum(["container", "app"]), vms = { running: s.guests.running - ctr.running, total: s.guests.total - ctr.total };
      const on = s.plugins.filter((p) => p.enabled), failing = on.filter((p) => p.ok === false), g = s.guest_backups;
      const list = [];
      if (ctr.total) list.push(["Containers", `${ctr.running} / ${ctr.total} running${s.containers.unhealthy || s.containers.restarting ? ` · ${s.containers.unhealthy + s.containers.restarting} to check` : ""}`, s.containers.unhealthy || s.containers.restarting ? "warn" : ""]);
      if (vms.total) list.push(["Virtual machines", `${vms.running} / ${vms.total} running`]);
      if (s.sites.total) list.push(["Sites", s.sites.down ? `${s.sites.total} · ${s.sites.down} down` : String(s.sites.total), s.sites.down ? "bad" : ""]);
      if (s.sites.next_expiry_days !== null) list.push(["Next certificate", s.sites.next_expiry_days < 0 ? "expired" : `ends in ${plural(s.sites.next_expiry_days, "day")}`, s.sites.certificates_expired ? "bad" : s.sites.certificates_expiring ? "warn" : ""]);
      if (g && g.configured) list.push(["Guest backups", `${g.protected} / ${g.guests} protected${g.failed ? ` · ${g.failed} failed` : g.late ? ` · ${g.late} late` : ""}`, g.failed ? "bad" : g.late || g.unprotected ? "warn" : ""]);
      list.push(["Netlens backup", s.backup.last_at ? timeAgo(s.backup.last_at) : s.backup.enabled ? "not yet" : "off", s.backup.last_ok === false ? "bad" : ""]);
      if (on.length) list.push(["Plugins", failing.length ? `${failing.length} of ${on.length} failing: ${failing.map((p) => p.id).join(", ")}` : `${on.length} working`, failing.length ? "bad" : ""]);
      return rows(list);
    } },
  { id: "vulns", title: "Vulnerabilities", href: "#/vulnerabilities", size: "s", def: true, about: "What the vulnerability scanner found, worst first.",
    show: (d) => !!(d.summary.vulns && d.summary.vulns.allowed && d.summary.vulns.configured),
    tone: (d) => { const c = d.summary.vulns.counts; return c.critical ? "bad" : c.high || d.summary.vulns.exploited ? "warn" : "ok"; },
    build: ({ summary: s }) => { const c = s.vulns.counts;
      return rows([["Critical", c.critical, c.critical ? "bad" : ""], ["High", c.high, c.high ? "warn" : ""], ["Medium", c.medium], ["Known to be exploited", s.vulns.exploited, s.vulns.exploited ? "bad" : ""], ["Devices at risk", s.vulns.devices]]); } },
  { id: "attention", title: "Needs attention", size: "w", def: true, about: "Everything that is wrong or worth a look, worst first.",
    tone: (d) => (d.attention.some((a) => a.level === "bad") ? "bad" : d.attention.some((a) => a.level === "warn") ? "warn" : "ok"),
    build: ({ attention, snoozed }) => h("div", {},
      attention.length
        ? h("ul", { class: "d-attention" }, attention.map((a) => h("li", { class: `d-${a.level}` }, h("a", { href: a.href }, a.text), a.snooze ? " " : null, snoozeMenu(a.snooze))))
        : h("p", { class: "d-quiet" }, snoozed && snoozed.length ? "All quiet. What you snoozed is below." : "All quiet. Nothing needs your attention."),
      snoozedList(snoozed)) },
  { id: "health", title: "Health", href: "#/health", size: "w", def: true, about: "A heat-map of the devices whose health is monitored (processor, memory, disk), with what is past a limit.",
    show: (d) => !!d.health && d.health.monitors.some((m) => m.enabled), tone: (d) => healthTone(d.health.monitors, d.health.problems),
    build: ({ health }) => buildHealthCard(health) },
  { id: "capacity", title: "Running out soon", href: "#/health", size: "s", def: true, about: "Disks that are filling up, with the day they will be full, worked out from how fast they have grown.",
    show: (d) => !!d.capacity && d.capacity.items.length > 0, tone: (d) => capacityTone(d.capacity),
    build: ({ capacity }) => buildCapacityCard(capacity) },
  { id: "events", title: "Recent events", href: "#/scans", size: "w", def: true, about: "The latest things that happened on the network.",
    build: ({ events }) => (events.length ? h("ul", { class: "d-events" }, events.slice(0, 8).map((e) => h("li", {},
      h("span", { class: "d-time" }, timeAgo(e.ts)), h("span", { class: "d-kind" }, kindText(e.kind)),
      e.device_id ? h("a", { href: `#/device/${e.device_id}` }, shortName(e.device) || `device ${e.device_id}`) : null))) : emptyNote("No events yet.")) },
  { id: "minimap", title: "Map", href: "#/map", size: "f", about: "A small picture of your network. Click it to open the full map.", tall: true, build: null },

  // not on the default dashboard, added by the user
  { id: "worst", title: "Least reliable devices", href: "#/uptime", size: "s", def: true, about: "The five devices that were down most in the last 7 days.",
    build: ({ worst }) => (worst.length ? barList(worst.map((w) => ({ label: shortName(w.name), count: Math.round(100 - w.pct), href: `#/device/${w.id}` })), { unit: "% down" }) : emptyNote("Every device was up all week.")) },
  { id: "trend", title: "Devices online, 14 days", href: "#/stats", size: "w", def: true, about: "How many devices were online, day by day.",
    build: ({ trend }) => lineChart(trend.map((t) => ({ x: t.day.slice(5), online: t.online, total: t.devices })), [{ key: "online", label: "Online" }, { key: "total", label: "Known" }], { height: 130 }) },
  { id: "eventsday", title: "Events per day", href: "#/scans", size: "w", about: "How busy the network was, 14 days.",
    build: ({ trend }) => (trend.length ? columnChart(trend.map((t) => ({ x: t.day.slice(5), v: t.events })), { height: 90 }) : emptyNote()) },
  { id: "types", title: "Device types", href: "#/devices", size: "s", about: "What kinds of devices you have.",
    build: ({ summary: s }) => {
      const counts = {};
      s.device_list.forEach((d) => { counts[d.type || "unknown"] = (counts[d.type || "unknown"] || 0) + 1; });
      return barList(Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([label, count]) => ({ label, count })));
    } },
  { id: "groups", title: "Groups", href: "#/devices", size: "s", about: "Online devices per group.", show: (d) => d.summary.device_list.some((x) => x.group),
    build: ({ summary: s }) => {
      const g = {};
      s.device_list.forEach((d) => { const k = d.group || "(no group)"; g[k] = g[k] || [0, 0]; g[k][1] += 1; if (d.online) g[k][0] += 1; });
      return rows(Object.entries(g).sort((a, b) => b[1][1] - a[1][1]).slice(0, 6).map(([k, [on, all]]) => [k, `${on} / ${all}`, on < all ? "" : "ok"]));
    } },
  { id: "wifi", title: "Wi-Fi", href: "#/stats", size: "s", about: "Wi-Fi clients and signal strength.", show: (d) => d.summary.wifi.clients > 0,
    build: ({ summary: s }) => big(s.wifi.clients, `clients · average ${s.wifi.avg_rssi ?? "–"} dBm${s.wifi.weak ? ` · ${s.wifi.weak} weak` : ""}`) },
  { id: "newdevices", title: "New devices", href: "#/devices", size: "s", about: "Devices first seen in the last 7 days.",
    build: ({ new_devices: n }) => (n.length ? linkList(n.map((x) => ({ text: shortName(x.name), href: `#/device/${x.id}`, note: timeAgo(x.first_seen) }))) : emptyNote("Nothing new this week.")) },
  { id: "certs", title: "Certificates", href: "#/stats", size: "s", about: "The certificates that end first.", show: (d) => d.certificates.length > 0,
    build: ({ certificates: c }) => linkList(c.map((x) => ({ text: x.name, note: x.days < 0 ? "expired" : `${x.days} d`, tone: x.days < 0 ? "bad" : x.days <= 14 ? "warn" : "" }))) },
  { id: "updates", title: "Updates available", href: "#/settings/about", size: "s", about: "Newer container images and Netlens or plugin versions.",
    build: ({ summary: s }) => rows([
      ["Container images", s.guests.image_updates || 0, s.guests.image_updates ? "warn" : ""], ["Hosts with updates", s.guests.update_available || 0],
      ["Netlens", s.update.available ? s.update.latest : "up to date", s.update.available ? "warn" : ""], ["Plugins", s.update.plugin_updates, s.update.plugin_updates ? "warn" : ""],
    ]) },
  { id: "actions", title: "Quick actions", size: "s", admin: true, about: "Start a scan with one tap.",
    build: () => h("div", { class: "d-actions" },
      h("button", { class: "btn primary", type: "button", onclick: () => document.getElementById("scan-quick")?.click() }, "Quick scan"),
      h("button", { class: "btn", type: "button", onclick: () => document.getElementById("scan-deep")?.click() }, "Deep scan")) },
];
// The statistic widgets of the former Overview page are cards too (last 7 days, drawn from /api/stats); they are not on the default dashboard.
for (const w of STAT_WIDGETS) {
  CARDS.push({ id: `ov-${w.id}`, title: w.title, size: w.span >= 3 ? "f" : w.span === 2 ? "w" : "s", about: "A statistic over the last 7 days.", stat: true,
    show: (d) => !!d.stats, build: (d) => h("div", { class: "mk-body" }, w.draw(d.stats)) });
}
const TYPE_ABOUT = { value: "A value from your data", device: "A device", group: "A group of devices", service: "A service check", notes: "Notes and links" };
const FIRST_VIEW = ["attention", "devices", "uptime", "services", "reliability", "health", "flapping", "storage", "guestbackups", "vulns", "events", "worst", "trend", "capacity"];   // the order a new installation starts with
const DEFAULT_ORDER = [...FIRST_VIEW.filter((id) => CARDS.some((c) => c.id === id && c.def)), ...CARDS.filter((c) => c.def && !FIRST_VIEW.includes(c.id)).map((c) => c.id)];

// ---------- the chosen layout (per user, kept on the server so every browser and device shows the same dashboard) ----------
// The browser's own storage is only the fallback (and where an older version kept the layout): it is moved to the server once.

const storageKey = () => `netlens.dashboard.${sessionInfo()?.username || "default"}`;
const EMPTY = { order: null, custom: [] };

function localLayout() {
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey()) || "null");
    if (Array.isArray(saved)) return { order: saved, custom: [] };           // how an older version stored it
    if (saved && Array.isArray(saved.order)) return { order: saved.order, custom: Array.isArray(saved.custom) ? saved.custom : [] };
  } catch (e) {
    // no storage or damaged
  }
  return null;
}

function setLocal(layout) {
  try {
    if (layout) localStorage.setItem(storageKey(), JSON.stringify(layout));
    else localStorage.removeItem(storageKey());
  } catch (e) {
    // the choice then lasts until the page is closed
  }
}

// The administrator's dashboard for everybody (null while there is none). Whoever has not arranged their own sees this one.
async function loadDefault() {
  try {
    const d = await get("/api/dashboard/default");
    if (Array.isArray(d.order)) return { order: d.order, custom: d.custom || [] };
  } catch (e) {
    // an older server: the built-in cards
  }
  return null;
}

// The cards an administrator shared with everybody (they are added from the pool like the built-in ones)
async function loadLibrary() {
  try {
    return (await get("/api/dashboard/shared")).cards || [];
  } catch (e) {
    return [];
  }
}

async function loadLayout(shared, pending = null) {
  let server = EMPTY, reachable = true;
  try {
    server = await (pending || get("/api/dashboard/layout"));
  } catch (e) {
    reachable = false;
  }
  if (Array.isArray(server.order)) return { order: server.order, custom: server.custom || [], sizes: server.sizes || {}, own: true };
  const local = localLayout();
  if (local) {
    if (reachable) {  // a layout from before it was kept on the server: move it there
      try { await put("/api/dashboard/layout", local); setLocal(null); } catch (e) { /* stays in the browser */ }
    }
    return { ...local, sizes: local.sizes || {}, own: true };
  }
  return shared ? { order: [...shared.order], custom: [...shared.custom], sizes: { ...(shared.sizes || {}) }, own: false } : { order: [...DEFAULT_ORDER], custom: [], sizes: {}, own: false };
}

// reset: go back to what the administrator set (or the built-in cards); the layout of this user is then removed
async function saveLayout(layout, reset) {
  try {
    if (reset) await del("/api/dashboard/layout");
    else await put("/api/dashboard/layout", layout);
    setLocal(null);
  } catch (e) {
    if (e && e.status === 422) throw e;   // the server refused the layout itself: nothing is kept, the window shows why
    setLocal(reset ? null : layout);      // for example the demo, where nothing may be saved on the server
  }
}

// ---------- the mini map ----------

function loadVis() {
  if (window.vis) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const script = document.querySelector('script[src="vendor/vis-network.min.js"]') || Object.assign(document.createElement("script"), { src: "vendor/vis-network.min.js" });
    script.addEventListener("load", () => resolve());
    script.addEventListener("error", () => reject(new Error("The map library could not be loaded.")));
    if (!script.parentNode) document.head.appendChild(script);
  });
}

// the Map page spaces its cards far apart; the small map packs the same layout tighter so it fills the card
const squeeze = (p) => (p ? { x: p.x * 1.3, y: p.y * 0.34 } : {});

function miniMap() {
  const box = h("div", { class: "d-map", "aria-label": "Map of the network" });
  let network = null, nodes = null;
  const colors = () => ({ on: cssVar("--ok", "#16a34a"), off: cssVar("--muted", "#94a3b8"), edge: cssVar("--border", "#cbd5e1") });
  const paint = (device) => { const c = colors(); return { color: { background: device.online ? c.on : c.off, border: device.online ? c.on : c.off } }; };

  async function load() {
    try {
      const [data] = await Promise.all([get("/api/map"), loadVis()]);
      // the same left-to-right layout as the Map page: the top device on the left, every level a column to its right
      const parents = data.edges.filter((e) => e.kind === "parent");
      const parentOf = new Map(parents.map((e) => [e.to, e.from]));
      const ids = new Set(data.nodes.map((n) => n.id));
      const where = layoutHorizontal(data.nodes.map((n) => ({ id: n.id, parent_id: ids.has(parentOf.get(n.id)) ? parentOf.get(n.id) : null }))).positions;
      const list = data.nodes.map((n) => ({ id: n.id, title: `${shortName(n.label)}${n.online ? "" : " (offline)"}`, shape: "dot", size: n.online ? 9 : 7, ...paint(n), ...squeeze(where.get(n.id)) }));
      const edges = parents.map((e) => ({ from: e.from, to: e.to, color: { color: colors().edge } }));
      if (!network) {
        nodes = new window.vis.DataSet(list);
        network = new window.vis.Network(box, { nodes, edges: new window.vis.DataSet(edges) }, {
          physics: false, interaction: { dragNodes: false, dragView: false, zoomView: false, hover: true },
          edges: { smooth: { type: "cubicBezier", forceDirection: "horizontal", roundness: 0.5 }, width: 1 }, nodes: { borderWidth: 0 },
        });
        network.on("click", (p) => { location.hash = p.nodes.length && Number.isInteger(p.nodes[0]) ? `#/device/${p.nodes[0]}` : "#/map"; });
        network.once("afterDrawing", () => network.fit({ animation: false }));
      } else {
        nodes.update(list.map((n) => ({ id: n.id, size: n.size, color: n.color, title: n.title, x: n.x, y: n.y })));
        network.redraw();
        network.fit({ animation: false });
      }
    } catch (err) {
      box.replaceChildren(h("p", { class: "hint" }, err.message || "The map could not be loaded."));
    }
  }
  return { box, load, destroy: () => { if (network) network.destroy(); network = null; } };
}

// ---------- the page ----------

export async function render(container) {
  // the three requests do not depend on each other: ask for them together (one round trip instead of three, which matters over the internet)
  const layoutRequest = get("/api/dashboard/layout");
  layoutRequest.catch(() => {});
  const [shared, library0] = await Promise.all([loadDefault(), loadLibrary()]);
  const layout = await loadLayout(shared, layoutRequest);
  let library = library0;
  const base = () => (shared ? { order: shared.order, custom: shared.custom, sizes: shared.sizes || {} } : { order: DEFAULT_ORDER, custom: [], sizes: {} });
  let data = null, order = layout.order, custom = layout.custom, sizes = { ...(layout.sizes || {}) }, own = layout.own, editing = false, disposed = false, timer = null, drawerApi = null;
  const map = miniMap();
  let mapStarted = false;
  const header = h("div", { class: "dash-head" });
  const grid = h("div", { class: "dash-grid" });
  const nudge = h("div", {});
  container.append(nudge, header, grid);
  // administrators who have not been through the getting-started guide (or closed it halfway) get a one-line invitation
  if (isAdmin()) {
    get("/api/wizard").then((w) => {
      if (disposed || !w || w.status === "done" || w.status === "dismissed") return;
      nudge.append(h("div", { class: "card wiz-banner", id: "wizard-nudge" },
        h("p", {}, h("strong", {}, "Finish setting up Netlens. "), "A short guide walks through the settings that matter: networks, alerts, always-on devices and checks."),
        h("span", { class: "wiz-nav-end" },
          h("a", { class: "btn primary", href: "#/wizard" }, w.status === "pending" ? "Continue the guide" : "Open the guide"),
          h("button", { class: "btn", type: "button", onclick: async () => {
            try { await put("/api/wizard", { status: "dismissed" }); } catch (err) { /* hidden anyway */ }
            clear(nudge);
          } }, "Not now"))));
    }).catch(() => {});
  }

  const visible = (card) => !card.admin || isAdmin();
  const hasData = (card) => !card.show || card.show(data);
  // every card there can be right now: the built-in ones, those of the enabled plugins and the ones this user made
  const registry = () => {
    const all = new Map(CARDS.map((c) => [c.id, c]));
    for (const pc of data ? data.plugin_cards || [] : []) { const c = pluginCard(pc); all.set(c.id, c); }
    for (const def of library) { const c = customCard(def, data); c.shared = true; all.set(c.id, c); }
    for (const def of custom) { const c = customCard(def, data); all.set(c.id, c); }        // your own copy wins over a shared one
    return all;
  };
  const byId = (id) => registry().get(id);

  async function persist() {
    const known = registry();
    order = order.filter((id) => known.has(id) || !data);                      // a card of a plugin that is switched off is dropped
    try {
      const b = base();
      sizes = Object.fromEntries(Object.entries(sizes).filter(([id]) => order.includes(id)));
      own = !(!custom.length && !b.custom.length && order.length === b.order.length && order.every((id, i) => id === b.order[i]) && JSON.stringify(sizes) === JSON.stringify(b.sizes || {}));
      await saveLayout({ order, custom, sizes }, !own);
    } catch (e) {
      toast(e.message || "Could not save the dashboard", "error");
    }
  }
  const isShared = (id) => library.some((c) => c.id === id) && !custom.some((c) => c.id === id);
  async function saveLibrary(next) {
    await put("/api/dashboard/shared", { cards: next });
    library = next;
  }
  function edit(def) {
    if (def && isShared(def.id)) {                                               // a shared card: changing it changes it for everybody
      if (!isAdmin()) return;
      openEditor({ def, data, onSave: async (saved) => {
        await saveLibrary(library.map((c) => (c.id === saved.id ? saved : c)));
        draw();
      } });
      return;
    }
    openEditor({ def, data, onSave: async (saved) => {
      const next = custom.some((c) => c.id === saved.id) ? custom.map((c) => (c.id === saved.id ? saved : c)) : [...custom, saved];
      const placed = order.includes(saved.id) ? order : [...order, saved.id];
      await saveLayout({ order: placed, custom: next }, false);   // the server checks the card; a mistake shows in the window
      custom = next; order = placed; own = true;
      draw();
    } });
  }
  function deleteCard(id) {
    custom = custom.filter((c) => c.id !== id);
    order = order.filter((x) => x !== id);
    persist();
    draw();
  }
  // administrators: move one of their own cards into the shared library (everybody can then add it) and back
  async function shareCard(def) {
    try {
      await saveLibrary([...library, def]);
      custom = custom.filter((c) => c.id !== def.id);
      await persist();
      toast("Everybody can now add this card from their card pool", "success");
    } catch (e) {
      toast(e.message || "Could not share the card", "error");
    }
    draw();
  }
  async function unshareCard(def) {
    try {
      await saveLibrary(library.filter((c) => c.id !== def.id));
      custom = [...custom, def];
      await persist();
    } catch (e) {
      toast(e.message || "Could not stop sharing the card", "error");
    }
    draw();
  }
  async function deleteShared(def) {
    try {
      await saveLibrary(library.filter((c) => c.id !== def.id));
      order = order.filter((x) => x !== def.id);
      await persist();
    } catch (e) {
      toast(e.message || "Could not delete the card", "error");
    }
    draw();
  }

  let mapCard = null;                // the map card is kept as it is: the map inside it updates itself
  function cardEl(card) {
    const tone = card.tone ? card.tone(data) : "";
    const empty = !hasData(card);
    const title = h("h2", { class: "d-title" }, card.href && !editing ? h("a", { href: card.href }, card.title) : card.title);
    const head = h("div", { class: "d-head" }, title);
    const size = sizes[card.id] || card.size;
    if (editing) {
      const extra = [
        card.custom && (!card.shared || isAdmin()) ? h("button", { class: "bd-btn", type: "button", "aria-label": `Change ${card.title}`, title: "Change this card", onclick: () => edit(card.custom) }, "✎") : null,
        card.custom && !card.shared && isAdmin() ? h("button", { class: "bd-btn", type: "button", "aria-label": `Share ${card.title} with everyone`, title: "Share with everyone", onclick: () => shareCard(card.custom) }, "⇪") : null,
      ].filter(Boolean);
      head.append(controlBar({ size, extra,
        onGrip: (e) => dragCard(e, node, grid, (ids) => { order = [...ids, ...order.filter((x) => !ids.includes(x))]; persist(); }),
        onSize: () => { const next = nextSize(sizes[card.id] || card.size); if (next === card.size) delete sizes[card.id]; else sizes[card.id] = next; persist(); draw(); },
        onRemove: () => { order = order.filter((x) => x !== card.id); persist(); draw(); } }));
    }
    if (card.id === "minimap" && mapCard && mapCard.key === `${size}${tone}${editing}`) return mapCard.node;
    const body = card.id === "minimap" ? map.box : empty ? h("p", { class: "hint" }, "Nothing to show here yet: this card appears when it has something to report.") : card.build(data);
    const node = h("section", { class: `dcard size-${size} ${tone ? `tone-${tone}` : ""} ${card.href && !editing ? "linked" : ""} ${card.tall ? "tall" : ""} ${editing ? "editing bd-card" : ""}`, dataset: { card: card.id } }, head, body);
    if (card.id === "minimap") mapCard = { key: `${size}${tone}${editing}`, node };
    return node;
  }

  function drawHeader() {
    const a = data.attention, s = data.summary;
    const crit = a.filter((x) => x.level === "bad").length, bad = a.filter((x) => x.level !== "info").length;
    const tone = crit ? "bad" : bad ? "warn" : "ok";
    const verdict = crit ? `${plural(crit, "critical problem")}${bad > crit ? ` and ${plural(bad - crit, "warning")}` : ""}` : bad ? `${plural(bad, "thing")} need${bad === 1 ? "s" : ""} attention` : "Everything is running normally";
    const core = s.core && s.core.devices ? s.core.uptime["24h"] : s.uptime["24h"];
    const fact = (href, value, label, cls) => h("a", { href, class: "dash-fact" }, h("strong", { class: cls || "" }, value), ` ${label}`);
    const last = s.scans.last;
    header.className = `dash-hero tone-${tone}`;
    patch(header,
      h("div", { class: "dash-hero-main" }, h("h1", {}, "Dashboard"), h("p", { class: "dash-verdict" }, verdict),
        h("div", { class: "dash-facts" },
          fact("#/devices", `${s.devices.online} / ${s.devices.total}`, "devices online", s.devices.offline ? "d-warn" : ""),
          s.services.up + s.services.down > 0 ? fact("#/services", `${s.services.up} / ${s.services.up + s.services.down}`, "services up", s.services.down ? "d-bad" : "") : null,
          core === null || core === undefined ? null : fact("#/uptime", fmtPct(core), "uptime, 24 hours", `d-${toneUp(core) || "ok"}`),
          last ? fact("#/scans", timeAgo(last.finished), `last ${last.kind} scan`, last.status === "failed" ? "d-bad" : "") : null,
          h("span", { class: "dash-fact hint" }, `updated ${timeAgo(s.generated)}`)),
        shared && !own ? h("p", { class: "hint" }, "This is the starting dashboard set by your administrator. Press Customize to make it your own.") : null),
      h("div", { class: "dash-tools" },
        h("a", { class: "btn", href: "#/hud", title: "Full-screen live view for a wall display" }, "Wall screen"),
        h("button", { class: `btn ${editing ? "primary" : ""}`, type: "button", "aria-pressed": String(editing), onclick: () => { editing = !editing; draw(); } }, editing ? "Done" : "Customize")));
  }

  async function setForEveryone() {
    try {
      await put("/api/dashboard/default", { order, custom, sizes });
      toast("Saved. Everybody who has not arranged their own dashboard now sees this one.");
      location.reload();
    } catch (e) {
      toast(e.message || "Could not save the default dashboard", "error");
    }
  }
  async function clearForEveryone() {
    try {
      await del("/api/dashboard/default");
      toast("The built-in default is used again.");
      location.reload();
    } catch (e) {
      toast(e.message || "Could not remove the default dashboard", "error");
    }
  }
  async function resetMine() {
    const b = base();
    order = [...b.order]; custom = b.custom.map((c) => ({ ...c })); sizes = { ...(b.sizes || {}) }; own = false;
    try { await saveLayout(null, true); } catch (e) { toast(e.message || "Could not reset the dashboard", "error"); }
    draw();
  }

  // The drawer on the right (js/board.js): a tick box and a small picture for every card there is; ticking puts it on the dashboard.
  const KIND_OF = Object.fromEntries(STAT_WIDGETS.map((w) => [`ov-${w.id}`, w.kind]));
  const kindOf = (c) => KIND_OF[c.id] || (c.size === "f" ? "bars" : c.size === "w" ? "list" : "tiles");
  function drawDrawer() {
    if (!editing) { if (drawerApi) { const api = drawerApi; drawerApi = null; api.close(); } return; }
    const known = [...registry().values()].filter((c) => visible(c));
    const rows = known.map((c) => {
      const extra = [];
      if (c.custom && (!c.shared || isAdmin())) extra.push(h("button", { class: "btn", type: "button", onclick: () => edit(c.custom) }, "Change"));
      if (c.custom && !c.shared && isAdmin()) extra.push(h("button", { class: "btn", type: "button", title: "Let every user add this card to their dashboard", onclick: () => shareCard(c.custom) }, "Share"));
      if (c.custom && c.shared && isAdmin()) extra.push(h("button", { class: "btn", type: "button", title: "Take it out of the shared cards; it stays in your own cards", onclick: () => unshareCard(c.custom) }, "Stop sharing"));
      if (c.custom && (!c.shared || isAdmin())) extra.push(h("button", { class: "btn danger", type: "button", onclick: () => (c.shared ? deleteShared(c.custom) : deleteCard(c.id)) }, "Delete"));
      return { id: c.id, title: c.title, about: c.shared ? `${c.about || ""} Shared by your administrator.`.trim() : c.about, kind: kindOf(c), checked: order.includes(c.id), extra,
        onToggle: (on) => { order = on ? [...order.filter((x) => x !== c.id), c.id] : order.filter((x) => x !== c.id); persist(); draw(); } };
    });
    const head = [h("p", { class: "hint bd-pick" }, "Drag the grip on a card to move it, use ↔ for its width and ✕ to remove it. Tick a card here to put it on the dashboard."),
      h("button", { class: "btn bd-pick", type: "button", onclick: () => edit(null) }, "Create a card of your own")];
    if (!drawerApi) {
      const foot = [h("button", { class: "btn", type: "button", onclick: resetMine }, shared ? "Back to the default" : "Reset to default"),
        ...(isAdmin() ? [h("button", { class: "btn", type: "button", title: "Everybody who has not arranged their own dashboard will see this one", onclick: setForEveryone }, "Use as default for everyone"),
          shared ? h("button", { class: "btn", type: "button", title: "Back to the built-in default for everybody who has not arranged their own", onclick: clearForEveryone }, "Remove the default") : null] : [])].filter(Boolean);
      drawerApi = openDrawer({ title: "Customize the dashboard", head, rows, footer: foot, onClose: () => { if (drawerApi) { drawerApi = null; editing = false; if (!disposed) draw(); } } });
    } else {
      const footer = drawerApi.el.querySelector("footer");
      const keep = [...footer.children];
      drawerApi.update(rows, head);
      drawerApi.el.querySelector("footer").append(...keep.slice(1));        // the buttons after Done stay as they were
    }
  }

  let statsLoading = false;
  function needStats() {
    if (data.stats || statsLoading || !order.some((id) => id.startsWith("ov-"))) return;
    statsLoading = true;
    if (!document.getElementById("overview-css")) document.head.appendChild(h("link", { id: "overview-css", rel: "stylesheet", href: "css/overview.css" }));
    get("/api/stats?range=7d").then((st) => { data.stats = st; if (!disposed) draw(); }).catch(() => {}).finally(() => { statsLoading = false; });
  }

  function draw() {
    if (!data) return;
    needStats();
    drawHeader();
    grid.classList.toggle("editing", editing);
    const known = registry();
    const cards = [];
    for (const id of order) {
      const card = known.get(id);
      if (!card || !visible(card) || (!editing && !hasData(card))) continue;
      cards.push(cardEl(card));
    }
    if (!cards.length) cards.push(h("p", { class: "hint" }, "Your dashboard is empty. Press Customize to add cards."));
    patch(grid, cards);               // only the cards whose content changed are replaced, so nothing flickers on a refresh
    drawDrawer();
    if (order.includes("minimap") && !mapStarted) { mapStarted = true; map.load(); }
    else if (order.includes("minimap")) map.load();
  }

  async function refresh() {
    try {
      // everything the cards need, asked for at the same time; the extras may fail without hiding the dashboard
      const [main, health, capacity, reliability] = await Promise.all([
        get("/api/dashboard"),
        Promise.all([get("/api/monitors"), get("/api/monitoring/limits")]).then(([m, l]) => ({ monitors: m.monitors || [], problems: m.problems || [], rules: l.rules || {} }), () => null),   // an older server or no access: the card simply does not show
        get("/api/forecast").catch(() => null),
        get("/api/reliability?days=30").catch(() => null),
      ]);
      const keepStats = data && data.stats;
      data = main;
      if (keepStats) data.stats = keepStats;
      data.health = health;
      data.capacity = capacity;
      data.reliability = reliability;
      if (!disposed && !(editing && grid.children.length)) draw();
    } catch (err) {
      if (!data && !disposed) clear(grid), grid.append(h("p", { class: "error" }, err.message || "The dashboard could not be loaded."));
    }
  }

  grid.append(h("p", { class: "hint" }, "Loading…"));
  const onSnoozed = () => { if (!disposed) refresh(); };
  document.addEventListener("netlens:snoozed", onSnoozed);
  await refresh();
  timer = setInterval(() => { if (!editing && !document.hidden) refresh(); }, REFRESH_MS);
  return () => { disposed = true; clearInterval(timer); if (drawerApi) { const api = drawerApi; drawerApi = null; api.close(); } map.destroy(); document.removeEventListener("netlens:snoozed", onSnoozed); };
}
