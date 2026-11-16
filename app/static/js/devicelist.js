// The devices a picker offers (name and address), asked for once a minute at most. A customer view may not list devices: then the list is empty.
import { get } from "./api.js";

let cache = null;
export async function loadDevices() {
  if (cache && Date.now() - cache.at < 60000) return cache.list;
  let list = [];
  try {
    list = (await get("/api/map")).nodes.filter((n) => !String(n.id).startsWith("v")).map((n) => ({ id: n.id, name: n.label || n.ip || `device ${n.id}`, ip: n.ip, type: n.type }));
  } catch (err) {
    list = [];
  }
  list.sort((a, b) => a.name.localeCompare(b.name));
  cache = { at: Date.now(), list };
  return list;
}

export const deviceLabel = (d) => d.name + (d.ip ? ` (${d.ip})` : "");
