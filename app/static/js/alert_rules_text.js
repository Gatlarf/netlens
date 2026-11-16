// A rule in a sentence. No DOM, so it is tested on its own (tests/test_js_logic.py).
const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

export function listOf(items, empty = "", joiner = "and") {
  if (!items.length) return empty;
  if (items.length === 1) return items[0];
  return `${items.slice(0, -1).join(", ")} ${joiner} ${items[items.length - 1]}`;
}

export function describeDays(days) {
  const d = [...days].sort((a, b) => a - b);
  if (d.length === 7) return "every day";
  if (d.join() === "0,1,2,3,4") return "Monday to Friday";
  if (d.join() === "5,6") return "at the weekend";
  // runs of days: Mon–Wed, Fri
  const parts = [];
  for (let i = 0; i < d.length;) {
    let j = i;
    while (j + 1 < d.length && d[j + 1] === d[j] + 1) j += 1;
    parts.push(j - i >= 2 ? `${DAYS[d[i]]}–${DAYS[d[j]]}` : d.slice(i, j + 1).map((x) => DAYS[x]).join(", "));
    i = j + 1;
  }
  return parts.join(", ");
}

// ctx: { kindName(kind), groupName(id), deviceName(id) }
export function describeRule(rule, ctx) {
  const kinds = rule.kinds.includes("*") ? "any event" : listOf(rule.kinds.map(ctx.kindName), "nothing");
  const scope = rule.scope;
  let who = "every device";
  if (scope.type === "group") who = `devices in ${listOf(scope.ids.map(ctx.groupName))}`;
  else if (scope.type === "devices") who = scope.ids.length > 3 ? `${scope.ids.length} chosen devices` : listOf(scope.ids.map(ctx.deviceName));
  else if (scope.type === "below") who = `everything behind ${ctx.deviceName(scope.device_id)}`;
  else if (scope.type === "tier") who = `devices marked ${scope.value}`;
  else if (scope.type === "type") who = `${scope.value} devices`;
  const when = rule.when ? `, ${describeDays(rule.when.days)} ${rule.when.from}–${rule.when.to}` : "";
  const tail = `${rule.keep_critical ? "" : " (critical events too)"}`;
  if (rule.type === "while_down") return `Ignore ${kinds} for ${who} while ${ctx.deviceName(rule.device_id)} is offline${when}${tail}.`;
  if (rule.type === "repeat") return `After ${rule.count} ${rule.kinds.includes("*") ? "events" : `${listOf(rule.kinds.map(ctx.kindName), "", "or")} events`} within ${rule.minutes} minutes ${rule.per === "device" ? "for the same device" : `for ${who} together`}, ignore the rest and tell me once${when}${tail}.`;
  return `Ignore ${kinds} for ${who}${when}${tail}.`;
}
