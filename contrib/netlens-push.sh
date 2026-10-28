#!/bin/sh
# netlens-push.sh - send the load, uptime and disk usage of this host to Netlens (Enterprise: Settings -> Host agents).
#
# For Unix systems that have no OpenTelemetry Collector or Telegraf build (AIX, Solaris, HP-UX, older systems): plain POSIX sh, read-only commands, one
# HTTPS request with the client certificate of this host. Run it from cron every minute:   * * * * * /opt/netlens/netlens-push.sh
#
# Tested on Linux (dash, bash, busybox sh). AIX, Solaris and HP-UX were NOT available for testing: the commands used (uptime, df -Pk, date) are POSIX, but check
# the output with  NETLENS_DRY_RUN=1 ./netlens-push.sh  before relying on it, and read the notes below.
#
# Settings (environment or edit here):
#   NETLENS_URL    https://netlens.example.com:4318/telegraf
#   NETLENS_DIR    folder with ca.pem, agent.crt and agent.key (default: the folder of this script)
#   NETLENS_DF     the df command that understands -P (Solaris: /usr/xpg4/bin/df; HP-UX: use bdf and adapt the awk below)
#
# What it sends is the Telegraf JSON format that Netlens accepts. To add readings (processor, memory, network), add objects of the same shape:
#   {"name":"mem","tags":{},"fields":{"used_percent":42.5},"timestamp":<seconds>}   (names: cpu with tag cpu=cpu-total and field usage_idle, mem, swap, disk, net, system)

URL="${NETLENS_URL:-}"
DIR="${NETLENS_DIR:-$(cd "$(dirname "$0")" && pwd)}"
DF="${NETLENS_DF:-df}"

[ -n "$URL" ] || { echo "set NETLENS_URL, for example https://netlens.example.com:4318/telegraf" >&2; exit 2; }

now=$(date +%s 2>/dev/null)
case "$now" in ''|*[!0-9]*) now=$(perl -e 'print time' 2>/dev/null) ;; esac
case "$now" in ''|*[!0-9]*) echo "cannot get the time in seconds (date +%s and perl both failed)" >&2; exit 2 ;; esac

# load average (1 minute): the number after "load average(s):" with a dot or a comma as decimal sign
load=$(uptime 2>/dev/null | sed -e 's/.*load averages*: *//' -e 's/[ ,;].*//' | tr ',' '.')
case "$load" in ''|*[!0-9.]*) load="" ;; esac

# uptime in seconds, from the kernel when it offers it, else from the days in the uptime line (coarse)
up=""
if [ -r /proc/uptime ]; then
  up=$(sed 's/\..*//; s/ .*//' /proc/uptime)
else
  days=$(uptime 2>/dev/null | sed -n 's/.* up \([0-9][0-9]*\) day.*/\1/p')
  [ -n "$days" ] && up=$((days * 86400))
fi
case "$up" in ''|*[!0-9]*) up="" ;; esac

items=""
add() { if [ -z "$items" ]; then items="$1"; else items="$items,$1"; fi; }

if [ -n "$load" ] || [ -n "$up" ]; then
  f=""
  [ -n "$load" ] && f="\"load1\":$load"
  [ -n "$up" ] && { [ -n "$f" ] && f="$f,"; f="$f\"uptime\":$up"; }
  add "{\"name\":\"system\",\"tags\":{},\"fields\":{$f},\"timestamp\":$now}"
fi

# disks: df -Pk gives  Filesystem 1024-blocks Used Available Capacity Mounted-on  (POSIX). Mount points with characters Netlens does not accept are skipped.
for line in $($DF -Pk 2>/dev/null | awk 'NR>1 && $2+0>0 && $6 ~ /^\/[A-Za-z0-9_.\/-]*$/ { printf "%s:%s:%s\n", $6, $3, $4 }'); do
  mount=${line%%:*}; rest=${line#*:}; used=${rest%%:*}; free=${rest#*:}
  case "$mount" in /proc*|/sys*|/dev*|/run*|/system/*|/platform*|/lib/modules*|/etc/svc*|/etc/mnttab|/devices*|/objects*|/var/run*) continue ;; esac
  total=$((used + free))
  [ "$total" -gt 0 ] || continue
  pct=$(awk -v u="$used" -v t="$total" 'BEGIN { printf "%.2f", 100 * u / t }')
  add "{\"name\":\"disk\",\"tags\":{\"path\":\"$mount\",\"fstype\":\"unknown\"},\"fields\":{\"used_percent\":$pct,\"free\":$((free * 1024))},\"timestamp\":$now}"
done

[ -n "$items" ] || { echo "nothing to send" >&2; exit 1; }
body="{\"metrics\":[$items]}"

if [ -n "${NETLENS_DRY_RUN:-}" ]; then printf '%s\n' "$body"; exit 0; fi
printf '%s' "$body" | curl --silent --show-error --fail --max-time 20 --cacert "$DIR/ca.pem" --cert "$DIR/agent.crt" --key "$DIR/agent.key" \
  -H 'Content-Type: application/json' --data-binary @- "$URL" >/dev/null
