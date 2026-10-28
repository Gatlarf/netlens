#!/bin/sh
# netlens-renew.sh - get a new client certificate from Netlens before the current one ends (Enterprise: Settings -> Host agents).
#
# A certificate that Netlens issued is valid for 30 days. The collector does not renew it by itself, so run this once a day (cron or a systemd timer): it does
# nothing until the certificate has less than NETLENS_RENEW_DAYS (default 20) days left, then it makes a NEW key and request, asks Netlens for a certificate by
# presenting the current one, replaces agent.key and agent.crt, and runs NETLENS_RESTART so the collector picks them up.
#
# The old certificate keeps working for up to 7 days after the new one was issued, so a failed restart does not lose the host. A certificate that has already
# ended cannot renew: enrol again with a new token (Settings -> Host agents -> Enrol again).
#
# Settings (environment or edit here):
#   NETLENS_DIR      folder with ca.pem, agent.crt and agent.key (default: the folder of this script)
#   NETLENS_RENEW_URL  https://netlens.example.com:4318/renew
#   NETLENS_RESTART  command that restarts the collector, for example "systemctl restart otelcol-contrib" (default: none)
#   NETLENS_OWNER    user:group that must own the key, for example "root:otelcol-contrib" (default: leave as the current user)
#   NETLENS_RENEW_DAYS  renew when fewer days are left (default 20)

DIR="${NETLENS_DIR:-$(cd "$(dirname "$0")" && pwd)}"
URL="${NETLENS_RENEW_URL:-}"
DAYS="${NETLENS_RENEW_DAYS:-20}"
[ -n "$URL" ] || { echo "set NETLENS_RENEW_URL, for example https://netlens.example.com:4318/renew" >&2; exit 2; }

# still more than DAYS days left: nothing to do
if openssl x509 -in "$DIR/agent.crt" -noout -checkend $((DAYS * 86400)) >/dev/null 2>&1; then exit 0; fi

umask 077
work=$(mktemp -d "$DIR/.renew.XXXXXX") || exit 1
trap 'rm -r -f "$work"' EXIT

openssl ecparam -name prime256v1 -genkey -noout -out "$work/agent.key" || exit 1
openssl req -new -key "$work/agent.key" -subj "/CN=$(hostname)" -out "$work/agent.csr" || exit 1
curl --silent --show-error --fail --max-time 30 --cacert "$DIR/ca.pem" --cert "$DIR/agent.crt" --key "$DIR/agent.key" \
  --data-binary @"$work/agent.csr" "$URL" -o "$work/agent.crt" || { echo "renewal refused or Netlens not reachable" >&2; exit 1; }
openssl x509 -in "$work/agent.crt" -noout -subject >/dev/null 2>&1 || { echo "the answer is not a certificate" >&2; exit 1; }
# the new certificate must match the new key
[ "$(openssl x509 -in "$work/agent.crt" -noout -pubkey | openssl sha256)" = "$(openssl pkey -in "$work/agent.key" -pubout | openssl sha256)" ] || { echo "key and certificate do not match" >&2; exit 1; }

# The answer holds the new certificate first and then the CA certificate(s) Netlens uses. During a CA rotation that is how the host learns the new CA: add the ones
# that ca.pem does not have yet (the old ones stay, so the host trusts Netlens before and after the rotation is finished).
split_pem() {   # split_pem FILE DIR : one file per certificate, DIR/1.pem, DIR/2.pem ...
  n=0; out=""
  while IFS= read -r line; do
    case "$line" in *"BEGIN CERTIFICATE"*) n=$((n + 1)); out="$2/$n.pem"; : > "$out" ;; esac
    [ -n "$out" ] && printf '%s\n' "$line" >> "$out"
    case "$line" in *"END CERTIFICATE"*) out="" ;; esac
  done < "$1"
}
mkdir "$work/new" "$work/old" && split_pem "$work/agent.crt" "$work/new" && split_pem "$DIR/ca.pem" "$work/old" && cp "$DIR/ca.pem" "$work/ca.merged" || exit 1
added=0
for f in "$work"/new/*.pem; do
  [ "$f" = "$work/new/1.pem" ] && continue
  have=0
  for g in "$work"/old/*.pem; do [ -f "$g" ] && cmp -s "$f" "$g" && have=1; done
  if [ "$have" = 0 ]; then cat "$f" >> "$work/ca.merged"; added=$((added + 1)); fi
done

if [ -n "${NETLENS_OWNER:-}" ]; then chown "$NETLENS_OWNER" "$work/agent.key" "$work/agent.crt" || exit 1; chmod 640 "$work/agent.key" "$work/agent.crt"; fi
if [ "$added" -gt 0 ]; then chmod 644 "$work/ca.merged"; mv -f "$work/ca.merged" "$DIR/ca.pem" || exit 1; echo "ca.pem: $added new CA certificate(s) added"; fi
mv -f "$work/agent.key" "$DIR/agent.key" && mv -f "$work/agent.crt" "$DIR/agent.crt" || exit 1
echo "renewed: $(openssl x509 -in "$DIR/agent.crt" -noout -enddate)"
if [ -n "${NETLENS_RESTART:-}" ]; then sh -c "$NETLENS_RESTART" || { echo "restart failed" >&2; exit 1; }; fi
