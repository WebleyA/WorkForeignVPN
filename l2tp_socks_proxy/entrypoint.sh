#!/usr/bin/env bash
set -euo pipefail
umask 077

fail() { echo "ERROR: $*" >&2; exit 1; }
require_env() { [ -n "${!1:-}" ] || fail "Missing required environment variable: $1"; }
ppp_ready() { ip -o -4 addr show dev ppp0 2>/dev/null | grep -q ' inet '; }
print_link() {
  printf 'vless://%s@127.0.0.1:%s?encryption=none&security=none&type=tcp#L2TP-VLESS\n' "$VLESS_UUID" "$VLESS_PORT"
}

uuid_file=/var/lib/gateway/vless-uuid
if [ -z "${VLESS_UUID:-}" ]; then
  if [ -f "$uuid_file" ]; then
    VLESS_UUID="$(cat "$uuid_file")"
  elif [ "${1:-start}" = start ]; then
    mkdir -p "$(dirname "$uuid_file")"
    VLESS_UUID="$(cat /proc/sys/kernel/random/uuid)"
    printf '%s\n' "$VLESS_UUID" > "$uuid_file.tmp"
    mv "$uuid_file.tmp" "$uuid_file"
  else
    fail 'UUID is not available yet. Start the container first.'
  fi
fi
[[ "$VLESS_UUID" =~ ^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$ ]] \
  || fail 'VLESS_UUID must be a valid UUID.'
export VLESS_UUID
export VLESS_PORT="${VLESS_PORT:-1081}"
[[ "$VLESS_PORT" =~ ^[0-9]{1,5}$ ]] || fail 'VLESS_PORT must be a port number.'
(( 10#$VLESS_PORT >= 1 && 10#$VLESS_PORT <= 65535 )) || fail 'VLESS_PORT must be 1..65535.'
VLESS_PORT="$((10#$VLESS_PORT))"

case "${1:-start}" in
  link)
    print_link
    exit 0
    ;;
  outbound)
    envsubst '${VLESS_UUID} ${VLESS_PORT}' \
      < /etc/gateway/templates/client-outbound.json.template
    exit 0
    ;;
  start) ;;
  *) fail 'Usage: gateway-entrypoint [start|link|outbound]' ;;
esac

for name in VPN_SERVER VPN_TYPE VPN_USER VPN_PASSWORD VPN_L2TP_KEY; do
  require_env "$name"
done
[ "$VPN_TYPE" = l2tp-ipsec ] || fail "Unsupported VPN_TYPE=$VPN_TYPE; expected l2tp-ipsec."
[ -c /dev/ppp ] || fail '/dev/ppp is missing; enable PPP on the Docker host.'

export VPN_DNS="${VPN_DNS:-1.1.1.1}"
[[ "$VPN_DNS" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail 'VPN_DNS must be an IPv4 address.'
IFS=. read -r -a octets <<< "$VPN_DNS"
for octet in "${octets[@]}"; do
  (( 10#$octet <= 255 )) || fail 'VPN_DNS contains an invalid IPv4 octet.'
done

mkdir -p /run/xl2tpd /etc/xray
envsubst '${VLESS_UUID} ${VPN_DNS}' \
  < /etc/gateway/templates/xray.json.template > /etc/xray/config.json
xray run -test -config /etc/xray/config.json

# Resolve before PPP changes the default route, and use the pinned IP in both daemons.
original_gateway="${HOST_GATEWAY:-$(ip -4 route show default | awk 'NR == 1 {print $3}')}"
[ -n "$original_gateway" ] || fail 'Cannot detect the original Docker gateway.'
server_ip="$(getent ahostsv4 "$VPN_SERVER" | awk 'NR == 1 {print $1}')" \
  || fail 'Cannot resolve VPN_SERVER before connecting.'
[ -n "$server_ip" ] || fail 'VPN_SERVER has no IPv4 address.'
ip -4 route replace "$server_ip/32" via "$original_gateway"
export VPN_SERVER="$server_ip"

vpn_variables='${VPN_SERVER} ${VPN_USER} ${VPN_PASSWORD} ${VPN_L2TP_KEY}'
envsubst "$vpn_variables" < /etc/gateway/templates/ipsec.conf.template > /etc/ipsec.conf
envsubst "$vpn_variables" < /etc/gateway/templates/ipsec.secrets.template > /etc/ipsec.secrets
envsubst "$vpn_variables" < /etc/gateway/templates/xl2tpd.conf.template > /etc/xl2tpd/xl2tpd.conf
envsubst "$vpn_variables" < /etc/gateway/templates/options.l2tpd.client.template > /etc/ppp/options.l2tpd.client
chmod 600 /etc/ipsec.secrets /etc/ppp/options.l2tpd.client /etc/xray/config.json

pids=()
cleanup() {
  trap - EXIT
  set +e
  if ((${#pids[@]})); then kill "${pids[@]}" 2>/dev/null; fi
  timeout 5 ipsec stop >/dev/null 2>&1
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ipsec start --nofork &
ipsec_pid=$!
pids+=("$ipsec_pid")
ipsec_ready=false
for ((attempt=0; attempt<30; attempt++)); do
  kill -0 "$ipsec_pid" 2>/dev/null || fail 'IPsec exited during startup.'
  if ipsec status >/dev/null 2>&1; then ipsec_ready=true; break; fi
  sleep 1
done
"$ipsec_ready" || fail 'IPsec control socket did not become ready.'
timeout 60 ipsec up old-vpn

xl2tpd -D &
xl2tpd_pid=$!
pids+=("$xl2tpd_pid")
for ((attempt=0; attempt<30; attempt++)); do
  [ -p /var/run/xl2tpd/l2tp-control ] && break
  kill -0 "$xl2tpd_pid" 2>/dev/null || fail 'xl2tpd exited during startup.'
  sleep 1
done
[ -p /var/run/xl2tpd/l2tp-control ] || fail 'xl2tpd control FIFO was not created.'
timeout 5 bash -c 'echo "c old-vpn" > /var/run/xl2tpd/l2tp-control'

for ((attempt=0; attempt<60; attempt++)); do
  ppp_ready && break
  kill -0 "$xl2tpd_pid" 2>/dev/null || fail 'xl2tpd exited before PPP was ready.'
  sleep 1
done
ppp_ready || fail 'ppp0 has no IPv4 address; check VPN credentials and connectivity.'
ip -4 route replace default dev ppp0

xray run -config /etc/xray/config.json &
xray_pid=$!
pids+=("$xray_pid")

xray_ready=false
for ((attempt=0; attempt<30; attempt++)); do
  kill -0 "$xray_pid" 2>/dev/null || fail 'Xray exited during startup.'
  ppp_ready || fail 'PPP disconnected during Xray startup.'
  if ss -H -lnt 'sport = :1081' | grep -q .; then
    xray_ready=true
    break
  fi
  sleep 1
done
"$xray_ready" || fail 'Xray did not open VLESS port 1081.'

# Restart the connection if PPP disappears while xl2tpd stays alive.
monitor_ppp() {
  while sleep 2; do
    ppp_ready || { echo 'PPP disconnected; restarting the container.' >&2; return 1; }
  done
}
monitor_ppp &
pids+=("$!")
echo 'L2TP ready. VLESS TCP without TLS is listening on container port 1081.'
print_link
wait -n "${pids[@]}"
