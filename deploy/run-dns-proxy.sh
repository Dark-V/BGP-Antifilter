#!/bin/sh
set -eu

# shellcheck source=deploy/lib.sh
. /lib.sh
start_log_stream "dns-proxy"
enabled="$(python3 -c 'from bgp_antifilter.dns_settings import load_active_environment; print(load_active_environment()["DNS_PROXY_ENABLED"])')"
if [ "$enabled" != "1" ]; then
  echo "DNS proxy disabled; idling"
  exec tail -f /dev/null
fi
exec python3 -m bgp_antifilter.dns_proxy
