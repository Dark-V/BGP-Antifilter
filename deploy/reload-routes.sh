#!/bin/sh
set -eu

if [ "$(id -u)" -eq 0 ]; then
  exec setpriv --reuid=10001 --regid=10001 --clear-groups \
    --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs /reload-routes.sh "$@"
fi

CONFIG_DIR="${CONFIG_DIR:-/etc/bird/config}"
SETTINGS_ENV_FILE="${SETTINGS_ENV_FILE:-$CONFIG_DIR/settings.env}"
if [ -f "$SETTINGS_ENV_FILE" ]; then
  set -a
  # shellcheck source=/dev/null
  . "$SETTINGS_ENV_FILE"
  set +a
fi
exec python3 -m bgp_antifilter.route_transaction apply "$@"
