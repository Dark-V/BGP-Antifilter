#!/bin/sh
set -eu

# shellcheck source=deploy/lib.sh
. /lib.sh
start_log_stream "admin"

if [ "${ADMIN_ENABLED:-0}" != "1" ]; then
  echo "admin server disabled; idling"
  exec tail -f /dev/null
fi

if [ "$ADMIN_PORT" -ge 1024 ]; then
  exec setpriv --inh-caps=-all --ambient-caps=-all python3 /admin-server.py
fi
exec python3 /admin-server.py
