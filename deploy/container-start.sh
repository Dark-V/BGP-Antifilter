#!/bin/sh
set -eu

if [ "$(id -u)" -eq 0 ]; then
  python3 -m bgp_antifilter.runtime_permissions
  runtime_groups=10001
  # Preserve the existing optional self-updater without changing the host socket.
  if [ -S /var/run/docker.sock ]; then
    runtime_groups="$runtime_groups,$(stat -c %g /var/run/docker.sock)"
  fi
  exec setpriv --reuid=10001 --regid=10001 --groups="$runtime_groups" \
    --inh-caps=-all,+net_bind_service --ambient-caps=-all,+net_bind_service \
    --bounding-set=-all,+net_bind_service --no-new-privs /container-start.sh
fi

/init-config.sh
exec supervisord -n -c /etc/supervisor/conf.d/bgp-antifilter.conf
