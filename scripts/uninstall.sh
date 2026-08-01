#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "uninstall.sh must run as root" >&2
  exit 1
fi

systemctl disable --now gargoyle 2>/dev/null || true
rm -f /etc/systemd/system/gargoyle.service
rm -f /usr/lib/tmpfiles.d/gargoyle.conf
rm -f /usr/local/bin/gargoyle
systemctl daemon-reload

echo "Removed binary and service. Configuration and logs were preserved."
