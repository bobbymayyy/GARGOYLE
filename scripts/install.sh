#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

binary=${1:-target/release/gargoyle}
config=${2:-config/gargoyle.example.toml}

install -D -m 0755 "$binary" /usr/local/bin/gargoyle
install -d -m 0750 /etc/gargoyle
if [[ ! -e /etc/gargoyle/gargoyle.toml ]]; then
  install -m 0640 "$config" /etc/gargoyle/gargoyle.toml
else
  echo "preserving existing /etc/gargoyle/gargoyle.toml"
fi
install -D -m 0644 packaging/systemd/gargoyle.service /etc/systemd/system/gargoyle.service
install -D -m 0644 packaging/systemd/gargoyle.tmpfiles /usr/lib/tmpfiles.d/gargoyle.conf
install -D -m 0644 packaging/logrotate/gargoyle /etc/logrotate.d/gargoyle
systemd-tmpfiles --create /usr/lib/tmpfiles.d/gargoyle.conf
systemctl daemon-reload

echo "Installed GARGOYLE. Start with: systemctl enable --now gargoyle"
