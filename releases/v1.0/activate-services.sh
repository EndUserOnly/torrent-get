#!/bin/sh
set -eu

if ! command -v systemctl >/dev/null 2>&1; then
  printf '%s\n' 'Error: systemd/systemctl is required to activate torrent-get services.' >&2
  exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
  printf '%s\n' 'Error: run this script as the target desktop user, not as root.' >&2
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
  printf '%s\n' 'Error: sudo is required to activate the system filter backend.' >&2
  exit 1
fi

sudo systemctl daemon-reload
sudo systemctl enable --now jackett.service
sudo systemctl enable --now torrent-get-filterd.service

systemctl --user daemon-reload
systemctl --user enable --now torrent-control.socket
systemctl --user enable --now torrent-rate-regulator.service

sudo systemctl is-active --quiet torrent-get-filterd.service
sudo systemctl is-active --quiet jackett.service
systemctl --user is-active --quiet torrent-control.socket
systemctl --user is-active --quiet torrent-rate-regulator.service

printf '%s\n' 'Jackett and torrent-get services are enabled and active.'

