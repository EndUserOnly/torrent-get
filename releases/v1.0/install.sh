#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$ROOT/verify.sh"

install_mandatory_dependencies() {
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y python3 nftables libtorrent-rasterbar2.0
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y python3 nftables rb_libtorrent
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --needed python nftables libtorrent-rasterbar
  elif command -v zypper >/dev/null 2>&1; then
    sudo zypper --non-interactive install python3 nftables libtorrent-rasterbar2_0
  else
    return 1
  fi
}

install_geoip_reader() {
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y python3-geoip2 python3-maxminddb
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y python3-geoip2 python3-maxminddb
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --needed python-geoip2 python-maxminddb
  elif command -v zypper >/dev/null 2>&1; then
    sudo zypper --non-interactive install python3-geoip2 python3-maxminddb
  else
    return 1
  fi
}

python_geoip_ready() {
  python3 -c 'import geoip2.database' >/dev/null 2>&1 ||
    python3 -c 'import maxminddb' >/dev/null 2>&1
}

native_worker_ready() {
  ldd "$ROOT/payload/user/libexec/torrent-worker-posix" 2>&1 | grep -q 'not found' && return 1
  return 0
}

jackett_ready() {
  [ -x /opt/Jackett/jackett ] && [ -f /etc/systemd/system/jackett.service ]
}

install_pinned_jackett() {
  jackett_archive="$ROOT/third-party/Jackett.Binaries.LinuxAMDx64-v0.24.2527.tar.gz"
  printf '%s  %s\n' \
    '13748450c3762a9d095f6959eab50b0d209cc298d4103e81f3144a80db8bd709' \
    "$jackett_archive" | sha256sum -c -
  if [ -e /opt/Jackett ]; then
    printf '%s\n' 'Error: /opt/Jackett exists but is incomplete; refusing to overwrite it.' >&2
    return 1
  fi
  sudo tar -xzf "$jackett_archive" -C /opt
  sudo chown -R "$(id -u):$(id -g)" /opt/Jackett
  sudo /opt/Jackett/install_service_systemd.sh
}

if [ "$(uname -m)" != "x86_64" ]; then
  printf '%s\n' 'Error: this binary release requires x86_64 Linux.' >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  printf '%s\n' 'Error: this release requires a systemd-based Linux distribution.' >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'Python 3 is missing.' >&2
fi
if ! command -v sudo >/dev/null 2>&1; then
  printf '%s\n' 'Error: sudo is required for system components.' >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1 || ! command -v nft >/dev/null 2>&1 || ! native_worker_ready; then
  printf '%s' 'Mandatory runtime components are missing. Install them now? [Y/n] '
  read answer
  case "$answer" in
    n|N|no|NO)
      printf '%s\n' 'Installation stopped: mandatory runtime components are unavailable.' >&2
      exit 1
      ;;
    *)
      if ! install_mandatory_dependencies; then
        printf '%s\n' 'Installation stopped: the mandatory distribution packages did not install.' >&2
        printf '%s\n' 'Install Python 3, nftables, and libtorrent-rasterbar 2.0, then rerun this installer.' >&2
        exit 1
      fi
      ;;
  esac
fi

if ! command -v python3 >/dev/null 2>&1 || ! command -v nft >/dev/null 2>&1 || ! native_worker_ready; then
  printf '%s\n' 'Installation stopped: mandatory runtime verification failed.' >&2
  exit 1
fi

if ! python_geoip_ready; then
  printf '%s' 'Optional GeoIP country lookup is unavailable. Install a GeoIP reader now? [y/N] '
  read answer
  case "$answer" in
    y|Y|yes|YES)
      if ! install_geoip_reader; then
        printf '%s\n' 'The distribution GeoIP install failed.' >&2
        printf '%s' 'Try installing geoip2 and maxminddb with pip --user? [y/N] '
        read answer
        case "$answer" in
          y|Y|yes|YES) python3 -m pip install --user geoip2 maxminddb || true ;;
        esac
      fi
      ;;
  esac
  if ! python_geoip_ready; then
    printf '%s\n' 'Continuing without optional GeoIP country-name lookup.' >&2
  fi
fi

if ! jackett_ready; then
  printf '%s' 'Mandatory Jackett v0.24.2527 is missing. Install the bundled verified release now? [Y/n] '
  read answer
  case "$answer" in
    n|N|no|NO)
      printf '%s\n' 'Installation stopped: Jackett is mandatory for torrent search.' >&2
      exit 1
      ;;
    *)
      if ! install_pinned_jackett || ! jackett_ready; then
        printf '%s\n' 'Installation stopped: Jackett installation did not complete.' >&2
        exit 1
      fi
      ;;
  esac
fi

install -d -m 0755 "$HOME/.local/bin" "$HOME/.local/libexec"
install -d -m 0755 "$HOME/.local/lib/torrent-get/security"
install -d -m 0755 "$HOME/.local/share/torrent-get/geoip"
install -d -m 0755 "$HOME/.config/systemd/user"

for name in magnet-search torrent-get torrent-mgmnt torrent-peers torrent-queue torrent-rate-regulator; do
  install -m 0755 "$ROOT/payload/user/bin/$name" "$HOME/.local/bin/$name"
done
install -m 0700 "$ROOT/payload/user/libexec/torrent-approval-bridge" "$HOME/.local/libexec/torrent-approval-bridge"
install -m 0755 "$ROOT/payload/user/libexec/torrent-control-service" "$HOME/.local/libexec/torrent-control-service"
install -m 0755 "$ROOT/payload/user/libexec/torrent-worker-posix" "$HOME/.local/libexec/torrent-worker-posix"

for name in approval_store.py gate_store_connector.py gatekeeper_diagnostic_connector.py store_mgmnt_connector.py; do
  install -m 0644 "$ROOT/payload/user/lib/torrent-get/security/$name" "$HOME/.local/lib/torrent-get/security/$name"
done
chmod 0755 "$HOME/.local/lib/torrent-get/security/approval_store.py"
chmod 0600 "$HOME/.local/lib/torrent-get/security/gatekeeper_diagnostic_connector.py"

install -m 0644 "$ROOT/payload/user/share/torrent-get/geoip/GeoLite2-Country.mmdb" \
  "$HOME/.local/share/torrent-get/geoip/GeoLite2-Country.mmdb"

for name in torrent-control.service torrent-control.socket torrent-get.slice torrent-rate-regulator.service; do
  install -m 0644 "$ROOT/payload/user/systemd/$name" "$HOME/.config/systemd/user/$name"
done

if command -v sudo >/dev/null 2>&1; then
  sudo install -d -m 0755 /usr/local/libexec
  sudo install -m 0755 "$ROOT/payload/system/libexec/torrent-get-filterd" /usr/local/libexec/torrent-get-filterd
  sudo install -m 0644 "$ROOT/payload/system/systemd/torrent-get-filterd.service" /etc/systemd/system/torrent-get-filterd.service
else
  printf '%s\n' 'sudo not found: system filter backend was not installed.' >&2
fi

printf '%s\n' 'Files installed successfully.'
printf '%s\n' 'GeoIP database installed at ~/.local/share/torrent-get/geoip/GeoLite2-Country.mmdb.'
printf '%s\n' 'Next step: run ./activate-services.sh as this same desktop user.'
printf '%s\n' 'Then configure Jackett indexers at http://127.0.0.1:9117 and add the local API key to ~/.config/torrent-cli/config.json.'

# Initialize the privileged peer-blocking backend and create its runtime socket.
user_uid=$(id -u)
filter_unit=/etc/systemd/system/torrent-get-filterd.service
filter_state_dir=/var/lib/torrent-get-filter
sudo install -d -m 0700 "$filter_state_dir"
sudo sed -i -E \
  "s/^Environment=TORRENT_FILTER_UID=.*/Environment=TORRENT_FILTER_UID=$user_uid/" \
  "$filter_unit"
sudo systemctl daemon-reload
sudo systemctl reset-failed torrent-get-filterd.service || true
sudo systemctl enable --now torrent-get-filterd.service
