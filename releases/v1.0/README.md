# torrent-get 1.0

Stable x86_64 release package, frozen for 2026-09-04 and prepared for
publication on 2026-09-05.

Run `./verify.sh` before installation. Run `./install.sh` as the target desktop
user to install the user components. If `sudo` is available, the installer also
installs the existing system filter backend and its unit file.

After installation, run `./activate-services.sh` as the same desktop user. It
reloads the packaged system and user unit definitions, then enables and starts
the permanent filter backend, control socket, and transfer-rate regulator. The
control service remains socket-activated.

The installer recognizes Debian/Ubuntu (`apt-get`), Fedora (`dnf`), Arch
(`pacman`), and openSUSE (`zypper`) when runtime components are missing. This
binary release requires x86_64 glibc, systemd, Python 3, nftables, sudo, and
libtorrent-rasterbar 2.0. Missing mandatory components stop installation if the
distribution cannot install them. It is not compatible with musl-based
distributions such as Alpine.

Only GeoIP country-name lookup is optional. If its Python reader is unavailable,
the installer offers distribution and `pip --user` installation choices, then
allows torrent-get installation to continue without country names.

Jackett is mandatory for torrent search. The package contains the pinned official
Jackett v0.24.2527 Linux x64 archive. If `/opt/Jackett` and `jackett.service` are
absent, the installer verifies and installs that bundled release. It never
packages or overwrites a user's Jackett settings, API key, or indexer choices.
After service activation, configure indexers at `http://127.0.0.1:9117`, then
place the local URL and API key in `~/.config/torrent-cli/config.json` with mode
`0600`.

The frozen GeoLite2 Country database is installed at
`~/.local/share/torrent-get/geoip/GeoLite2-Country.mmdb`.

The package excludes runtime state, job metadata, approvals, logs, caches,
download data, credentials, and machine-specific configuration.
