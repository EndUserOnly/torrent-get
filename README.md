# torrent-get

`torrent-get` is a Linux command-line interface for libtorrent. It was built and tested on x86_64 Pop!_OS and compatible Ubuntu-family systems. Other systems are not certified.

This was a personal project that felt worthy to share.

## Prerequisites

- x86_64 Linux with systemd
- Python 3
- libtorrent-rasterbar 2.0
- nftables
- sudo
- Jackett, configured with selected indexers (required for search; magnet import works independently)
- `geoip2` and GeoLite2 Country data (optional; peer country names are omitted when unavailable)

The torrent-get package itself does not change when optional GeoIP support is unavailable.

## Current source update

The recovery fix is packaged in [`releases/v1.0.1`](releases/v1.0.1).
It preserves queue ownership and recovery artifacts, safely prunes
inactive jobs, and reconciles global pause state. The original v1.0 package
and download instructions below remain historical and unchanged.

## Download and verify (original v1.0)

Download the release archive, contents inventory, `SHA256SUMS`, and their `.sig` files from the GitHub release. Save the public key below as `torrent-get-release-key.pub`, then verify every detached signature and checksum:

```sh
printf '%s\n' 'torrent-get-release ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICaVqlxlIvuJkRhCr2cXtGiYwRA0y9ZdC8GIeSfOcOBB' > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I torrent-get-release -n file -s SHA256SUMS.sig < SHA256SUMS
ssh-keygen -Y verify -f allowed_signers -I torrent-get-release -n file -s torrent-get-1.0-x86_64-20260905.tar.gz.sig < torrent-get-1.0-x86_64-20260905.tar.gz
ssh-keygen -Y verify -f allowed_signers -I torrent-get-release -n file -s torrent-get-1.0-x86_64-20260905.contents.txt.sig < torrent-get-1.0-x86_64-20260905.contents.txt
sha256sum -c SHA256SUMS
tar -xzf torrent-get-1.0-x86_64-20260905.tar.gz
cd torrent-get-1.0-20260905
./verify.sh
```

Do not install a release that fails either verification step.

Release-key fingerprint: `SHA256:15fvO3m6t3PZnFLowkjezBN+WkSITjNjQR78DkodnbI`.

## Install

Run the installer as the target desktop user:

```sh
./install.sh
./activate-services.sh
```

After installation, configure Jackett indexers at <http://127.0.0.1:9117>, then place the local Jackett URL and API key in `~/.config/torrent-cli/config.json` with mode `0600`.

## Commands

```text
torrent-get search SEARCH_TERM
torrent-get import
torrent-mgmnt
torrent-mgmnt maint
torrent-mgmnt pause
torrent-mgmnt resume
torrent-mgmnt pause JOB_ID
torrent-mgmnt resume JOB_ID
torrent-peers limit down none JOB_ID|all
```

The normal flow is:

```text
torrent-get search SEARCH_TERM
torrent-get import
torrent-mgmnt
```

`torrent-queue` and `torrent-peers` remain available for historical observation and supervision; their main controls are also exposed through `torrent-mgmnt`.

## Architecture

`torrent-get` submits a job to the queue. The queue qualifies it and passes it to peer management, where a transient native `torrent-worker-<job-id>.service` receives the job.

- `torrent-rate-regulator.service` — persistent user service enforcing the aggregate transfer-rate limit.
- `torrent-control.socket` — persistent user socket that activates the control service on demand.
- `torrent-control.service` — socket-activated user service handling local worker-control requests.
- `torrent-worker-<job-id>.service` — transient native worker for one queue job.
- `torrent-get-filterd.service` — persistent system service and sole persistent peer-deny authority; owns nftables enforcement and permanent IPv4/IPv6 deny sets.
- `torrent-get.slice` — user resource-control boundary for torrent-get services and workers.

Gatekeeper is the live traffic-control layer. It is distinct from `torrent-get-filterd`, which owns persistent/global peer blocking, and from the rate regulator, which controls aggregate transfer rates.

The design uses live state and small JSON files where necessary rather than a general application database. GeoIP uses its own database; torrent-get does not.

## Release contents

The exact v1.0 release source/package tree is under [`releases/v1.0`](releases/v1.0). Runtime state, job metadata, approvals, logs, caches, downloads, credentials, and machine-specific configuration are excluded.

## Credits

Design: Teop Versant and Ness  
Coding: Ness  
<https://downtroddendream.com/ChatGPT>

Contact: <wm.djackson@pm.me>

Bitcoin: `3KPigrE8rRiohh9RSxnzvozfD25gjrdbB7`
