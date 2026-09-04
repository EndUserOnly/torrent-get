#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build
g++ -std=c++17 -O2 -pthread \
  source/worker/torrent-worker-posix-approval-v1.cpp \
  source/worker/approval_gate_client.cpp \
  -o build/torrent-worker-posix \
  $(pkg-config --cflags --libs libtorrent-rasterbar)
sha256sum -c BINARY-REFERENCE.sha256

