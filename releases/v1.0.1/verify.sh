#!/bin/sh
set -eu
cd "$(dirname "$0")"
sha256sum -c MANIFEST.sha256
