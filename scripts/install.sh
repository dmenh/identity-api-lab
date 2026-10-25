#!/usr/bin/env sh
set -eu
exec sh "$(dirname "$0")/lab.sh" install "${1:-postgres}" "${2:-8787}"
