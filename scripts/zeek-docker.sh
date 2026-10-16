#!/bin/sh
# Pinned official Zeek image used by the synthetic integration check.
set -eu
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "$PWD" in
  "$project_root"|"$project_root"/*) ;;
  *) echo 'Run Zeek from within the project directory.' >&2; exit 2 ;;
esac
exec docker run --rm --network none --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$project_root,target=$project_root" \
  --workdir "$PWD" --entrypoint /usr/local/zeek/bin/zeek \
  zeek/zeek@sha256:03edc722834dc810a7766b1cbece6a1ee345726ec9726f3e69671600a1673c5a "$@"
