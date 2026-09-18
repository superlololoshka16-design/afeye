#!/usr/bin/env bash
# afeye: pack the ninja build state for handoff to the next build stage.
#
# chrome binary exists  -> BUILD_DONE + chrome-runtime.tzst (small, final)
# otherwise             -> out/ split into <=7GB zstd tar pieces
#                          (obj/ separately: it is the bulk)
#
# usage: pack_state.sh <abs path to out/afeye> <pack dir>
set -eu

OUT_ABS="${1:?usage: pack_state.sh <out/afeye> <packdir>}"
PACK="${2:?usage: pack_state.sh <out/afeye> <packdir>}"
SRC_ROOT="$(cd "$OUT_ABS/.." && pwd)" # chromium/src

mkdir -p "$PACK"

if [ -x "$OUT_ABS/chrome" ]; then
  echo done > "$PACK/BUILD_DONE"
  bash "$(dirname "$0")/pack_runtime.sh" "$OUT_ABS" "$PACK"
  echo "state: BUILD_DONE + chrome-runtime.tzst"
  exit 0
fi

cd "$SRC_ROOT"
# out/ without obj/ (ninja files, gen/, args) - small
tar -C "$SRC_ROOT" --exclude='out/afeye/obj' -cf - out/afeye \
  | zstd -3 -T2 \
  | split -b 7G - "$PACK/out-part-a.tzst."
# obj/ - the bulk
tar -C "$SRC_ROOT" -cf - out/afeye/obj \
  | zstd -3 -T2 \
  | split -b 7G - "$PACK/out-part-b.tzst."
echo "state: out parts"
ls -la "$PACK"
