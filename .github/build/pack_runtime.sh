#!/usr/bin/env bash
# afeye: pack the runnable chrome runtime files (what the crawl workflow
# downloads from the release) into chrome-runtime.tzst inside PKG.
#
# usage: pack_runtime.sh <out/afeye> <pkg dir>
set -eu

OUT_ABS="${1:?usage: pack_runtime.sh <out/afeye> <pkgdir>}"
PKG="${2:?usage: pack_runtime.sh <out/afeye> <pkgdir>}"

mkdir -p "$PKG/chrome-linux"
cd "$OUT_ABS"

for f in chrome chrome_crashpad_handler chrome_sandbox; do
  [ -f "$f" ] && cp -a "$f" "$PKG/chrome-linux/"
done
for so in ./*.so; do
  [ -e "$so" ] && cp -a "$so" "$PKG/chrome-linux/"
done
for f in icudtl.dat snapshot_blob.bin v8_context_snapshot.bin; do
  [ -f "$f" ] && cp -a "$f" "$PKG/chrome-linux/"
done
[ -d locales ] && cp -a locales "$PKG/chrome-linux/"
[ -d resources ] && cp -a resources "$PKG/chrome-linux/"
[ -d swiftshader ] && cp -a swiftshader "$PKG/chrome-linux/"

cd "$PKG"
tar -I 'zstd -3 -T2' -cf chrome-runtime.tzst chrome-linux
ls -la "$PKG"
