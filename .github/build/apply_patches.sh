#!/usr/bin/env bash
# afeye: layer-aware patch application against a synced chromium tree.
#
# V8 patches are FATAL - they are the raw executing-source core of the whole
# instrument (sink plumbing 0001, embedder compiles 0002, eval chokepoint 0013).
# blink/net patches carry extra sink depth; on context drift they retry with
# fuzz and are dropped with a loud warning instead of blocking the core build.
#
# usage: apply_patches.sh <chromium-src dir>
set -u

SRCROOT="${1:?usage: apply_patches.sh <chromium-src>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WS="$(cd "$HERE/../.." && pwd)"

PDIR="$WS/src/patches"
[ -d "$PDIR" ] || PDIR="$WS/patches"
[ -d "$PDIR" ] || { echo "::error::no patch dir found"; exit 1; }

layer_of() {
  case "$1" in
    0001*|0002*|0003*|0004*|0005*|0013*) echo v8 ;;
    0006*|0007*|0008*|0009*|0010*|0012*) echo blink ;;
    0011*) echo net ;;
    *) echo unknown ;;
  esac
}

subdir_of() {
  case "$1" in
    v8) echo "v8" ;;
    blink) echo "third_party/blink" ;;
    *) echo "." ;;
  esac
}

APPLIED=0
FUZZED=0
SKIPPED=()

shopt -s nullglob
for p in $(ls "$PDIR" | sort); do
  case "$p" in
    *.patch) ;;
    *) continue ;;
  esac
  layer="$(layer_of "$p")"
  sub="$(subdir_of "$layer")"

  if ( cd "$SRCROOT/$sub" && git apply "$PDIR/$p" ) 2>/tmp/afeye-apply.err; then
    echo "APPLIED(strict) $p [$layer]"
    APPLIED=$((APPLIED+1))
    continue
  fi
  if ( cd "$SRCROOT/$sub" && patch -p1 --fuzz=3 --forward --silent < "$PDIR/$p" ) >/tmp/afeye-apply2.log 2>&1 \
     && ! grep -qi "FAILED" /tmp/afeye-apply2.log; then
    echo "APPLIED(fuzz)   $p [$layer]"
    FUZZED=$((FUZZED+1))
    continue
  fi
  if [ "$layer" = "v8" ]; then
    echo "::error::FATAL: v8 patch $p failed to apply at this revision - rebase it (see src/patches/SERIES.md)"
    cat /tmp/afeye-apply.err /tmp/afeye-apply2.log 2>/dev/null | head -40
    exit 1
  fi
  echo "::warning::patch $p [$layer] SKIPPED (context drift) - its sinks are missing from this build"
  SKIPPED+=("$p")
done

echo "patch summary: strict=$APPLIED fuzz=$FUZZED skipped=${SKIPPED[*]:-none}"
if [ "${#SKIPPED[@]}" -gt 0 ]; then
  echo "::warning::build continues with the V8 core; rebase the skipped patches and re-run this workflow"
fi
exit 0
