#!/usr/bin/env bash
# afeye: build the patched Chromium 153 on a GitHub Actions runner.
#
# Speed levers (the whole point - the user wants hours, not a day):
#   - symbol_level=0 / v8_symbol_level=0 / blink_symbol_level=0:
#     no debug info anywhere. Debug info is ~1/3 of a default build's time.
#   - is_official_build=false: skips PGO and thin-LTO, the two slowest
#     non-debug stages of a chrome build.
#   - dcheck_always_on=false: DCHECKs compile out.
#   - ccache (GN cc_wrapper) + actions/cache: re-runs of this job hit the
#     cache and only relink, ~40-60 min instead of hours.
#   - only the `chrome` ninja target is built.
#   - gclient config + sync directly at the tag (no double fetch), --no-history.
set -euo pipefail

CHROMIUM_REF="${CHROMIUM_REF:-153.0.8010.52}"
WORK="${WORK:-/mnt/chromium}"
OUT_REL="${OUT_REL:-out/afeye}"
BUILD_WINDOW_SECS="${BUILD_WINDOW_SECS:-16200}"   # 4h30m of ninja
CCACHE_DIR="${CCACHE_DIR:-/mnt/ccache}"

echo "== afeye build: chromium $CHROMIUM_REF, window ${BUILD_WINDOW_SECS}s =="

# ---- 0. disk: the runner image ships ~45GB of preinstalled toolchains we
# never touch. Freeing them is the difference between fits and dies.
sudo rm -rf /usr/local/lib/android /usr/share/dotnet /opt/ghc \
            /usr/local/.ghcup /opt/hostedtoolcache/CodeQL 2>/dev/null || true
df -h / | tail -1

# ---- 1. depot_tools
if [ ! -d "$WORK/depot_tools" ]; then
  git clone -q --depth 1 https://chromium.googlesource.com/chromium/tools/depot_tools.git "$WORK/depot_tools"
fi
export PATH="$WORK/depot_tools:$PATH"
# bootstrap the bundled python/cipd once (fetch dies without it)
gclient --version >/dev/null 2>&1 || true

# ---- 2. source, pinned to the tag, no history, single sync
mkdir -p "$WORK/src"
cd "$WORK"
if [ ! -f .gclient ]; then
  gclient config --name=src "https://chromium.googlesource.com/chromium/src.git"
fi
if [ ! -d src/.git ] || [ "$(cd src && git describe --tags --exact-match 2>/dev/null)" != "$CHROMIUM_REF" ]; then
  gclient sync --no-history --with_branch_heads --delete_unversioned_trees \
    -r "src@refs/tags/$CHROMIUM_REF"
fi
cd "$WORK/src"
git rev-parse HEAD

# ---- 3. system deps
sudo ./build/install-build-deps.sh --no-arm >/dev/null 2>&1 || \
  sudo ./build/install-build-deps.sh --no-arm || true

# ---- 4. patches (the series applies cumulatively - a failure here is a
# patch/anchor bug and must abort loudly, not silently produce stock chrome)
REPO_ROOT="${REPO_ROOT:-$GITHUB_WORKSPACE}"
# plain git apply, NOT --3way: v8/ is a nested git repo in a gclient checkout,
# its blobs are not in chromium/src's index, and --3way dies on that. The
# series contexts are exact (generated from the real 153.0.8010.52 tree), so
# direct application is the correct mode.
for p in "$REPO_ROOT"/patches/*.patch; do
  echo "applying $(basename "$p")"
  git apply "$p" || patch -p1 --fuzz=0 --no-backup-if-mismatch < "$p"
done

# ---- 5. ccache
export CCACHE_DIR
ccache -M 9G >/dev/null 2>&1 || ccache --max-size=9G >/dev/null || true

# ---- 6. gn gen - fast args
gn gen "$OUT_REL" --args="$(cat <<'EOF'
is_debug = false
is_official_build = false
is_component_build = false
symbol_level = 0
v8_symbol_level = 0
blink_symbol_level = 0
dcheck_always_on = false
treat_warnings_as_errors = false
use_remoteexec = false
cc_wrapper = "ccache"
# libc++ clang modules make compiles uncachable by ccache (module-using
# compilations are skipped) - the chained-run architecture depends on the
# cache carrying compiled objects between 4h windows, so modules go off.
# Per-file compiles get slightly slower; cross-run rebuilds get fast.
use_clang_modules = false
v8_enable_afeye = true
blink_enable_afeye = true
network_enable_afeye = true
EOF
)"

# ---- 7. build under a hard window; exiting 124 here is EXPECTED on the
# first run(s) - the ccache archive keeps the compiled objects, the next
# chained run resumes and finishes. The job must never hit the 6h runner
# cap (that is what "не вырубается" means here).
mkdir -p "$CCACHE_DIR"
set +e
timeout --signal=TERM "$BUILD_WINDOW_SECS" \
  ninja -C "$OUT_REL" -j "$(nproc)" chrome
rc=$?
set -e
if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
  echo "== ninja failed with rc=$rc (real build error) =="
  exit "$rc"
fi
if [ ! -x "$OUT_REL/chrome" ]; then
  echo "== chrome binary not ready yet (rc=$rc) - window exhausted, cache saved, next run resumes =="
  exit 42
fi
echo "== chrome built: $OUT_REL/chrome =="
exit 0
