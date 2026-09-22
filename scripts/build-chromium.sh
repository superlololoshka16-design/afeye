#!/usr/bin/env bash
# afeye: build the patched Chromium 153 on a GitHub Actions runner.
#
# Target: the REAL `chrome` binary (NOT headless_shell). v6 built
# headless_shell - the stripped test app with half the WebPlatform
# pipeline missing; antifraud scripts (Cloudflare / DataDome) probe for
# the missing interfaces and bail out before doing real work, so the
# sinks stayed silent not because the hooks were broken but because the
# antifraud JS never ran its real path. The full chrome binary runs
# headless via --headless=new with the ENTIRE platform intact - that is
# the honest capture surface. It costs ~2x the ninja graph of
# headless_shell; the chained-window + ccache architecture below absorbs
# it (first run(s) exhaust the window, cache carries progress, the chain
# re-triggers itself until the binary exists).
#
# Speed levers (the whole point - hours, not a day):
#   - `chrome` target but component build: per-component .so links, a
#     patched Blink/V8 re-link is seconds, not a 15-minute monolith link
#   - use_lld + concurrent_links=4: LLD links in parallel
#   - symbol_level=0 / v8_symbol_level=0 / blink_symbol_level=0: no debug
#     info anywhere (~1/3 of a default build's time)
#   - is_official_build=false: skips PGO and thin-LTO
#   - dcheck_always_on=false, enable_nacl=false
#   - ccache (GN cc_wrapper) + actions/cache: chained runs resume; a warm
#     re-run relinks in well under an hour
#   - gclient sync at the tag, --no-history, single pass
#   - use_clang_modules=false: module-using compiles are uncachable by
#     ccache, and the chained-run architecture depends on the cache
#   - extra_cflags GLOBAL defines: -DV8_AFEYE=1 -DBLINK_AFEYE=1
#     -DNET_AFEYE=1 reach EVERY translation unit in EVERY toolchain, so
#     no #ifdef-guarded hook can ever compile to nothing again (the v6
#     gn-scope nesting bug was exactly this class of failure)
set -euo pipefail

CHROMIUM_REF="${CHROMIUM_REF:-153.0.8010.52}"
WORK="${WORK:-/mnt/chromium}"
OUT_REL="${OUT_REL:-out/afeye}"
NINJA_TARGET="${NINJA_TARGET:-chrome}"
BUILD_WINDOW_SECS="${BUILD_WINDOW_SECS:-16200}"   # 4h30m of ninja
CCACHE_DIR="${CCACHE_DIR:-/mnt/ccache}"

echo "== afeye build: chromium $CHROMIUM_REF, target $NINJA_TARGET, window ${BUILD_WINDOW_SECS}s =="

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
# v6: eleven patches, grouped by layer (v8 sink / v8 scripts / v8 calls+wasm /
# v8 engine fidelity / blink sink / blink flow / blink probes / blink dom-api
# choke / blink input / blink context anchors / net wire). Only these files
# ever recompile after a warm ccache - the rest of the graph is cache hits.
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
# zero the counters so the stats printed after the build describe THIS run:
# hits = files that did NOT recompile (unchanged vs the cache), misses = the
# files we actually changed. "Only the files we patch compile" - here it is
# in numbers, every run.
ccache -z >/dev/null 2>&1 || true

# ---- 6. gn gen - fast args. extra_cflags carries the afeye defines to
# EVERY translation unit (v8, blink, net, content) - the GN-side
# target defines stay as a second belt (see 0001 BUILD.gn note), but the
# global flag is the one that makes "hook compiled to nothing"
# structurally impossible: no propagation rule, no scope nesting, no
# public_deps chain can hide from a command-line define.
gn gen "$OUT_REL" --args="$(cat <<'EOF'
is_debug = false
is_official_build = false
is_component_build = true
symbol_level = 0
v8_symbol_level = 0
blink_symbol_level = 0
dcheck_always_on = false
treat_warnings_as_errors = false
use_remoteexec = false
use_lld = true
concurrent_links = 4
cc_wrapper = "ccache"
# libc++ clang modules make compiles uncachable by ccache (module-using
# compilations are skipped) - the chained-run architecture depends on the
# cache carrying compiled objects between 4h windows, so modules go off.
use_clang_modules = false
enable_nacl = false
v8_enable_afeye = true
blink_enable_afeye = true
network_enable_afeye = true
extra_cflags = [
  "-DV8_AFEYE=1",
  "-DBLINK_AFEYE=1",
  "-DNET_AFEYE=1",
]

# v12.5 REVERT of the v12.4 ninja-graph cut (c1628ea). That commit added 26
# gn args at once; NONE had ever passed `gn gen`, and the first two CI runs
# to clear the patch stage both died on its asserts:
#   run 35697981760: use_gio=false + use_gtk=true -> ui/gtk/BUILD.gn:16
#                    assert(use_gio, "GIO is required for building with GTK")
#   run 35700335846: enable_print_preview=false -> chrome/test/BUILD.gn:8840
#                    pulls print_preview:interactive_ui_tests UNGATED, and
#                    print_preview/BUILD.gn:11 asserts the flag
# gn args cannot be validated without the full chromium tree + buildtools
# (the local oracle is 59 files, no gn binary), so every remaining cut flag
# was a 4.5h-CI-cycle gamble. The graph cut is a build-SPEED optimization -
# it removes test/dev/remoting/print TUs, never an afeye hook, so capture
# output is byte-identical with or without it. The window-chaining + ccache
# architecture exists precisely to absorb a slower full build. Reverting to
# the ONLY args config with empirical proof of reaching ninja (obj 23531 in
# run 35618590286): the 18-arg block above. Faster unproven << slower proven.
EOF
)"

# ---- 7. build under a hard window; exiting 124 here is EXPECTED on the
# first run(s) - the ccache archive keeps the compiled objects, the next
# chained run resumes and finishes. The job must never hit the 6h runner
# cap (that is what "не вырубается" means here).
mkdir -p "$CCACHE_DIR"
set +e
timeout --signal=TERM "$BUILD_WINDOW_SECS" \
  ninja -C "$OUT_REL" -j "$(nproc)" "$NINJA_TARGET"
rc=$?
set -e
if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
  echo "== ninja failed with rc=$rc (real build error) =="
  exit "$rc"
fi
if [ ! -x "$OUT_REL/$NINJA_TARGET" ]; then
  echo "== $NINJA_TARGET not ready yet (rc=$rc) - window exhausted, cache saved, next run resumes =="
  ccache -s 2>/dev/null | sed 's/^/  ccache: /' || true
  exit 42
fi
echo "== built: $OUT_REL/$NINJA_TARGET =="
# honest per-run compile accounting: cache hits are the translation units that
# did NOT recompile; misses are (roughly) the files the patch series touches
# plus cold misses on a fresh runner.
ccache -s 2>/dev/null | sed 's/^/  ccache: /' || true
exit 0
