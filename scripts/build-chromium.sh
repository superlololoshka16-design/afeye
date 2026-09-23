#!/usr/bin/env bash
set -euo pipefail

CHROMIUM_REF="${CHROMIUM_REF:-153.0.8010.52}"
WORK="${WORK:-/mnt/chromium}"
OUT_REL="${OUT_REL:-out/afeye}"
NINJA_TARGET="${NINJA_TARGET:-chrome}"
BUILD_WINDOW_SECS="${BUILD_WINDOW_SECS:-16200}"
CCACHE_DIR="${CCACHE_DIR:-/mnt/ccache}"

echo "== afeye build: chromium $CHROMIUM_REF, target $NINJA_TARGET, window ${BUILD_WINDOW_SECS}s =="

sudo rm -rf /usr/local/lib/android /usr/share/dotnet /opt/ghc \
            /usr/local/.ghcup /opt/hostedtoolcache/CodeQL 2>/dev/null || true
df -h / | tail -1

if [ ! -d "$WORK/depot_tools" ]; then
  git clone -q --depth 1 https://chromium.googlesource.com/chromium/tools/depot_tools.git "$WORK/depot_tools"
fi
export PATH="$WORK/depot_tools:$PATH"
gclient --version >/dev/null 2>&1 || true

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

sudo ./build/install-build-deps.sh --no-arm >/dev/null 2>&1 || \
  sudo ./build/install-build-deps.sh --no-arm || true

REPO_ROOT="${REPO_ROOT:-$GITHUB_WORKSPACE}"
for p in "$REPO_ROOT"/patches/*.patch; do
  echo "applying $(basename "$p")"
  git apply "$p" || patch -p1 --fuzz=0 --no-backup-if-mismatch < "$p"
done

export CCACHE_DIR
ccache -M 9G >/dev/null 2>&1 || ccache --max-size=9G >/dev/null || true
ccache -z >/dev/null 2>&1 || true

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

EOF
)"

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
ccache -s 2>/dev/null | sed 's/^/  ccache: /' || true
exit 0
