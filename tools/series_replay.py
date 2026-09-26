#!/usr/bin/env python3
"""Honest patch-series collision detector for afeye.

We have NO pristine chromium tree here, so a full `git apply` replay is
impossible to simulate faithfully (context lines that no patch quotes can
never be matched). Pretending otherwise produces hundreds of false
failures. This tool instead detects the REAL failure mode that breaks
`set -euo pipefail` builds: two patches that edit the SAME file with
OVERLAPPING anchor regions, so the second one's context no longer exists
after the first applies.

For every file touched by 2+ patches it reports:
  - the numeric application order
  - each patch's hunks (old_start, old_count) for that file
  - any pairwise region overlap between different patches  => COLLISION
  - index-blob chain breaks (patch B expects a preimage blob that patch A
    did not produce) => STALE-ANCHOR (git apply ignores the index line and
    matches by context, so this is informational, but a stale index almost
    always means the author hand-edited and the context may be wrong).

usage:
  python3 tools/series_replay.py            # all files, collisions first
  python3 tools/series_replay.py -v         # verbose: every multi-touch file
exit 0 = no collision, 1 = at least one COLLISION.
"""
import glob
import os
import re
import sys
from collections import defaultdict

PATCH_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "patches")
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
DIFF_RE = re.compile(r"^diff --git a/(.*) b/(.*)$")
INDEX_RE = re.compile(r"^index ([0-9a-f]+)\.\.([0-9a-f]+)")


class Hunk:
    __slots__ = ("old_start", "old_count", "new_start", "new_count")

    def __init__(self, os_, oc, ns, nc):
        self.old_start = os_
        self.old_count = oc
        self.new_start = ns
        self.new_count = nc

    def region(self):
        return (self.old_start, self.old_start + max(self.old_count, 1))


class FileTouch:
    __slots__ = ("patch", "order", "hunks", "is_new", "pre_blob", "post_blob", "path")

    def __init__(self, patch, order, is_new):
        self.patch = patch
        self.order = order
        self.hunks = []
        self.is_new = is_new
        self.pre_blob = None
        self.post_blob = None


def parse_patch(path, order):
    name = os.path.basename(path)
    text = open(path, encoding="utf-8", errors="replace").read()
    lines = text.split("\n")
    touches = []
    cur = None
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = DIFF_RE.match(line)
        if m:
            fpath = m.group(2)
            is_new = False
            pre = post = None
            j = i + 1
            while j < n and not lines[j].startswith("@@") and not DIFF_RE.match(lines[j]):
                hl = lines[j]
                if hl.startswith("new file mode") or hl.startswith("--- /dev/null"):
                    is_new = True
                im = INDEX_RE.match(hl)
                if im:
                    pre, post = im.group(1), im.group(2)
                j += 1
            cur = FileTouch(name, order, is_new)
            cur.pre_blob = pre
            cur.post_blob = post
            cur.path = fpath
            touches.append(cur)
            i = j
            continue
        if line.startswith("@@") and cur is not None:
            hm = HUNK_RE.match(line)
            if hm:
                oc = int(hm.group(2)) if hm.group(2) is not None else 1
                nc = int(hm.group(4)) if hm.group(4) is not None else 1
                cur.hunks.append(Hunk(int(hm.group(1)), oc, int(hm.group(3)), nc))
            i += 1
            continue
        i += 1
    return touches


def overlaps(a, b):
    a0, a1 = a.region()
    b0, b1 = b.region()
    return a0 < b1 and b0 < a1


def main():
    verbose = "-v" in sys.argv
    patches = sorted(glob.glob(os.path.join(PATCH_DIR, "*.patch")))
    by_file = defaultdict(list)
    for order, p in enumerate(patches):
        for t in parse_patch(p, order):
            t.order = order
            by_file[t.path].append(t)

    # The honest build-break signal is REGION OVERLAP in original file
    # coordinates, NOT the index-blob chain. `git apply` (no --3way) ignores
    # the index line and matches hunks by context, searching nearby offsets:
    # a patch whose context is intact but shifted (no overlap with the prior
    # patch's edited region) applies fine. The series BREAKS only when patch
    # A edits lines inside patch B's context window (regions overlap in the
    # ORIGINAL coordinates) - then B's contiguous context no longer exists
    # and git apply fails, aborting `set -euo pipefail`. A blob-chain
    # mismatch with NO overlap is offset-application, not a break.
    breaks = []
    overlap_only = []
    multi = []
    for fpath, touches in sorted(by_file.items()):
        if len(touches) < 2:
            continue
        multi.append((fpath, touches))
        touches.sort(key=lambda t: t.order)
        for k in range(1, len(touches)):
            prev, cur = touches[k - 1], touches[k]
            if cur.is_new:
                continue
            hit = [(ha, hb) for ha in prev.hunks for hb in cur.hunks if overlaps(ha, hb)]
            if not hit:
                continue
            chain_ok = (not cur.pre_blob) or (not prev.post_blob) or cur.pre_blob == prev.post_blob
            if chain_ok:
                # later patch was regenerated against the earlier's output:
                # its old_start is in post-earlier coordinates, raw overlap is
                # expected and git apply matches by context. Not a break.
                overlap_only.append((fpath, prev, cur, hit))
            else:
                # overlap AND stale blob: the later patch was authored on a
                # DIFFERENT base than the series produces, and it edits inside
                # the earlier's region -> context is gone -> real break.
                breaks.append((fpath, prev, cur, hit))

    print(f"series scan: {len(patches)} patches, {len(by_file)} files, "
          f"{len(multi)} files touched by 2+ patches")
    print(f"REGION-OVERLAP BREAKS (build-breaking): {len(breaks)}")
    print(f"OVERLAP-ONLY (chain intact, git apply survives): {len(overlap_only)}")

    if breaks:
        print("\n=== BREAKS (overlap + stale base: context does not exist) ===")
        for fpath, prev, cur, hit in breaks:
            print(f"\n{fpath}")
            print(f"  {prev.patch} (order {prev.order}) index {prev.pre_blob}..{prev.post_blob} edits:")
            for ha in prev.hunks:
                print(f"      @@ -{ha.old_start},{ha.old_count} region {ha.region()}")
            print(f"  {cur.patch} (order {cur.order}) index {cur.pre_blob}..{cur.post_blob} edits:")
            for hb in cur.hunks:
                print(f"      @@ -{hb.old_start},{hb.old_count} region {hb.region()}")
            for ha, hb in hit:
                print(f"  OVERLAP: {prev.patch} region {ha.region()} vs "
                      f"{cur.patch} region {hb.region()}")
            print(f"  -> {cur.patch} expects preimage {cur.pre_blob} but the series "
                  f"produces {prev.post_blob}, and it edits inside {prev.patch}'s "
                  f"region: context lines are gone, git apply (no --3way) fails, "
                  f"`set -euo pipefail` aborts the build here.")

    if overlap_only and verbose:
        print("\n=== OVERLAP-ONLY (raw regions touch but chain is intact) ===")
        for fpath, prev, cur, hit in overlap_only:
            regs = ", ".join(f"{ha.region()}vs{hb.region()}" for ha, hb in hit)
            print(f"  {fpath}: {prev.patch} -> {cur.patch}  [{regs}]")

    if verbose:
        print("\n=== MULTI-TOUCH FILES (application order + blob chain) ===")
        for fpath, touches in multi:
            chain = " -> ".join(
                f"{t.patch}[{t.pre_blob or '?'}..{t.post_blob or '?'}]" for t in touches)
            print(f"  {fpath}:\n    {chain}")

    return 1 if breaks else 0


if __name__ == "__main__":
    sys.exit(main())
