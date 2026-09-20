#!/usr/bin/env python3
"""Recount unified-diff hunk headers in afeye patches.

The series is anchor-style (applied with plain `git apply`, never --3way;
see SERIES.md), so line NUMBERS are approximations, but the +/- COUNTS in
each @@ header must match the hunk body exactly. This script recomputes them.
"""
import glob
import sys

MARKERS = ("diff --git ", "@@", "index ", "--- ", "+++ ", "new file mode", "deleted file mode")


def body_line(l: str) -> bool:
    if l == "":
        return False
    return l[0] in " +-\\"


def fix(path: str) -> int:
    lines = open(path).read().split("\n")
    out = []
    changed = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("@@ "):
            # parse header: @@ -a[,b] +c[,d] @@ optional-func
            head = line[3:]
            counts_part, _, func = head.partition("@@")
            try:
                old_spec, new_spec = counts_part.split()
                old_start = old_spec[1:].split(",")[0]
                new_start = new_spec[1:].split(",")[0]
            except ValueError:
                out.append(line)
                i += 1
                continue
            # collect body
            body = []
            j = i + 1
            while j < len(lines) and body_line(lines[j]):
                body.append(lines[j])
                j += 1
            ctx = sum(1 for l in body if l.startswith(" "))
            add = sum(1 for l in body if l.startswith("+"))
            rem = sum(1 for l in body if l.startswith("-") and not l.startswith("---"))
            if add == 0 and rem == 0 and ctx == 0:
                # empty hunk: drop the header entirely
                changed += 1
                i = j
                continue
            old_count = ctx + rem
            new_count = ctx + add
            old_str = f"-{old_start},0" if old_count == 0 else (
                f"-{old_start}" if old_count == 1 else f"-{old_start},{old_count}")
            new_str = f"+{new_start},0" if new_count == 0 else (
                f"+{new_start}" if new_count == 1 else f"+{new_start},{new_count}")
            new_header = f"@@ {old_str} {new_str} @@{func}"
            if new_header != line:
                changed += 1
            out.append(new_header)
            out.extend(body)
            i = j
        else:
            out.append(line)
            i += 1
    open(path, "w").write("\n".join(out))
    return changed


def main() -> None:
    total = 0
    for p in sorted(glob.glob("*.patch")):
        n = fix(p)
        if n:
            print(f"{p}: {n} hunk headers fixed")
        total += n
    print(f"done: {total} headers adjusted")


if __name__ == "__main__":
    sys.exit(main())
