#!/usr/bin/env python3
"""afeye: census of sink record files (.rec) - the runtime catch proof.

Walks every <layer>-<pid>.rec in a directory, parses the record stream
([u32 total_len][u8 kind][u8 flags][u16 rsv][u64 ts_ns][payload]) and
prints a per-(layer, kind) census. A .rec file that exists but carries
only the sink-hello record is a DEAD sink, not a catch - so this tool
also carries assertions:

    tools/rec_census.py /tmp/afeye-smoke \\
        --expect v8:script-source=1 blink:event-dispatch=1 \\
        --expect v8:call-completed=1 blink:timer=1 blink:fetch=1 net:net-request=1

Exit 0 if every expectation is met, exit 1 otherwise (with the census
printed either way). Used by the CI smoke test to prove the patched
binary REALLY captured at runtime: script sources through the v8
compile funnels, C++ -> JS entries through Invoke, event dispatches,
timers, fetches, and the network wire. Layer comes from the filename
prefix (v8- / blink- / net-), matching src/collect.rs.
"""
import argparse
import os
import struct
import sys

KIND_NAMES = {
    0: "sink-hello",
    1: "script-source",
    2: "bytecode-entry",
    3: "wasm-module",
    4: "wasm-memory",
    5: "wasm-table",
    6: "microtask-enqueue",
    7: "microtask-run",
    8: "call-completed",
    9: "atomics",
    10: "sab-backing",
    11: "crypto-op",
    12: "timer",
    13: "perf-entry",
    14: "message",
    15: "structured-clone",
    16: "fingerprint",
    17: "net-request",
    18: "net-resp-body",
    19: "websocket",
    20: "client-hints",
    21: "sw-cache",
    22: "script-source",
    23: "input",
    24: "event-dispatch",
    25: "dom-metric",
    26: "audio",
    27: "webrtc",
    28: "fetch",
    29: "dom-api",
    30: "microtask",
    31: "wasm-instance",
    32: "fn-tostring",
    33: "clock",
    34: "isolate",
    35: "worker",
    36: "nav-start",
    37: "taint-edge",
    38: "error-stack",
    39: "sink-drop",
}

HDR = struct.Struct("<IBHI")


def parse_layer(fname: str) -> str:
    stem = fname.rsplit(".", 1)[0]
    return stem.split("-", 1)[0] if "-" in stem else "?"


def census(path: str):
    buckets: dict[tuple[str, str], int] = {}
    total = bad = 0
    with open(path, "rb") as f:
        buf = f.read()
    off = 0
    while off + 16 <= len(buf):
        rec_len, kind, flags, _rsv = HDR.unpack_from(buf, off)
        if rec_len < 16 or off + rec_len > len(buf):
            tail = len(buf) - off
            if 16 <= rec_len <= 1 << 20 and 0 <= kind <= 39 and flags <= 1 and tail >= 16:
                print(f"torn tail at {path}:{off} rec_len={rec_len} have={tail}")
                break
            bad += 1
            break
        layer = parse_layer(os.path.basename(path))
        key = (layer, KIND_NAMES.get(kind, f"kind{kind}"))
        buckets[key] = buckets.get(key, 0) + 1
        total += 1
        off += rec_len
    return buckets, total, bad


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", help="directory holding <layer>-<pid>.rec files")
    ap.add_argument("--expect", action="append", default=[],
                    metavar="LAYER:KIND=MIN",
                    help="fail unless bucket LAYER:KIND has >= MIN records")
    args = ap.parse_args()

    buckets: dict[tuple[str, str], int] = {}
    files = bad_files = 0
    if os.path.isdir(args.dir):
        for name in sorted(os.listdir(args.dir)):
            if not name.endswith(".rec"):
                continue
            files += 1
            b, _t, bad = census(os.path.join(args.dir, name))
            if bad:
                bad_files += 1
            for k, v in b.items():
                buckets[k] = buckets.get(k, 0) + v

    for (layer, kind) in sorted(buckets):
        print(f"{layer}/{kind} = {buckets[(layer, kind)]}")
    print(f"#files={files} bad_files={bad_files}")

    if bad_files:
        print(f"CENSUS FAIL: {bad_files} corrupt record file(s)")
        return 1

    missing = []
    for exp in args.expect:
        try:
            bucket, minimum = exp.rsplit("=", 1)
            layer, kind = bucket.split(":", 1)
            minimum = int(minimum)
        except ValueError:
            print(f"CENSUS FAIL: bad --expect syntax: {exp!r}")
            return 1
        got = buckets.get((layer, kind), 0)
        if got < minimum:
            missing.append(f"{layer}/{kind} got {got} < {minimum}")
    if missing:
        for m in missing:
            print(f"CENSUS FAIL: {m}")
        return 1
    print("census ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
