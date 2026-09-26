#!/usr/bin/env python3
"""Cross-check every byte-carrying tag the C++ patches EMIT against the
whitelists the Rust sinkfilter uses to decide what is a sink / what carries a
value.

This is the bug class that bit twice: a patch adds a new value-bearing record
(canvas data URL, file-upload head, request headers) and the Rust side never
learns the tag, so the bytes land on disk but are silently excluded from
value-provenance. Capture without analysis is not capture.

The check mirrors src/sinkfilter.rs exactly:

  PAYLOAD_KINDS  - only these kinds are analysed at all. net-resp-body is
                   deliberately absent (gzip raw wire bytes cannot byte-match
                   decompressed script source), so its tags are informational.
  is_sink_tag():
    crypto-op | structured-clone | taint-edge | wasm-memory -> ALWAYS a sink,
        the tag name is irrelevant.
    websocket | net-request -> tag must be in SINK_TAGS (first token).
    fingerprint             -> tag must start with a VALUE_TAGS entry.

Byte-carrying emitters are EmitSpan (tag + raw bytes) and EmitTwoStr
(tag\\0value). EmitStr is prose metadata and is reported but not required.

Tags are frequently built with snprintf into a char buffer and passed as a
VARIABLE, so the literal never appears inside the Emit call. Those buffers are
resolved by scanning snprintf targets in the same patch.

usage: python3 tools/tag_cross_check.py [-v]
exit 1 if a byte-carrying tag is not reachable by the Rust whitelists.
"""
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAILS = []
OKS = 0


def check(cond, label):
    global OKS
    if cond:
        OKS += 1
        print(f"  OK   {label}")
    else:
        FAILS.append(label)
        print(f"  FAIL {label}")


def read(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


# C++ EventKind constant -> the kind name collect.rs writes into index.jsonl.
# Source of truth: patches/0001 (v8), 0005 (blink), 0011 (net) enum bodies,
# mirrored by src/collect.rs KINDS.
KIND_MAP = {
    "kCryptoOp": "crypto-op",
    "kStructuredClone": "structured-clone",
    "kTaintEdge": "taint-edge",
    "kWasmMemory": "wasm-memory",
    "kNetReq": "net-request",
    "kWebSocket": "websocket",
    "kFingerprint": "fingerprint",
    "kNetRespBody": "net-resp-body",
    "kWasmModule": "wasm-module",
    "kScriptSource": "script-source",
    "kBytecodeTrace": "bytecode-trace",
    "kMessage": "message",
    "kDomMetric": "dom-metric",
    "kAudio": "audio",
    "kWebrtc": "webrtc",
    "kInput": "input",
    "kEventDispatch": "event-dispatch",
    "kTimer": "timer",
    "kClock": "clock",
    "kIsolateBirth": "isolate",
    "kFnToString": "fn-tostring",
    "kCallCompleted": "call-completed",
    "kWasmInstance": "wasm-instance",
    "kErrorStack": "error-stack",
    "kSinkDrop": "sink-drop",
    "kSinkHello": "sink-hello",
    "kFetch": "fetch",
    "kWorker": "worker",
    "kDomApi": "dom-api",
    "kMicrotaskDrain": "microtask",
    "kNavStart": "nav-start",
}

# kinds whose every tag is a sink regardless of name (is_sink_tag arm 1)
AUTO_SINK_KINDS = {"crypto-op", "structured-clone", "taint-edge", "wasm-memory"}
# kinds gated by SINK_TAGS (is_sink_tag arm 2)
SINKLIST_KINDS = {"websocket", "net-request"}
# kind gated by VALUE_TAGS prefix match (is_sink_tag arm 3)
VALUELIST_KIND = "fingerprint"
# Tags that carry bytes but are DELIBERATELY not sinks/values. Each one was
# reviewed against the C++ emit site; they are not leaks. Adding a new byte
# tag here requires the same justification, not convenience.
EXCLUDE_TAGS = {
    # WebSocket::WebSocketEventHandler::OnDataFrame = frames RECEIVED. A sink
    # is where data LEAVES the page; ws-frame-out (0017) is the egress. An
    # inbound frame is server->page and cannot carry the token the page built.
    "ws-frame": "inbound frame (server->page), not egress",
    "ws-frame-fin": "inbound final frame (server->page), not egress",
    # GPUShaderModule::Create input: the WGSL program TEXT going in, i.e. the
    # shader source. Source material, not a token crossing a boundary. The
    # egress is webgpu/write-buffer / write-texture (already in SINK_TAGS).
    "webgpu/wgsl": "shader source input, not egress",
    # WebGPU readback is captured under kind 16 fingerprint as evidence of the
    # readback call; the map-readback bytes are device->page, not egress.
    "webgpu/map-readback": "device->page readback, not egress",
}

# kinds sinkfilter deliberately never analyses
NOT_ANALYSED = {
    "net-resp-body": "gzip raw wire bytes cannot byte-match decompressed source",
    "wasm-module": "handled by the wasm-module branch, not the sink scan",
    "script-source": "chain material, not a sink",
    "bytecode-trace": "consumed by bctrace, not sinkfilter",
    "message": "postMessage evidence, not a value sink",
    "dom-metric": "fact-only metric records",
    "audio": "audio samples go through kind 16 fingerprint records",
    "webrtc": "SDP/ICE evidence records",
    "input": "input events, trigger evidence",
    "event-dispatch": "dispatch evidence",
    "timer": "timer evidence",
    "clock": "clock read evidence",
    "isolate": "compile/jit evidence",
    "fn-tostring": "integrity evidence",
    "call-completed": "entry evidence",
    "wasm-instance": "instantiate evidence",
    "error-stack": "stack evidence",
    "sink-drop": "witness",
    "sink-hello": "liveness",
    "nav-start": "navigation marker (prose EmitStr)",
    "fetch": "fetch-call fact, the wire bytes go via net-request",
    "worker": "worker-scope marker (prose EmitStr)",
    "dom-api": "DOM identity/value records, consumed as fp evidence",
    "microtask": "microtask drain marker (prose EmitStr)",
}

# EmitSpan(<kind>, <ts>, <tag>, <bytes>, <n>)  and
# EmitTwoStr(<kind>, <ts>, <tag>, <value>)
SPAN_RE = re.compile(r"EmitSpan\s*\(([^;]*?)\);", re.S)
TWOSTR_RE = re.compile(r"EmitTwoStr\s*\(([^;]*?)\);", re.S)
STR_RE = re.compile(r"EmitStr\s*\(([^;]*?)\);", re.S)
LIT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
# snprintf(<buf>, sizeof(<buf>), "tag ...", ...) - tag built into a variable
SNPRINTF_RE = re.compile(r"snprintf\s*\(\s*(\w+)\s*,[^,]*,\s*\"((?:[^\"\\]|\\.)*)\"", re.S)
KIND_ARG_RE = re.compile(r"\b(k[A-Z]\w+)\b")


def split_args(s):
    """split a C++ argument list on top-level commas."""
    out, depth, cur = [], 0, []
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return [a.strip() for a in out]


def kind_of(arg):
    m = KIND_ARG_RE.search(arg)
    if not m:
        return None
    return KIND_MAP.get(m.group(1))


def collect():
    """-> (byte_tags, prose_tags, emitted_literals, unknown_kind).

    byte_tags / prose_tags are sets of (kind, tag) resolved from Emit calls.
    emitted_literals is EVERY plausible tag-shaped string literal in the
    patch, used only for the stale-whitelist direction: tags are frequently
    built by snprintf into a char buffer or held in a `const char*` and then
    handed to a helper wrapper (AfeyeStorageOn, AfeyeEmitAnalyserSpanF32),
    so a strict Emit-call scan cannot see them. Being loose there is safe -
    a stale whitelist entry is harmless, a missing one loses data.
    """
    byte_tags = set()
    prose_tags = set()
    unknown_kind = set()
    emitted_literals = set()
    for p in sorted(glob.glob(os.path.join(ROOT, "patches", "*.patch"))):
        body = "\n".join(
            l[1:] for l in read(p).split("\n")
            if l.startswith("+") and not l.startswith("+++")
        )
        # tag literals built into char buffers by snprintf
        buf_tags = {}
        for m in SNPRINTF_RE.finditer(body):
            buf_tags[m.group(1)] = m.group(2)
        for m in LIT_RE.finditer(body):
            lit = m.group(1).strip()
            if lit and len(lit) < 96:
                emitted_literals.add(lit)

        def resolve(arg):
            lit = LIT_RE.search(arg)
            if lit:
                return lit.group(1)
            return buf_tags.get(arg.strip())

        for rx, sink in ((SPAN_RE, True), (TWOSTR_RE, True), (STR_RE, False)):
            for m in rx.finditer(body):
                args = split_args(m.group(1))
                if len(args) < 3:
                    continue
                kind = kind_of(args[0])
                tag = resolve(args[2])
                if tag is None:
                    continue
                tag = tag.strip()
                if not tag:
                    continue
                if kind is None:
                    unknown_kind.add((os.path.basename(p), tag))
                    continue
                (byte_tags if sink else prose_tags).add((kind, tag))
    return byte_tags, prose_tags, emitted_literals, unknown_kind


def rust_list(src, name):
    m = re.search(rf"const {name}\s*:\s*&\[&str\]\s*=\s*&?\[(.*?)\];", src, re.S)
    if not m:
        return set()
    return set(re.findall(r'"([^"]*)"', m.group(1)))


def main():
    verbose = "-v" in sys.argv
    sf_path = os.path.join(ROOT, "src", "sinkfilter.rs")
    if not os.path.exists(sf_path):
        print("sinkfilter.rs missing")
        return 1
    sf = read(sf_path)
    payload_kinds = rust_list(sf, "PAYLOAD_KINDS")
    sink_tags = rust_list(sf, "SINK_TAGS")
    value_tags = rust_list(sf, "VALUE_TAGS")

    byte_tags, prose_tags, emitted_literals, unknown_kind = collect()

    print("== C++ emitted tags vs Rust sinkfilter whitelists ==")
    print(f"byte-carrying (EmitSpan/EmitTwoStr): {len(byte_tags)}")
    print(f"prose (EmitStr):                     {len(prose_tags)}")
    print(f"PAYLOAD_KINDS analysed:              {sorted(payload_kinds)}")
    print(f"SINK_TAGS: {len(sink_tags)}   VALUE_TAGS: {len(value_tags)}")

    unreachable = []
    excluded = []
    not_analysed = []
    reachable = []
    for kind, tag in sorted(byte_tags):
        if kind not in payload_kinds:
            not_analysed.append((kind, tag))
            continue
        first = tag.split(" ")[0]
        if first in EXCLUDE_TAGS:
            excluded.append((kind, tag, EXCLUDE_TAGS[first]))
            continue
        if kind in AUTO_SINK_KINDS:
            reachable.append((kind, tag, "auto-sink kind"))
        elif kind in SINKLIST_KINDS:
            if first in sink_tags:
                reachable.append((kind, tag, "SINK_TAGS"))
            else:
                unreachable.append((kind, tag, "not in SINK_TAGS"))
        elif kind == VALUELIST_KIND:
            if any(tag.startswith(v) for v in value_tags):
                reachable.append((kind, tag, "VALUE_TAGS prefix"))
            else:
                unreachable.append((kind, tag, "no VALUE_TAGS prefix"))
        else:
            not_analysed.append((kind, tag))

    if verbose:
        print("\n  reachable byte-carrying tags:")
        for kind, tag, why in reachable:
            print(f"    [{kind}] {tag!r} <- {why}")
        print("\n  deliberately excluded (reviewed, not a leak):")
        for kind, tag, why in excluded:
            print(f"    [{kind}] {tag!r} <- {why}")
        print("\n  byte-carrying tags in kinds sinkfilter never analyses:")
        for kind, tag in not_analysed:
            reason = NOT_ANALYSED.get(kind, "kind not in PAYLOAD_KINDS")
            print(f"    [{kind}] {tag!r} <- {reason}")

    print()
    check(not unreachable,
          f"every byte-carrying tag in an analysed kind is reachable or "
          f"reviewed-excluded (unreachable: {[(k, t) for k, t, _ in unreachable]})")
    for kind, tag, why in unreachable:
        print(f"    UNREACHABLE [{kind}] {tag!r}: {why}")

    # stale whitelist entries: names no patch mentions AT ALL. Matched against
    # every string literal in the series, not just resolved Emit calls, because
    # helper-wrapped emitters (AfeyeStorageOn, AfeyeEmitAnalyserSpanF32) and
    # `const char*` tags never appear inside an Emit argument list.
    stale_sink = sorted(
        t for t in sink_tags
        if not any(lit == t or lit.startswith(t + " ") for lit in emitted_literals)
    )
    stale_value = sorted(
        v for v in value_tags
        if not any(lit.startswith(v) for lit in emitted_literals)
    )
    check(not stale_sink, f"SINK_TAGS all have an emitter (stale: {stale_sink})")
    check(not stale_value, f"VALUE_TAGS all have an emitter (stale: {stale_value})")

    if unknown_kind:
        print(f"\n  note: {len(unknown_kind)} emit(s) with an unmapped kind constant:")
        for f, t in sorted(unknown_kind):
            print(f"    {f}: {t!r}")

    print(f"\n== summary: {OKS} OK, {len(FAILS)} FAIL ==")
    for f in FAILS:
        print(f"  FAIL: {f}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
