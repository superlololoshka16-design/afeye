#!/usr/bin/env python3
"""Cross-check the WIRE v3 24-byte record header contract between the C++
patch side (sink emitters, tools, tests) and the Rust parser side (collect.rs
and friends). One layout, many independent authors - this catches drift.

Contract (LE):
  [0..4]   u32 total = 24 + payload_len   (24 <= total <= 24 + 1MiB)
  [4]      u8 kind   (0..=40)
  [5]      u8 flags  (bit0 truncated)
  [6..10]  u32 sid   (script id; 0 = none / kind 40 / kind 39 / net layer)
  [10..12] u16 tid   (causality ambient low16; 0 = none)
  [12..16] u32 reserved = 0
  [16..24] u64 ts_ns (CLOCK_MONOTONIC)
  payload at offset 24

Checks performed per file class; each check prints OK/FAIL. exit 1 on any FAIL.
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


def read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def patch_added_lines(path):
    """concatenate only '+' lines of a patch (what lands in the tree)."""
    out = []
    for l in read(path).split("\n"):
        if l.startswith("+") and not l.startswith("+++"):
            out.append(l[1:])
    return "\n".join(out)


def main():
    patches = os.path.join(ROOT, "patches")
    src = os.path.join(ROOT, "src")
    tools = os.path.join(ROOT, "tools")
    tests = os.path.join(ROOT, "tests")

    print("== C++ sink layers: 24-byte header assembly ==")
    for name, p in [
        ("v8", os.path.join(patches, "0001-v8-sink.patch")),
        ("blink", os.path.join(patches, "0005-blink-sink.patch")),
        ("net", os.path.join(patches, "0011-net-wire.patch")),
    ]:
        if not os.path.exists(p):
            FAILS.append(f"{name}: patch missing")
            continue
        body = patch_added_lines(p)
        # header assembly must write ts at +16 and payload at +24
        check(re.search(r"rec \+ 16, &ts_ns|rec\+16|memcpy\(rec \+ 16", body) is not None,
              f"{name} sink: ts written at rec+16")
        check(re.search(r"rec \+ 24|rec\+24", body) is not None,
              f"{name} sink: payload copied at rec+24")
        check("24 +" in body or "+ 24" in body or "kHeaderSize = 24" in body
              or "= 24u" in body or "16 + 8" in body,
              f"{name} sink: total = 24 + payload_len arithmetic present")
        # sid/tid fill (v8/blink) or zero-fill (net)
        if name == "net":
            check("AfeyeFillAttrs" in body or re.search(r"rec\[6\] = 0|memset\(rec \+ 6, 0, 6\)|sid", body) is not None,
                  "net sink: sid/tid zero-fill present")
        else:
            check("AfeyeFillAttrs" in body or ("sid" in body and "tid" in body),
                  f"{name} sink: sid/tid fill present")
        # kind 40/39 gate for attrs
        if name == "v8":
            check(re.search(r"kind == 40|kBytecodeTrace", body) is not None,
                  "v8 sink: kind-40 attr gate present")

    print("\n== bcrec.h: kSinkRecordCap for 24-byte wire header ==")
    bcrec_patch = os.path.join(patches, "0033-v8-ignition-bytecode-trace.patch")
    if os.path.exists(bcrec_patch):
        body = patch_added_lines(bcrec_patch)
        m = re.search(r"kSinkRecordCap\s*=\s*\((1u?\s*<<\s*20)\)\s*-\s*(\d+)", body)
        check(m is not None and int(m.group(2)) == 24,
              "bcrec.h: kSinkRecordCap = (1<<20) - 24")
        check("sizeof(Hdr) == 72" in body,
              "bcrec.h: bcrec Hdr stays 72 bytes (inside payload, unchanged)")

    print("\n== Rust collect.rs: parser matches wire v3 ==")
    collect = read(os.path.join(src, "collect.rs")) if os.path.exists(os.path.join(src, "collect.rs")) else ""

    def const_u(needle_name, text):
        """resolve `const NAME: <ty> = <expr>;` to an int, accepting a
        named constant instead of a literal (HDR / MAX_RECORD)."""
        m = re.search(rf"const {needle_name}\s*:\s*\w+\s*=\s*([^;]+);", text)
        if not m:
            return None
        expr = m.group(1).strip()
        try:
            return eval(expr, {"__builtins__": {}}, {})
        except Exception:
            # resolve a single indirection: const HDR: usize = 24;
            m2 = re.match(r"^(\w+)$", expr)
            if m2:
                inner = const_u(m2.group(1), text)
                if inner is not None:
                    return inner
            return None

    hdr = const_u("HDR", collect)
    maxrec = const_u("MAX_RECORD", collect)
    check(hdr == 24, f"collect.rs: HDR const == 24 (found {hdr})")
    check(maxrec == 24 + (1 << 20),
          f"collect.rs: MAX_RECORD == 24+(1<<20) (found {maxrec})")
    # ts must be read from the wire v3 slot [16..24], never the v2 [8..16]
    check(re.search(r"rec\[16\][^\n]*rec\[23\]|rec\[16\.\.24\]", collect) is not None,
          "collect.rs: ts read from [16..24]")
    check(re.search(r"u64::from_le_bytes\(\[\s*rec\[8\]", collect) is None,
          "collect.rs: no ts read starting at rec[8] (wire v2)")
    check("rec[HDR..]" in collect or "&rec[24..]" in collect,
          "collect.rs: payload slice starts at HDR/24")
    check(re.search(r'"sid"', collect) is not None,
          "collect.rs: index.jsonl carries sid")
    check(re.search(r'"tid"', collect) is not None,
          "collect.rs: index.jsonl carries tid")
    check("Arc<Mutex" not in collect, "collect.rs: no Arc<Mutex<>>")
    check("BTreeMap<(u8, u8)" in collect or "BTreeMap<(u8,u8)" in collect,
          "collect.rs: per-counts keyed by (layer,kind) not String")

    print("\n== Rust bctrace.rs: bcrec Hdr still parsed at payload[0] ==")
    bctrace = read(os.path.join(src, "bctrace.rs")) if os.path.exists(os.path.join(src, "bctrace.rs")) else ""
    # strip line comments so a sentence mentioning a banned type is not
    # mistaken for code that uses it
    bctrace_code = re.sub(r"//[^\n]*", "", bctrace)
    check("HDR_LEN: usize = 72" in bctrace_code,
          "bctrace.rs: HDR_LEN stays 72 (bcrec header inside payload)")
    check("valuebook.bin" in bctrace, "bctrace.rs: streams valuebook.bin")
    check("exec_funcs.bin" in bctrace, "bctrace.rs: streams exec_funcs.bin")
    check("ops.txt" in bctrace, "bctrace.rs: writes ops.txt")
    check("offset_mismatch" in bctrace_code,
          "bctrace.rs: wide-offset mismatch witness")
    check("Vec<InstrRec>" not in bctrace_code,
          "bctrace.rs: no whole-stream Vec<InstrRec> in RAM")
    check("script_ids" in bctrace_code, "bctrace.rs: script_ids map for sid attribution")

    print("\n== matcher (Aho-Corasick) exists, sam.rs absent ==")
    check(os.path.exists(os.path.join(src, "matcher.rs")), "src/matcher.rs exists")
    check(not os.path.exists(os.path.join(src, "sam.rs")), "src/sam.rs absent")
    check(not os.path.exists(os.path.join(src, "valueflow.rs")), "src/valueflow.rs removed")
    lib = read(os.path.join(src, "lib.rs")) if os.path.exists(os.path.join(src, "lib.rs")) else ""
    check("pub mod matcher" in lib, "lib.rs: pub mod matcher")
    check("pub mod sam" not in lib and "pub mod valueflow" not in lib,
          "lib.rs: no sam/valueflow modules")
    if os.path.exists(os.path.join(src, "matcher.rs")):
        m = read(os.path.join(src, "matcher.rs"))
        check("out_link" in m, "matcher.rs: out-link optimization present")
        check("binary_search" in m or "partition_point" in m,
              "matcher.rs: sorted-transition lookup")

    print("\n== sinkfilter.rs: fact verdicts only ==")
    sf_path = os.path.join(src, "sinkfilter.rs")
    if os.path.exists(sf_path):
        sf = read(sf_path)
        for banned in ["FP_GRACE_NS", "NET_FP_WINDOW_NS", "CONTENT_LINK_GRACE_NS",
                       "ENTRY_JOIN_WINDOW_NS", "GRAPH_MAX_HOPS", "run_keys",
                       "blake3::hash", "extract_alphabets", "decode_custom_alphabet",
                       "chain_signals", "is_hot", "HOT_PATTERNS", "token_forming",
                       "drops_witnessed", "graph_hops_for"]:
            check(banned not in sf, f"sinkfilter.rs: {banned} gone")
        for required in ["causality", "ac_matches", "proven_causality",
                         "proven_value", "unavailable", "exec_funcs",
                         "matcher::AhoCorasick", "shutdown.json"]:
            check(required in sf, f"sinkfilter.rs: {required} present")
        # wasm-Liftoff emits "exec jit" with EMPTY script= (no JS SharedFunctionInfo);
        # only a JS tier-up (non-empty script) is a real interpreter-pin violation.
        check("as_ref().map(|s| !s.is_empty())" in sf or "wasm-Liftoff" in sf,
              "sinkfilter.rs: exec-jit violation gated to JS (wasm-Liftoff exempt)")
        # wire carries tid as low16 only; a long crawl can collide two distinct
        # causality trees into one low16 -> matching it would assert a FALSE
        # proven. Ambiguous low16 must be blacklisted from causality linking.
        check("ambig_low16" in sf and "tid_low16_collisions" in sf,
              "sinkfilter.rs: ambiguous low16 blacklisted (no false causality proven)")

    print("\n== main/browser: integrity gate + jitless default + marker ==")
    main = read(os.path.join(src, "main.rs")) if os.path.exists(os.path.join(src, "main.rs")) else ""
    browser = read(os.path.join(src, "browser.rs")) if os.path.exists(os.path.join(src, "browser.rs")) else ""
    check("google-chrome-stable" not in main, "main.rs: stock chrome candidates removed")
    check("afeye-sink/" in main, "main.rs: patched-binary marker check present")
    check("shutdown.json" in main, "main.rs: writes shutdown.json")
    check("gate_passed" in main, "main.rs: gate_passed field")
    check("AF_JITLESS" not in browser, "browser.rs: jitless no longer env-optional")
    # --jitless sets v8_flags.wasm_jitless -> wasm only via DrumbraKE (not in
    # this build) -> WASM antifraud (kasada/datadome/perimeterx) would never
    # run. Must NOT be used; JS stays interpreted via --no-opt/--no-sparkplug
    # /--no-maglev instead, which keeps wasm-Liftoff alive.
    check('"--jitless"' not in browser,
          "browser.rs: NO --jitless (it disables wasm execution)")
    check("--no-sparkplug" in browser and "--no-maglev" in browser,
          "browser.rs: JS pinned to interpreter via --no-opt/--no-sparkplug/--no-maglev")
    # vclock must be OPT-IN, not default. It advances Date.now() by executed
    # instruction count at 10ns/instruction; under the bytecode trace that is
    # 2-5% of wall time, so a 38-minute crawl leaves the page 36+ minutes
    # behind. An antifraud token's timestamp is compared against the server
    # clock -> unconditional vclock means every token is rejected. A naive
    # "string present" check passes on the comment alone and would bless the
    # broken behaviour, so assert the gate explicitly.
    check('var("AF_VCLOCK")' in browser,
          "browser.rs: vclock gated behind AF_VCLOCK (off by default)")
    check(re.search(r'if !jit_allowed\(\)\s*\{\s*\n\s*c\.env\("AFEYE_VIRTUAL_CLOCK"', browser) is None,
          "browser.rs: vclock NOT unconditionally enabled")
    check("AFEYE_TRACE_BYTECODE" in browser, "browser.rs: trace env passed to chrome")
    # chrome must launch headless by default: headful needs an X server and
    # Xvfb was removed, so a headful launch fails before it starts. Must NOT
    # be headless_shell either - the stripped binary kills antifraud
    # self-checks silently.
    check("fn headful()" in browser,
          "browser.rs: headless unless AF_HEADFUL + a real DISPLAY")
    drv = read(os.path.join(src, "drive.rs")) if os.path.exists(os.path.join(src, "drive.rs")) else ""
    # ONE foreground tab at a time. Concurrent per-tab tasks are physically
    # impossible: background tabs report visibilityState 'hidden', get no
    # rAF, and Input delivered to them arrives without focus.
    check("bring_to_front" in drv,
          "drive.rs: brings the tab to the foreground before driving it")
    check("tokio::spawn" not in drv,
          "drive.rs: no concurrent per-tab tasks (single foreground session)")
    check("struct Session" in drv, "drive.rs: session context struct (>3 args)")
    check("allow(clippy" not in drv, "drive.rs: no clippy allow (repo forbids it)")
    # The load gate. Under --no-opt --no-sparkplug --no-maglev JS runs 10-50x
    # slower, so a sign-up page that loads in 3s takes 30-150s. A fixed gaze
    # budget of a few seconds means the driver starts clicking an empty tree.
    check("fn content_ready" in drv,
          "drive.rs: content gate (do not click a page that has not rendered)")
    check("READ_GIVE_UP" in drv, "drive.rs: content gate has a hard ceiling")
    # start lives INSIDE Phase::Read so forgetting to reset it is a compile
    # error, not a silent bug measuring the ceiling from session start.
    check("Read { until: Instant, start: Instant }" in drv,
          "drive.rs: READ ceiling carried in the phase variant (not a stale field)")
    # A latched submit must be releasable without navigation, otherwise
    # multi-step SPA wizards (URL never changes) fill step 2 forever.
    check(drv.count("s.submitted = false") >= 5,
          "drive.rs: submitted latch releasable (SPA multi-step support)")
    # No Walk clone on the load-gate poll: it fires ~every 900ms while the
    # page loads, and Walk carries up to 32KB of page text.
    check("s.scan = Some(w.clone())" not in drv,
          "drive.rs: load-gate scan is moved, not cloned per poll")
    # Coordinates go stale: challenge widgets animate and resize while
    # rendering, so any sleep between getBoxModel and the click means
    # clicking where the element no longer is. The hesitation (a human
    # looking before reaching) must come BEFORE measuring, never after.
    stale = re.search(r"geometry\(page, &f\)\.await[^}]*?tokio::time::sleep", drv, re.S)
    check(stale is None,
          "drive.rs: no sleep between geometry() and click() (stale coords)")
    # Marking an unresolvable field `acted` is a lie: it stays empty,
    # form_ready() calls the form complete, we submit a hole and bounce on
    # validation forever. But never marking it is an infinite loop on the
    # same element. Bounded retries are the only correct answer.
    check("MAX_FIELD_TRIES" in drv and "unreachable" in drv,
          "drive.rs: unresolvable fields retried a bounded number of times")
    # the retry counters must reset on navigation, else a new page inherits
    # the old give-up counts and gives up on fresh fields immediately
    check("s.unreachable.clear()" in drv,
          "drive.rs: unreachable counters reset on navigation")

    print("\n== alien modules deleted ==")
    for f in ["src/tg.rs", "src/human.rs", "src/inject.rs", "src/relay.rs",
              "src/wg.rs", "src/bin/jscheck.rs", "targets.json",
              "queue/pending.json", "state/cadence.json", "tools/push-js.py",
              ".github/workflows/afeye.yml"]:
        check(not os.path.exists(os.path.join(ROOT, f)), f"{f} deleted")

    print("\n== tools/tests: 24-byte header ==")
    # tools/*_main.cc are smoke tests that CALL the sink API (Emit/EmitStr/
    # EmitSpan); the 24-byte header is assembled inside sink.cc (the patches),
    # not in the tool. So the tool only has to NOT hardcode a stale 16-byte
    # total. A tool that builds a record by hand must use 24.
    for t in glob.glob(os.path.join(tools, "*_main.cc")):
        body = read(t)
        stale = re.search(r"\b16 \+ (?:static_cast<uint32_t>\()?n\b|total = 16 \+|"
                          r"uint8_t rec\[16 \+", body)
        check(stale is None,
              f"{os.path.basename(t)}: no stale 16-byte header arithmetic")
    census = os.path.join(tools, "rec_census.py")
    if os.path.exists(census):
        c = read(census)
        check(re.search(r"IBH I|<IBHIHII|sid", c) is not None or "24" in c,
              "rec_census.py: struct matches 24-byte header")
    for t in glob.glob(os.path.join(tests, "*.rs")):
        body = read(t)
        check("16 + payload" not in body, f"{os.path.basename(t)}: no stale 16-byte total")

    print("\n== crawler stimulus + non-destructive raw (the mission) ==")
    drive = read(os.path.join(src, "drive.rs")) if os.path.exists(os.path.join(src, "drive.rs")) else ""
    motor = read(os.path.join(src, "motor.rs")) if os.path.exists(os.path.join(src, "motor.rs")) else ""
    input_layer = drive + motor
    check(drive != "", "src/drive.rs exists (form model + phases)")
    check(motor != "", "src/motor.rs exists (human motor model)")
    check("DispatchMouseEvent" in motor, "motor.rs: trusted CDP mouse events")
    check("DispatchKeyEvent" in motor, "motor.rs: trusted CDP key events")
    check("ReloadParams" in drive, "drive.rs: Page.reload to re-trigger challenges")

    # The physical event state that distinguishes a device from a synthesised
    # event. Omitting any of these is a bot tell that antifraud reads
    # directly off the event object.
    check(".force(" in motor, "motor.rs: sets force (press=1, hover=0)")
    check(".buttons(" in motor, "motor.rs: sets pressed-button mask")
    check("DispatchMouseEventPointerType" in motor,
          "motor.rs: reports pointer device type")
    check(".location(" in motor, "motor.rs: sets DOMKeyLocation (Shift=1/2)")
    check(".unmodified_text(" in motor, "motor.rs: sets unmodifiedText")
    check("DispatchKeyEventType::Char" in motor,
          "motor.rs: emits discrete char events for printable keys")
    check("ShiftLeft" in motor,
          "motor.rs: dispatches Shift as its own key (not just modifiers)")
    check(".auto_repeat(" in motor, "motor.rs: sets auto_repeat flag")
    # TIME-based sampling: a 125Hz mouse emits at constant density no matter
    # how fast the hand moves. Sampling by distance inverts the physics.
    check("SAMPLE_MS" in motor, "motor.rs: constant-rate (time-based) mouse sampling")
    check("min_jerk" in motor, "motor.rs: minimum-jerk reach profile")
    check("fitts_ms" in motor, "motor.rs: Fitts' law movement time")
    check("TREMOR_PX" in motor, "motor.rs: idle micro-tremor (no frozen pointer)")
    check("keystroke_ms" in motor, "motor.rs: bigram-paced keystroke cadence")

    # The driver must model the form, not click controls at random: a
    # submit before every field is filled yields a validation error and the
    # challenge never fires.
    check("fn form_ready" in drive, "drive.rs: submit hard-gated on form_ready")
    check("fn focus_field" in drive, "drive.rs: focus model (Tab, not re-click)")
    check("enum Phase" in drive, "drive.rs: explicit read/work/observe phases")
    check("CHALLENGE_HOSTS" in drive,
          "drive.rs: cross-origin challenge frames detected by URL, not page text")
    check("MAX_SUBMIT_TRIES" in drive, "drive.rs: error-repair loop is bounded")

    # stimulus must be pure observation: no fabricated requests, no spoofing,
    # no JS injection. Strip comments first - the files document these bans in
    # prose ("NEVER Runtime.evaluate"), and matching raw text would fail the
    # very rule the prose states.
    def strip_comments(s):
        s = re.sub(r"//[^\n]*", "", s)
        return re.sub(r"/\*.*?\*/", "", s, flags=re.S)

    clean = strip_comments(input_layer)
    check("credentials" not in clean,
          "input layer: no synthetic fetch(credentials) poke")
    check("Runtime.evaluate" not in clean and "EvaluateParams" not in clean,
          "input layer: no Runtime.evaluate JS injection")
    check("getParameter" not in clean and "37445" not in clean,
          "input layer: no WebGL fingerprint spoofing")
    main = read(os.path.join(src, "main.rs")) if os.path.exists(os.path.join(src, "main.rs")) else ""
    check("drive::drive(" in main, "main.rs: driver spawned for the session")
    check("mod drive;" in main, "main.rs: drive module declared")
    check("mod motor;" in main, "main.rs: motor module declared")
    # the session must not be a bare sleep_until (dead crawler = no stimulus)
    check("sleep_until(end) => {}" not in main or "drive::drive(" in main,
          "main.rs: session drives input, not a passive sleep")
    cls = read(os.path.join(src, "classify.rs")) if os.path.exists(os.path.join(src, "classify.rs")) else ""
    # The engine layer is the product and must survive classification. classify
    # only READS collect/filtered/report.json (the proven-facts bridge) and
    # never writes under collect/ - raw .rec, bctrace and sinkfilter output are
    # untouchable. What classify prunes is the CDP layer (timeline + artifacts),
    # which is the intended behaviour: that pruning IS the product.
    check("collect\")\n        .join(\"filtered\")\n        .join(\"report.json\")" in cls
          or 'join("collect").join("filtered").join("report.json")' in cls,
          "classify.rs: reads sinkfilter report.json (engine-fact bridge)")
    check("proven_scripts" in cls and "tainted.extend(proven_scripts(stage))" in cls,
          "classify.rs: seeds taint from engine proven facts, not kk-heuristics")
    # classify reads collect/filtered/report.json but must never WRITE under
    # collect/: that is where the raw .rec dumps, bctrace output and sinkfilter
    # report live - the actual product.
    writes_in_collect = re.search(
        r'(remove_file|remove_dir_all|File::create|OpenOptions|fs::write|rename)'
        r'[^;\n]*collect', cls)
    check(writes_in_collect is None,
          "classify.rs: no write/delete under collect/ (engine data intact)")
    cap = read(os.path.join(src, "capture.rs")) if os.path.exists(os.path.join(src, "capture.rs")) else ""
    ev = read(os.path.join(src, "events.rs")) if os.path.exists(os.path.join(src, "events.rs")) else ""
    # the crawler must record EVERY rendered image byte-for-byte + hash;
    # storable() must not return None for images, sniff() must resolve formats
    check('resource == "Image"' in cap or "image/" in cap,
          "capture.rs: storable() keeps image resources (not None)")
    check("0x89, b'P', b'N', b'G'" in cap or "PNG" in cap,
          "capture.rs: sniff() resolves png magic")
    check("0xff, 0xd8, 0xff" in cap, "capture.rs: sniff() resolves jpg magic")
    check("GIF8" in cap, "capture.rs: sniff() resolves gif magic")
    check("WEBP" in cap, "capture.rs: sniff() resolves webp magic")
    check("E_PNG" in ev and "E_JPG" in ev and "E_WEBP" in ev,
          "events.rs: image format ext codes defined")
    # media must not starve the crown jewels: images/fonts/bin draw from a
    # SEPARATE budget so a banner-heavy page cannot evict antifraud JS or
    # POST bodies (tokens) via post_art's drop path.
    check("fn is_media" in cap, "capture.rs: is_media() classifies media codes")
    check("img_budget" in cap, "capture.rs: post_art routes media to img_budget")
    ctxs = read(os.path.join(src, "ctx.rs")) if os.path.exists(os.path.join(src, "ctx.rs")) else ""
    check("img_budget" in ctxs, "ctx.rs: Ctx carries img_budget counter")
    check("img_budget_limit" in main, "main.rs: img_budget_limit defined")
    check("img_budget_used" in main, "main.rs: manifest reports img_budget_used")
    # per-tab meta DashMap must be consumed, not leaked: on_fin removes the
    # entry (single-use), on_fail removes entries for requests that never
    # fire loadingFinished. Otherwise the map grows unbounded on a long crawl.
    check("tb.meta.remove(" in cap, "capture.rs: on_fin/on_fail consume meta entries (no unbounded DashMap growth)")
    check("fn on_fail" in cap and "on_fail)" in cap,
          "capture.rs: on_fail registered to clean failed-request meta")

    print(f"\n== summary: {OKS} OK, {len(FAILS)} FAIL ==")
    for f in FAILS:
        print(f"  FAIL: {f}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
