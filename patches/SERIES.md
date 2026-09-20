# afeye chromium patch series v12.2

**v12.1 is the six-agent audit + repair pass.** Six parallel audits (v8
layer, blink layer, net layer, sink core, Rust filter, driver) walked every
patch against the pristine tree AND the Rust driver end-to-end. They found
the deep filter had NEVER run on real data (the collector wrote to
`stage/collect` while the filter read `stage/<slot>/collect` since v4), the
CI crawl gate never wrote `$GITHUB_OUTPUT` (the scheduled run never
crawled), and four patch defects that `git apply` passes but the compiler
kills. All fixed:

**patch fixes (apply-verified 24/24 against pristine after each edit):**

- **0024 (compile blockers):** `v8::String::NO_NULL_TERMINATION` does not
  exist at this rev (WriteFlags rework) - the string readback is now
  `WriteUtf8` (correct pairing: returns UTF-8 BYTES, the old
  `Utf8Length`+`WriteOneByte` copied CODE UNITS into a bytes-sized buffer -
  multi-byte strings truncated + stale stack tail leaked into .rec files);
  include `v8-container.h` (v8-array.h does not exist; Array lives there);
  size_t math (Utf8Length returns size_t; -Werror would fail the int
  narrowing); `[array len=%u]` with the uint32 cast.
- **0015 (compile blockers):** `PositionInWindow()` -> `PositionInWidget()`
  (does not exist at 153); `unique_pointer_id` -> `id` (int32 PointerId);
  `pressure` -> `force` (web_pointer_properties.h).
- **0007 (compile blockers):** the media_device_info emit block sat at
  NAMESPACE scope after the ctor brace (hard error) - now inside the ctor
  body; `GetAsArrayBufferView()` returns `NotShared<DOMArrayBufferView>`
  (raw-pointer assignment does not compile) - now `.Get()` with the null
  check.
- **0017 (dead hook):** the reassembly-path guard read `bytes_reassembled_`
  AFTER the line above zeroed it - always false, so fragmented
  do_not_fragment outbound WS (the Kasada/HUMAN telemetry shape) never
  emitted. Now guards on `data_frame->data_length` and reads
  `message_under_reassembly_->bytes()` (alive; the std::move happens in
  SendFrame below).
- **0013 + 0021 (graph admission):** both emitted PROSE (EmitStr) with no
  NUL tag; the Rust VALUE_TAGS gate splits on NUL, so cookie/storage values
  and the json-stringify head NEVER joined the content graph - the claimed
  store-then-send cookie relay and stringify->req-body edge did not exist.
  Both now emit `EmitSpan(tag, value)` (tag carries the len=/key= metadata,
  body = the value bytes; 960/800 B caps stay). 0013 also gains the
  series-standard gate + 2M cap (`AFEYE_TRACE_STORAGE=0`).
- **0001/0005/0011 (fork safety):** zygote-forked renderers inherited a
  completed once_flag + ring with NO drain thread (fork keeps only the
  calling thread): the child filled 8 MiB and dropped everything, its
  .rec was never created, and the drop witness never fired. All three sink
  cores now check `getpid() != g_pid` in Enabled() (vDSO, free) and
  re-init the ring + drain thread after fork.
- **0016 + 0005 (cap truth):** five per-TU `g_afeye_taint` atomics = 500k
  records/process, 5x the documented 100k cap. ONE counter now lives in the
  blink sink (extern in sink.h) and the five funnels share it.

**Rust fixes (driver + filter, tests green):**

- `main.rs`: the collector now writes `stage/<slot>/collect` (was
  `stage/collect` - the filter read a directory nothing ever wrote; the
  deep filter never ran on real data in ANY committed artifact);
  graceful shutdown (SIGTERM + 1.2s grace before SIGKILL so the C++
  atexit Flush(500) drains the rings; a SIGKILL-only shutdown loses the
  tail records invisibly to the kind-39 witness - false dead-end-proven);
  the raw dir is wiped before chrome starts (stale .rec from a previous
  run would blend timelines and pass the sink-hello probe from a dead
  run).
- `sinkfilter.rs`: kind-16 NUL-less PROSE records (legacy) derive their
  (tag, body) via `value_of_prose` so old .rec files also join the graph;
  the query-sink seed measures the QUERY STRING (a 90-char path with
  `?v=` was a hop-0 sink = false PROVEN for page-load chains); the
  drop-witness refuses dead-end-proven on drops in ANY pid (the graph's
  sinks live in the network-service pid, not the chain's renderer) and
  within 500ms after the window end (0023 throttles reports to 10/s);
  `name_to_chain` is keyed by (pid, canonical name) - two renderers
  loading the same URL no longer cross-attribute PROVEN verdicts, and
  >160-char script names (the query-URL scripts this capture carries)
  now join after canonicalizing the C++ 160/200-char truncation;
  event-dispatch records get the same ambient-family exclusion as
  kind-23 (evt mousemove storms re-saturated handler-born - the exact
  v7 bug v9 closed on the input side); TouchMove/GestureScrollUpdate/
  PointerHoverMove join the kind-23 ambient list; nav-start parses the
  payload `mono_ns=` (the true browser T0) instead of the emission ts;
  the fanout-drop counter lands in report.json; edge-budget exhaustion
  admits the sink with empty keys (a dropped seed silently deletes every
  upstream chain's provenness); dead code (content_runs +
  CONTENT_MAX_TOTAL_RUNS) deleted; `is_hot` excludes the harness's own
  injected script by the AFXH marker (it embeds literal HOT_PATTERNS and
  always classified itself token-forming).
- `collect.rs`: `PartWriter::push` no longer returns a fabricated
  (rel, off) when the write/roll fails - the index line is skipped
  (honest absence, not a pointer at bytes that never landed).
- `inject.rs`: `replacen(__G__, count=1)` left the SECOND `__G__` (the
  _boot record's spoof flag) literal - always reported spoof=0; now 2.
  The SRC carries the `afeye-harness` marker line for the filter's
  self-exclusion.
- `.github/workflows/afeye.yml`: the gate step now writes
  `$GITHUB_OUTPUT` (printing `cadence=go` to stdout does nothing; every
  `steps.gate.outputs.cadence == 'go'` consumer was permanently false and
  the scheduled crawl never ran); the committed TG token/chat-id
  fallbacks removed (rotate the leaked token).
- `tools/rec_census.py`: a torn tail (chrome killed by `timeout` /
  SIGTERM mid-drain) is a warning, not whole-file corruption - parity
  with collect.rs's starved-tail logic.


**25 patches** against **Chromium 153.0.8010.52** (v8 rev
`d1fed5cd7e3b114dea70f18b20d26f816322833d`). The whole series is
re-verified to apply cumulatively with plain `git apply` against a
pristine tree assembled from sources fetched at that tag
(25/25, generated by real git diff against the 24-patch tree).

v12.2 is ONE patch, **0025 - the total-capture pass**. It closes the four
honest-limit holes that made the capture selective instead of total:

1. **EXECUTION COVERAGE (api.cc):** every isolate installs a
   `JitCodeEventHandler` at birth. CODE_ADDED events name EVERY function
   as it is compiled - bytecode, baseline, turbofan, wasm (`exec <type>
   <name> len=N`, kind 34). The lazy-compile hook (0022) only saw a
   function's FIRST run; tier-up and recompile were invisible. The
   handler is sink-only (plain C struct, no v8 API, no handles - safe on
   the logger thread), one install per process, 4M cap,
   `AFEYE_TRACE_EXEC=0` off. The filter reports the tier distribution
   (exec_jit / exec_byte / exec_wasm_code) in v8_depth.
2. **WASM LINEAR MEMORY (wasm-objects.cc):** `WasmMemoryObject::Grow` emits
   `wasm-mem grow old=N new=N` (kind 31) at all three success exits.
   PoW-style wasm antifraud (Kasada) allocates and grows in deterministic
   bursts - the pattern is now a record. Memory CONTENTS remain a black
   box (per-access capture needs CSA hooks that do not exist - the honest
   limit stays, now for contents only, not for the growth pattern).
   `AFEYE_TRACE_WASMMEM=0` off, 100k cap.
3. **PROXY GOPD (js-objects.cc):** the JSReceiver::GOPD proxy branch
   returned into `JSProxy::GetOwnPropertyDescriptor` BEFORE the 0022
   end-hook - descriptor tamper-checks over PROXIES (antifraud wraps
   navigator in a proxy, then GOPDs it to detect the wrap) were
   invisible. The branch now emits `gopd holder=proxy key=K` (kind 16)
   before the call; shares the AFEYE_TRACE_GOPD gate. The old honest-limit
   text "proxy GOPD is NOT captured" is now FALSE and was corrected.
4. **COOKIE->HEADER RELAY (url_request_http_job.cc):** the exact `Cookie:`
   line built from the jar at `SetCookieHeaderAndStart` is emitted as
   `cookie-attach url=U\0<line>` (net kind 17, EmitSpan). This was the
   documented DEFERRED hole: 0013 catches the cookie VALUE in blink and
   kind-18 the Set-Cookie that planted it, but the ATTACH was inference.
   Now it is a record, and the content graph joins the attached line to
   the blink cookie-set VALUE bytes (tag prefix `cookie-attach`).
   `AFEYE_TRACE_COOKIEATTACH=0` off, 500k cap.

v12 is ONE patch, 0024, and it is the single biggest capture win in the
series: it makes EVERY WebIDL value universal instead of funnel-by-funnel.
Until now the dom-api thunk (0008) logged only the member NAME
("dom Navigator.get userAgent") - the VALUE (the actual userAgent string,
screen.width, deviceMemory, hardwareConcurrency, plugins list, every
fingerprint read by exact name) was invisible, because the wrapped callback
sets ReturnValue INSIDE itself and the public bindings never re-exposed it.
0024 reads it back with `ReturnValue::Get()` right after `orig()` runs - so
ALL IDL getter/operation return values land in the kind-29 stream in ONE
already-patched TU (idl_member_installer.cc), zero new files. Strings are
read with `WriteOneByte` into stack scratch (no `Utf8Value` heap alloc - the
no-alloc discipline from 0003/0004); numbers/bools format inline; objects
report their type tag (their payload bytes are caught at their own funnels).
`AFEYE_TRACE_DOM_VALUES=0` reverts to name-only.

This does NOT make 0013/0019 redundant - they cover what 0024 structurally
cannot: (a) WRITE side - `document.cookie = X` and `Storage.setItem(k,v)`
return undefined, so the written value is the ARGUMENT, still caught by 0013;
(b) NON-IDL interceptor paths - `getComputedStyle().fontFamily` (camelCase
named-getter installs via SetHandler, not IDLMemberInstaller) is invisible to
the thunk, still caught by 0019's CSS funnel. 0024 + 0013 + 0019 are
complementary, not overlapping.

v11 makes the SELECTION honest and adds the witness that makes honesty
possible.

COMPILE-COST FIX (this is what kept the build near the 6h CI window): v10 and
earlier touched `v8/src/flags/flag-definitions.h` to add one `afeye_source`
bool with exactly ONE reader (0002's script-source gate). That header is
included by EVERY v8 translation unit, so one knob forced a full v8
recompile. v11 deletes that hunk and replaces the flag with an env-gate
(`AFEYE_SOURCE=0`) cached in a function-local static inside compiler.cc -
zero header churn, the v8 tree stays cached. The only headers the series
still touches are the three afeye sink.h files (0001/0005/0011/0023 - new
files, no tree-wide inclusion) and `messages.h` (0021, one Impl decl).

One new C++ patch:

- **0023 (sink-drop witness, kind 39).** Every sink already counts its ring
  overflows (`SinkDropped()`), but the counter was never emitted - so the
  filter could not tell "this branch fed nothing" from "this branch's
  records were dropped". Each layer's drain thread now writes
  `sink-drop layer=X dropped=N` DIRECTLY to its fd (never through the ring:
  a drop report that could itself be dropped is worthless), throttled to
  ~10/s and only when the count moved. This is what turns `unresolved` from
  a guess into a verdict: a chain with no link AND zero drops in its pid
  before the end of its window is `dead-end-proven`; with drops present it
  stays `unresolved`.

The rest of v11 is Rust-only: the fact graph, compile-provenance, and the
four-state verdict (see "the FACT GRAPH" and "three-way verdict" under the
deep filter below). The 22-patch capture surface is otherwise unchanged.

v10 is the **v8-depth pass over v9** - a dedicated audit of the engine
layer found 8 gaps where capture was still selective. Seven landed as
patches 0020-0022 (one rejected with reasons, see honest limits):

1. **wasm streaming + execution (0020).** THE way antifraud ships wasm:
   `compileStreaming`/`instantiateStreaming` jobs are created with EMPTY
   bytes and the module materializes in
   `AsyncStreamingProcessor::OnFinishedStream` - never crossing the
   0003 SyncCompile/AsyncCompile hooks, so kind-3 was EMPTY for
   Kasada/Cloudflare/DataDome loads. Plus the HTTP-code-cache restore
   path (`Deserialize`, tag `cached`), per-function FIRST EXECUTION
   (`Runtime_WasmCompileLazy` - lazy compilation is default, so every
   function that ever ran crosses here once; zero-alloc, runs under the
   existing DisallowGarbageCollection contract) and every wasm TRAP
   (`ThrowWasmError` - induced-trap environment probing).
2. **JSON.stringify result + Error.stack (0021).** The two highest-
   signal v8 records for token reconstruction and automation detection:
   `BUILTIN(JsonStringify)` logs the assembled PLAINTEXT head (960 B,
   the fingerprint object immediately before crypto/wire - the content
   slice can now match stringify-head against the uploaded body);
   `ErrorUtils::GetFormattedStack` (renamed original -> Impl, public
   wrapper logs) captures EVERY materialized `.stack` string head -
   automation harness markers in stacks are a first-class detector
   surface AND the only cheap JS->JS call-graph source in the engine
   (Invoke sees C++->JS only). Both no-alloc (GetFlatContent under
   DisallowGC, the 0003/0004 pattern), new kind 38 for stacks.
3. **descriptor tamper-checks + execution edges + clock/wrapped
   completeness (0022).** `JSReceiver::GetOwnPropertyDescriptor` (the
   C++ funnel reached only for special receivers/proxies - exactly the
   blink DOM objects antifraud inspects): how it VERIFIES
   navigator.webdriver / plugins / window.chrome were not tampered
   with - holder type + key + the RESULT attributes (the tamper
   evidence; 0008 sees invocations, never descriptors).
   `Compiler::Compile` lazy funnel: every function's FIRST execution as
   `lazy-compile name=.. script=..:line` (kind 8) - dead-code evidence
   per chain. `Compiler::GetWrappedFunction`: the fourth compile funnel
   (CompileFunction API) closes the last script-source gap.
   `BUILTIN(DateConstructor)`: `Date()`/`new Date()` clock reads join
   kind 33 (a clock hook that moves only Date.now() is itself a
   detector; half the clock stream was missing).

REJECTED from the same audit (verified, not guessed): per-call wasm
export logging (dispatch is generated machine code per-arch, no C++
funnel exists - the firstcall record is the honest substitute); CallIC
JS->JS edges (no CallIC C++ class in this rev, feedback is pure Torque);
Proxy birth/traps (CSA-only fast paths, C++ fallbacks would give a
misleading partial picture; the GOPD hook already catches proxy
descriptor traps via the special-receiver dispatch); Intl resolvedOptions
timezone (ICU/CppGCManaged-backed - extracting it without a compile loop
is unsafe; the value rides out through the JSON.stringify/TE boundaries
anyway); BUILTIN(ObjectDefineProperty) as the define funnel (misses
Reflect + internal defines; the C++ choke is DefineOwnProperty, deferred
with the Error-construction noise filter it would need).

v9 is the **completeness pass over v8** - five subagent audits (v8
depth, blink probes, bindings/input, wire/payload, rust graph) walked
the pristine tree for surfaces where capture was still SELECTIVE, and
closed every one that feeds a token:

1. **the input master funnel (0015).** `WidgetEventHandler::HandleInputEvent`
   is the single point every physical WebInputEvent crosses per root
   frame: mouse, wheel, keyboard, gesture, pointer (touch/pen). It
   closes three v8 blind spots at once:
   - **`kFromDebugger` (1<<23)** - the ONLY provenance marker for
     CDP-injected input. `isTrusted` is TRUE for Playwright/Puppeteer
     `Input.dispatch*` (they ride the real browser input pipeline), so
     the kind-24 flag could not tell automation from human. The bit is
     set in devtools_input_handler.cc and survives the mojo round-trip;
     nothing in blink ever read it. Now every kind-23 record carries
     `dbg=0|1`.
   - **wheel raw deltas** (scroll cadence) and **gesture types**
     (tap/scroll/fling - the REAL mobile click/scroll) were invisible.
   - type is logged via `WebInputEvent::GetName()` (stable string, not
     enum int). Zero alloc: snprintf into stack scratch, 4M cap,
     `AFEYE_TRACE_INPUT=0` off.
2. **the plaintext boundaries (0016, kind 37 taint-edge).** Encryption
   destroys content - the v8 content-slice could not cross a pure-JS
   AES (Kasada) because the plaintext never landed in any record. v9
   captures EVERY string->bytes boundary of the token pipeline:
   `TextEncoder.encode/encodeInto` (the main one - form bodies, token
   JSON), `TextDecoder.decode` (challenge responses), `atob/btoa`
   (base64 token wrappers - the btoa input content-matches the JS-AES
   ciphertext in the req-body), `FormData::Entry` ctors (per-field
   name+value; append/set/form-submit all funnel), `URLSearchParams::
   toString` (the exact bytes a fetch body uploads). Records are spans
   under the existing EmitSpan convention; the Rust filter hashes them
   (blake3 runs) like every other payload - C++ does zero hashing.
   `AFEYE_TRACE_TAINT=0` off, 100k/process cap.
3. **WS outbound (0017).** SERIES.md v8 claimed "WS frames both
   directions" - FALSE: the 0011 hook sat in `OnDataFrame` (inbound
   only). A token leaving over WS (Kasada/HUMAN telemetry channels)
   crossed no sink. v9 emits `ws-frame-out` spans at both
   `ReadAndSendFrameFromDataPipe` materialization points (direct +
   reassembly). Inbound tags stay carriers, only `ws-frame-out` sinks.
4. **the crypto result boundary (0018).** `CryptoResultImpl::
   CompleteWithBuffer` is the single funnel where every SubtleCrypto
   promise resolves its ArrayBuffer - the ciphertext/signature/digest
   itself. 0007 captured raw_data BEFORE BoringSSL; the output was
   invisible, so the slice died exactly at the encryption boundary
   (req-body ciphertext content-matched nothing). `crypto-out` spans
   now content-match the req-body / ws-frame-out sinks verbatim - the
   graph crosses encryption. Op pairing in<->out stays heuristic
   (documented): threading an op-id would touch CryptoResultImpl and
   all 14 creation sites for an edge the content match already gives.
5. **the fingerprint VALUES (0019).** kind-29 names every WebIDL call
   but never its arguments or results; the named-getter interceptor
   path (`cs.fontFamily`) bypasses the thunk ENTIRELY. v9 captures the
   reads that feed the font/device signature:
   - `CSSComputedStyleDeclaration::GetPropertyCSSValue` - THE funnel
     every string-API path converges on (getPropertyValue, item(), the
     camelCase interceptor): property name + resolved value. Font-metric
     fingerprinting lives here. 2M cap (layout reads styles heavily).
   - `BaseRenderingContext2D::DrawTextInternal` - the fillText/strokeText
     INPUT (text+font+xy): what was drawn to produce the canvas digest
     0012/0014 capture on the way out.
   - `FontFaceSet::check` - direct font enumeration (which font probed).
   - `Permissions::query` name + `Notification::permission` value - the
     headless MISMATCH tell (DataDome/CreepJS pair the two).
   - `LocalDOMWindow::matchMedia` query + `MediaQueryList::matches`
     answer - the device/OS/rendering feature probes.
6. **the filter stops lying (src/sinkfilter.rs, src/main.rs).**
   - **prune cap bug (real):** `chains[]` capped at 4000 entries; the
     filtered-zip cut walked only the report - chains past the cap
     silently escaped into the "token-only" zip (eval storms produce
     thousands). New uncapped compact `prune` list is the
     authoritative cut set; main.rs uses it (old reports fall back).
   - **handler-born saturation:** TRIGGER_KINDS included READ kinds
     (fingerprint/dom-metric/audio/webrtc/crypto-op) - during the load-
     phase fp storm they fire hundreds/sec, so the 250ms window found
     a "trigger" for every early chain and filtered==run. Narrowed to
     causal kinds {input, event-dispatch, timer}; mousemove/pointer-
     move raw updates excluded (ambient, not compile triggers).
   - **new sinks in the content graph:** `crypto-out` (0018) and
     `ws-frame-out` (0017) join SINK_CRYPTO_OPS / the sink set;
     `websocket` and `taint-edge` join payload_kinds as carriers.
   - **entry-join (kind-8):** the call-completed stream - the ready-made
     caller identity sitting unused in the index - now attributes every
     fetch initiation (kind 28), cookie/storage access (kind 16),
     fingerprint read (kind 29), JSON.stringify assembly (0021), GOPD
     probe (0022) and Error.stack materialization (0021) to the chain
     that was the active C++->JS entry. Signals: `send-initiator`
     (observed send, beats the sink-call text match), `token-access`
     (read/wrote the stored token), `fp-probes-entry` (>=2 distinct fp
     reads by entry, immune to window false-positives), `gopd-check`
     (descriptor tamper probe), `stack-inspect` (materialized .stack),
     plus the `payload_assembler` column (ran JSON.stringify).
     Lazy-compile records (0022) are EXCLUDED from the entry index
     (they name the compiled function, not an executing entry) and
     instead feed per-chain `executed_funcs` - dead-code evidence.
     Limits documented: nearest C++->JS boundary, not the exact
     reader; same-pid threads interleave.
   - **v8_depth report block:** lazy_funcs, wasm_firstcalls,
     wasm_traps, wasm_cached, and `automation_tells` - harness markers
     (pptr:, playwright, cdc_, __webdriver_evaluate, ...) found in
     materialized Error.stacks. If OUR crawler's own harness shows up
     there, that is a capture-integrity alarm.

v8 is the **latency + blind-spot pass over v7**, four changes:

1. **no-alloc hot hooks.** v7 logged the `Invoke` funnel (every C++->JS
   entry - scripts, microtasks, revivers, comparators) and the
   `FunctionPrototypeToString` integrity builtin through the PUBLIC v8
   API: `GetScriptOrigin()` + `v8::String::Utf8Value` + `std::string`
   per call. That is heap allocation + V8 handle creation inside the
   hottest funnels in the engine, exactly where V8 internals run under
   `DisallowGarbageCollection` / during GC bookkeeping - the class of
   hook that costs milliseconds per page and can deadlock or OOM the
   isolate. v8 rewrites both hooks onto the internal `Tagged<>` object
   graph: `JSFunction -> shared() -> script()` name via
   `String::GetFlatContent(no_gc)` copied into stack scratch, line via
   the member `Script::GetLineNumber(pos)` (runs under DisallowGC:
   cached `line_ends` fast path, flat-source slow path - no
   allocation). Zero heap, zero handles, zero isolate re-entry; record
   format unchanged (`call argc=N script=name:line` / `fnts name=..
   script=..:N`). Bound functions now unwrap to their target in the
   toString hook, so integrity probes of `bound(f)` name the real
   callee instead of `?`.
2. **the blind spots: performance.now(), canvas export, cookie values,
   storage values.** Four surfaces antifraud actually uses were name-
   only or invisible:
   - `performance.now()` (0012): the high-resolution clock every PoW
     loop and timing check reads. kind-33 only caught `Date.now()`.
     Same env switch (`AFEYE_TRACE_CLOCK`), same 2M cap, same kind.
   - `canvas.toDataURL` / `toBlob` (0012): THE canvas-fingerprint
     readback. Hooked at `ToDataURLInternal` - the single funnel where
     the encoded data URL materializes - logging mime + encoded length
     (the result digest; no second render, the string already exists).
     `toBlob` logs the ask (mime + geometry).
   - `document.cookie` get/set VALUES (0013): the challenge token
     store (cf_clearance and friends). kind-29 named the call; the
     value was invisible. Head-capped at 960 bytes per record.
   - `StorageArea` getItem/setItem VALUES (0013): localStorage /
     sessionStorage - where antifraud parks the fingerprint at init
     and reads it back at send time. Key + value head, kind 16.
3. **content-based backward slice (the net-window fix, `src/sinkfilter.rs`).**
   v7's `net-window` signal is a FIXED 5 s timer before a send.
   Cloudflare/DataDome/Kasada collect the base fingerprint in the
   first ~200 ms, stash it (IndexedDB via structured-clone, storage,
   or a closure), and encrypt+send it 10-30 s later on a
   focus/mousemove/captcha-decision event. The timer dropped that init
   chain into the dead-end bucket. v8 links payload records BY
   CONTENT: blake3 runs (32 B windows, 16 B stride, monotone windows
   skipped) over crypto-op raw_data / structured-clone blobs /
   req-body uploads; any record sharing a run with a SINK record
   (payload-forming crypto encrypt/sign/deriveBits/digest, or an
   upload body) is sink-linked regardless of the clock gap, and a
   chain materialized within 200 ms grace of a sink-linked payload
   gets the `content-sink` signal. Bounded: 50k payload records,
   4M runs, 8k runs/record.
4. **input cadence in the report** - the kind-23 stream (0009) now
   gets summarized: per-type counts, median/p90 inter-event delta,
   path length in px, span; every net-request entry carries its own
   `input_5s` window (n / moves / keys / median delta). "How often the
   mouse went, where, and when" - readable per send without the raw
   stream.

v7 is the **honesty pass over v6**, driven by a code review that found
the v6 series silently dead in three places:

1. **the v8 layer compiled to NOTHING.** The 0001 BUILD.gn hunk nested
   `if (v8_enable_afeye)` INSIDE `if (v8_enable_vtunetracemark && ...)`
   (false by default) - sink.cc never compiled, `V8_AFEYE` was never
   defined, and every `#ifdef V8_AFEYE` hook in api.cc / compiler.cc /
   wasm / builtins / microtask-queue compiled to empty translation
   units. The build stayed green; the capture layer did not exist.
   A second copy of the same bug nested the header under
   `v8_enable_experimental_tq_to_tsa` (also false). v7 hoists the
   block out as a sibling (fixed hunk, `defines +=`), and - belt to
   that suspenders - promotes the defines to **global
   `extra_cflags`** in args.gn: `-DV8_AFEYE=1 -DBLINK_AFEYE=1
   -DNET_AFEYE=1` reach EVERY translation unit in EVERY toolchain; no
   GN scope, no `public_configs` propagation chain, no dependency
   nesting can ever hide from a command-line define again.
2. **the build target was `headless_shell`** - the stripped test app
   missing half the WebPlatform pipeline. Antifraud scripts (Cloudflare
   Turnstile, DataDome) probe for the missing interfaces and silently
   bail before doing real work - the sinks were dead not because the
   hooks failed but because the antifraud JS never ran its real path.
   v7 builds the **real `chrome`** binary and runs it headless via
   `--headless` (since 132 that IS the full new headless). The window
   chain absorbs the bigger graph.
3. **the smoke test proved nothing**: `--dump-dom about:blank` executes
   zero external scripts, so "a .rec file appeared" was only the
   sink-hello handshake. v7 smokes on a real local page (external +
   inline script, timer, fetch, dispatched event, toString, wasm
   bytes) and asserts the ACTUAL record kinds through
   `tools/rec_census.py` - `v8:script-source>=2`, `v8:call-completed`,
   `blink:event-dispatch`, `blink:timer`, `blink:fetch`,
   `blink:dom-api`, `net:net-request`. A dead layer now fails the
   build loudly, at the smoke step.

Plus the depth upgrades from the same review:

- **the Invoke funnel** (0003, execution.cc): the call-origin hook
  moved from `v8::Function::Call` (api.cc - public API surface only)
  into `Invoke`, the single funnel every C++ -> JS entry passes
  through: `Script::Run` / `RunModule`, `Execution::New`, microtask
  callbacks, JSON revivers, sort comparators, v8's own internal
  callers. Nothing C++-initiated slips past it. Same record format
  (`call argc=N [c=1] script=name:line`), same kind 8, same env
  switches (`AFEYE_TRACE_CALLS=0`, 4M cap).
- **`EventTarget::FireEventListeners`** (0006, event_target.cc): the
  "did the event actually reach listeners" fact - listener count,
  legacy or not, trusted or synthetic. Joined with the Invoke funnel
  the filter now reads: event -> N listeners -> each listener's
  script:line entry. (EventDispatcher stays the dispatch-side
  superset.)
- **packaging**: the release tar carries the WHOLE component `.so`
  set (exclusion-based tar + sanity assertions), not a hard-coded
  file list that shipped a binary missing its libraries.
- **dead-end classification** (`src/sinkfilter.rs`): every chain is
  split into **token-forming** vs **dead-end** (see below). The
  filtered zip keeps only what feeds the challenge token; the raw run
  zip stays as complete as v6 (no downgrade).

## the funnels (all symbols verified in the pinned tree)

### scripts - every line of JS that executes, exactly once - `0002`

| funnel | covers | verified at |
|---|---|---|
| `GetSharedFunctionInfoForScriptImpl` | every **buffered** compile: classic scripts, modules, code-cache consume, compile hints, extensions, embedder API. All four `CompileUnboundInternal` variants and `...WithExtension` funnel here | compiler.cc:3947; call sites 4117-4175 |
| `GetSharedFunctionInfoForStreamedScript` | every **streamed** compile - the normal path for external `<script src>` (blink `ScriptStreamer` hand-off) | v8_script_runner.cc:142-147 -> api.cc:2931 -> compiler.cc:4295 |
| `Compiler::GetFunctionFromEval` | every `eval()` / `new Function()` - where deobfuscated code materializes. Own path: eval-cache lookup, then `CreateScript` + `CompileToplevel` | compiler.cc:3301 |

v6: every script name is **isolate-prefixed** (`iso:<ptr> <name>`), so
the external filter groups eval-chains per isolate/session - a
dedicated worker's stream never mixes with the main thread even inside
one renderer process.

### calls, isolates, wasm - `0003`

| funnel | covers |
|---|---|
| `Invoke` (execution.cc:305) | **THE C++ -> JS funnel** (v7, replaces the api.cc hook): every entry - `v8::Function::Call`, `Script::Run`/`RunModule`, `Execution::New`, microtask callbacks, JSON revivers, comparators, v8-internal callers. Callee script:line. v8: NO-ALLOC - name via `GetFlatContent(no_gc)` into stack scratch, line via member `Script::GetLineNumber` (DisallowGC-safe); the v7 public-API body heap-allocated per call. `AFEYE_TRACE_CALLS=0` off, 4M cap |
| `Isolate::New` (api.cc) | isolate birth record (kind 34) - the join key for `iso:` chains |
| `WasmEngine::SyncCompile` / `AsyncCompile` | full wasm module bytes (buffered `new WebAssembly.Module` / `compile` / `instantiate`) |
| `InstanceBuilder::ProcessImports` (module-instantiate.cc) | **the imports as RESOLVED at instantiation** - every `wasm-import <module.field> kind=` record, plus the instantiate header with the import count |

### engine fidelity - `0004` (the antifraud introspection surface)

| funnel | covers |
|---|---|
| `BUILTIN(FunctionPrototypeToString)` (builtins-function.cc) | WHO was toString-inspected: receiver name + script:line (kind 32) - the native-code integrity probe, pure observation, no result tampering. v8: NO-ALLOC (internal Tagged<> reads under DisallowGarbageCollection; bound functions unwrapped to the real target). 2M cap |
| `BUILTIN(DateNow)` (builtins-date.cc) | every `Date.now()` read (kind 33) - the clock cadence all timing checks run on. `AFEYE_TRACE_CLOCK=0` disables, 2M cap |
| `MicrotaskQueue::RunMicrotasks` (microtask-queue.cc) | drain start/end brackets with pending + ran counts per isolate (kind 30) |

### the telemetry scripts consume - `0006` (flow)

| funnel | covers |
|---|---|
| `EventDispatcher::DispatchEvent` | **the** event funnel: every dispatched event, type + `isTrusted` + target node + mouse client/screen coords + key/code, ns timestamp. Sets the blink ambient tag |
| `EventTarget::FireEventListeners` (v7) | the listeners-reached fact: `lis evt=<type> n=<count> legacy=<0/1> trusted=<0/1>` (kind 24) - joined with the Invoke funnel: event -> N listeners -> each listener's script:line |
| `DOMTimer` ctor + `DOMTimer::Fired` | timer installs (id/timeout/single) and fires (id/nesting) |
| `ResourceFetcher::RequestResource` | renderer-side request provenance: url + resource type + ambient cause, logged BEFORE the mojo hop |

### the probes - `0007` (what fingerprinting actually reads)

| funnel | covers |
|---|---|
| `Element::getClientRects` / `GetBoundingClientRectForBinding` | DOM geometry reads - v6 also logs the **result** (`bounding-rect-r x/y/w/h`): the font-probe string's measured geometry, not just the ask |
| `HTMLElement` offset/scroll/absolute dims | the classic layout-probe family (`offsetWidth`/`offsetHeight`/`scrollWidth`/...) |
| `WebGLRenderingContextBase` getParameter / getExtension / getShaderPrecisionFormat | the WebGL parameter sweep (kind 16 fingerprint records) |
| `BaseRenderingContext2D::measureText` / `getImageData` | font-probe (text + unparsed font) + canvas readback geometry |
| `OfflineAudioDestinationHandler::FinishOfflineRendering` | rendered offline-audio channel-0 head - the audio-fingerprint digest |
| `RTCPeerConnection` createOffer / setLocalDescription / addIceCandidate | full SDP + ICE candidates (local IP / device leaks) |
| `MediaDeviceInfo` ctor | device id / group / label - real device identities |
| `Crypto::getRandomValues` / `SubtleCrypto` encrypt/decrypt/sign/digest/deriveBits | nonces and plaintext BEFORE BoringSSL - the payload-forming crypto |
| `SerializedScriptValue(DataBufferPtr)` ctor | full structured-clone bytes: postMessage / BroadcastChannel payloads |

### THE dom-api choke - `0008` (every WebIDL attribute + operation)

In 153 every generated attribute getter/setter and every operation
installs through `IDLMemberInstaller` (bindings codegen; the old
V8DOMConfiguration is gone). `0008` wraps each callback in a thunk
that logs `dom <Interface>.<get|set|call> <member>` (kind 29) and
calls the original. The identity rides in the FunctionTemplate data
slot, which blink leaves EMPTY for these installs - stock callbacks
never read `info.Data()`, so nothing observable changes. This is the
per-DOM-property funnel v5 documented as impossible:
`navigator.*`, `screen.*`, `document.*`, `window.*`, every fingerprint
read by exact name. Honest limit: Fast-API overloads
(`NoAllocDirectCall`) still take the CFunction fast path when argument
types match - the thunk sees the slow path.

### input at the source - `0009`

| funnel | covers |
|---|---|
| `MouseEventManager::DispatchMouseEvent` | full WebMouseEvent geometry at the source: widget + screen coords, button, click count, modifiers (kind 23) - before any DOM dispatch decision; the EventDispatcher keeps the `isTrusted` DOM-side view |
| `KeyboardEventManager::KeyEvent` | type, windows/dom key codes, dom_key, modifiers (kind 23) |

### context anchors - `0010`

| funnel | covers |
|---|---|
| `DocumentLoadTiming::SetNavigationStart` | navigation T0 (kind 36) - `base::TimeTicks` on POSIX is CLOCK_MONOTONIC, the SAME clock domain the sinks use, so every record diffs exactly against page start |
| `WorkerOrWorkletGlobalScope` ctor | worker/worklet scope birth (kind 35): isolate pointer + name - the join key that names an `iso:` chain "which worker was this" |

### the wire - `0011`

| funnel | covers |
|---|---|
| `URLLoader::ScheduleStart` / `SetUpUpload` / `ContinueOnResponseStarted` / `DidRead` / `NotifyCompleted` | method + url, request headers, **upload bodies before TLS**, response headers/mime, response body spans, completion |
| `WebSocket` frame handler | WS frames both directions |

### the v8 blind spots - `0012` + `0013` + `0014`

| funnel | covers |
|---|---|
| `Performance::now` (performance.cc, 0012) | every `performance.now()` read (kind 33, `clock performance-now`) - the high-resolution clock all PoW/timing checks run on; `Date.now()` was only half the stream. `AFEYE_TRACE_CLOCK=0` off, 2M cap |
| `HTMLCanvasElement::ToDataURLInternal` (0012) | the canvas-fingerprint readback RESULT: mime + encoded data-URL length (kind 16) - hooked where the string materializes, no second render |
| `HTMLCanvasElement::toBlob` (0012) | the async export ask: mime + geometry (kind 16) |
| `Document::cookie` / `setCookie` (document.cc, 0013) | cookie-jar VALUES both directions (kind 16, head-capped 960 B) - the cf_clearance / challenge-token store |
| `StorageArea::getItem` / `setItem` (storage_area.cc, 0013) | localStorage/sessionStorage key+value head (kind 16) - the store-then-send pattern: fingerprint parked at init, read back at send time |

### the v9 completeness pass - `0015` + `0016` + `0017` + `0018`

| funnel | covers |
|---|---|
| `WidgetEventHandler::HandleInputEvent` (widget_event_handler.cc, 0015) | THE physical-input master funnel: every mouse/wheel/key/gesture/pointer event per root frame, with `mods` + **`dbg`** (kFromDebugger - CDP-injected vs human; isTrusted cannot tell them apart) + per-type geometry. kind 23, `AFEYE_TRACE_INPUT=0` off, 4M cap |
| `TextEncoder::encode` / `encodeInto` (0016) | the string->bytes boundary every UTF-8 payload crosses before ANY crypto (kind 37, `text-encoder`) |
| `TextDecoder::Decode` (0016) | the bytes->string boundary of challenge responses (kind 37, `text-decoder`) |
| `UniversalGlobalScope::btoa` / `atob` (0016) | the base64 token wrapper both directions - btoa input content-matches the JS-AES ciphertext in the upload; atob output is the decoded challenge plaintext (kind 37) |
| `FormData::Entry` ctors (0016) | every form field name+value as one span (append/set/form-submit funnel through the ctors); blob entries log metadata (kind 37, `form-data`) |
| `URLSearchParams::toString` (0016) | the full form-encoded query - the exact bytes of a fetch-body upload (kind 37, `url-search-params`) |
| `WebSocket::ReadAndSendFrameFromDataPipe` (0017) | WS OUTBOUND frames (both materialization paths) - `ws-frame-out` spans; the v8 "both directions" claim was inbound-only (kind 19) |
| `CryptoResultImpl::CompleteWithBuffer` (0018) | every SubtleCrypto buffer RESULT - ciphertext/signature/digest as `crypto-out` spans; the edge that lets the content graph cross encryption (kind 11) |
| `CSSComputedStyleDeclaration::GetPropertyCSSValue` (0019) | getComputedStyle per-property name + resolved VALUE - the funnel getPropertyValue/item()/camelCase-interceptor all converge on; the interceptor path is INVISIBLE to kind-29 (kind 16, 2M cap) |
| `BaseRenderingContext2D::DrawTextInternal` (0019) | fillText/strokeText INPUT: text + font + xy - what was drawn to produce the canvas digest (kind 16) |
| `FontFaceSet::check` (0019) | direct font enumeration: which font string was probed (kind 16) |
| `Permissions::query` / `Notification::permission` (0019) | the headless mismatch tell: query NAME + permission VALUE, pairable by the filter (kind 16) |
| `LocalDOMWindow::matchMedia` / `MediaQueryList::matches` (0019) | device/OS feature probes: query string + matches bit (kind 16) |

### the v12 universal value capture - `0024`

| funnel | covers |
|---|---|
| `AfeyeDomApiThunk` value readback (idl_member_installer.cc, 0024) | EVERY WebIDL attribute-get and operation return value via `ReturnValue::Get()` - the actual userAgent/screen.*/deviceMemory/plugins/etc strings and numbers that 0008 only named. One existing TU, no new files, no-alloc (WriteOneByte into stack scratch). kind 29 now carries `dom <Iface>.get <m> val=<value>`. `AFEYE_TRACE_DOM_VALUES=0` reverts to name-only. Write-side (setters/void ops) and interceptor paths (getComputedStyle camelCase) stay on 0013/0019 |

### the v10 v8-depth pass - `0020` + `0021` + `0022`

| funnel | covers |
|---|---|
| `AsyncStreamingProcessor::OnFinishedStream` (module-compiler.cc, 0020) | THE wasm-bytes funnel for streaming delivery - compileStreaming/instantiateStreaming modules materialize here, never crossing the 0003 Sync/AsyncCompile hooks (kind 3, same record shape) |
| `AsyncStreamingProcessor::Deserialize` (0020) | wasm restored from the HTTP code cache - tag `cached` (kind 3) |
| `RUNTIME_FUNCTION(Runtime_WasmCompileLazy)` (runtime-wasm.cc, 0020) | every lazily-compiled wasm function's FIRST execution = the execution trace (kind 31, `wasm-firstcall func_index= module=`); zero-alloc under the existing DisallowGC contract |
| `ThrowWasmError` (0020) | every wasm trap - induced-trap environment probing (kind 31, `wasm-trap msg=`) |
| `BUILTIN(JsonStringify)` (builtins-json.cc, 0021) | the assembled PLAINTEXT: result head (960 B) + replacer flag - the fingerprint object immediately before crypto/wire (kind 16, `json-stringify`). `AFEYE_TRACE_JSON=0` off, 2M cap |
| `ErrorUtils::GetFormattedStack` (messages.cc, 0021) | EVERY materialized Error.stack head (960 B) - automation-harness detection + the only cheap JS->JS call-graph source (kind 38, `errstack`). Original renamed to Impl; the wrapper catches all four return paths. `AFEYE_TRACE_STACK=0` off, 2M cap |
| `JSReceiver::GetOwnPropertyDescriptor` (js-objects.cc, 0022) | descriptor tamper-checks over DOM objects/proxies: holder type + key + RESULT attrs (data-vs-accessor, writable/enumerable/configurable) - the evidence that a patched property changes the token (kind 16, `gopd`). Reached only for special receivers/proxies - plain-object GOPD stays in the CSA fast path. `AFEYE_TRACE_GOPD=0` off, 2M cap |
| `Compiler::Compile` lazy funnel (compiler.cc, 0022) | every JS function's FIRST execution: `lazy-compile name= script=:line` (kind 8) - dead-code evidence per chain, no-alloc (0003 pattern), 4M cap |
| `Compiler::GetWrappedFunction` (compiler.cc, 0022) | the FOURTH compile funnel (CompileFunction API) - closes the last script-source gap (kind 1, name `wrapped`) |
| `BUILTIN(DateConstructor)` (builtins-date.cc, 0022) | `Date()` / `new Date()` zero-arg clock reads join kind 33 (`clock date-ctor`) - the Date.now cross-check half |
| `WebGLRenderingContextBase::ReadPixelsHelper` (0014) | the WebGL readback: ask (rect+fmt+type) + RESULT head-span (the rendered digest). Covers both WebGL1 and WebGL2 (single funnel). kind 16 |
| `BaseRenderingContext2D::getImageDataInternal` (0014) | the canvas-2d readback RESULT: head-span of the filled pixel buffer (`RawByteSpan`). 0007 logged the ask; this is the digest the antifraud hashes. kind 16 |
| `AnalyserNode::get*FrequencyData` / `get*TimeDomainData` (0014) | the realtime audio fingerprint: head-span of every frequency/time-domain buffer. 0007 covered the OFFLINE render; this is the realtime surface (per-frame polls, 2M cap). kind 16 |

## compile cost (what "only the changed files compile" means here)

| patch | Chromium TUs touched | libraries that relink |
|---|---|---|
| 0001 v8-sink | +1 new (`v8/src/afeye/sink.cc`) + BUILD.gn + flag header | v8 |
| 0002 v8-scripts | 1 (`compiler.cc`) | v8 |
| 0003 v8-calls-wasm | 4 (`execution.cc`, `api.cc`, `wasm-engine.cc`, `module-instantiate.cc`) | v8 |
| 0004 v8-engine-fidelity | 3 (`builtins-function.cc`, `builtins-date.cc`, `microtask-queue.cc`) | v8 |
| 0005 blink-sink | +1 new (`platform/afeye/sink.cc`) + BUILD.gn | blink_platform |
| 0006 blink-flow | 4 (`event_dispatcher.cc`, `event_target.cc`, `dom_timer.cc`, `resource_fetcher.cc`) | blink core/platform |
| 0007 blink-probes | 10 (`element.cc`, `html_element.cc`, `webgl_rendering_context_base.cc`, `base_rendering_context_2d.cc`, `offline_audio_destination_handler.cc`, `rtc_peer_connection.cc`, `media_device_info.cc`, `crypto.cc`, `subtle_crypto.cc`, `serialized_script_value.cc`) | blink core/modules |
| 0008 blink-dom-api | 1 (`idl_member_installer.cc`) | blink platform |
| 0009 blink-input | 2 (`mouse_event_manager.cc`, `keyboard_event_manager.cc`) | blink core |
| 0010 blink-context | 2 (`document_load_timing.cc`, `worker_or_worklet_global_scope.cc`) | blink core |
| 0011 net-wire | 3 (`url_loader.cc`, `websocket.cc`, + sink TU + BUILD.gn) | network service |
| 0012 blink-clock-canvas | 2 (`performance.cc`, `html_canvas_element.cc`) | blink core |
| 0013 blink-cookie-storage | 2 (`document.cc`, `storage_area.cc`) | blink core/modules |
| 0014 blink-readback-results | 3 (`webgl_rendering_context_base.cc`, `base_rendering_context_2d.cc`, `analyser_node.cc`) | blink core/modules |
| 0015 blink-input-master | 1 (`widget_event_handler.cc`) | blink core |
| 0016 blink-taint-edges | 5 (`text_encoder.cc`, `text_decoder.cc`, `universal_global_scope.cc`, `form_data.cc`, `url_search_params.cc`) | blink core/modules |
| 0017 net-ws-outbound | 0 new (`websocket.cc` already in 0011) | network service |
| 0018 blink-crypto-out | 1 (`crypto_result_impl.cc`) | blink modules |
| 0019 blink-fp-values | 7 (`css_computed_style_declaration.cc`, `font_face_set.cc`, `media_query_list.cc`, `local_dom_window.cc`, `base_rendering_context_2d.cc`*, `permissions.cc`, `notification.cc`) | blink core/modules |
| 0020 v8-wasm-streaming-exec | 2 (`module-compiler.cc`, `runtime-wasm.cc`) | v8 |
| 0021 v8-payload-stack | 2 + header (`builtins-json.cc`, `messages.cc`, `messages.h`) | v8 |
| 0022 v8-introspection | 1 new + 2 existing (`js-objects.cc` new; `compiler.cc`*, `builtins-date.cc`* already patched) | v8 |
| 0023 sink-drop-witness | 0 new (`sink.cc`/`sink.h` x3 - already created by 0001/0005/0011) | v8 + blink_platform + network service |
| 0024 blink-dom-api-values | 0 new (`idl_member_installer.cc` already patched by 0008) | blink platform |

~55 changed/new TUs total (*already-patched TUs - ccache miss only for the
changed file). v8 relinks once for 0020-0023; blink_platform and the network
service relink for 0023's sink.cc change. The CI build (`scripts/build-chromium.sh`)
runs `ccache -z` before ninja and `ccache -s` after: on a warm cache
only these TUs recompile - a series tweak costs minutes, not hours.
First build chains across 4h30m windows under the 6h runner cap
(`afeye-build.yml`: manual dispatch only, self-retriggering, ccache
carried by actions/cache). v7 target: the **real `chrome`** (the
headless_shell of v6 is what the review killed - see the top of this
file); the window chain absorbs the bigger graph.

## wire format (unchanged v2)

Every sink appends to `$AFEYE_RAW_DIR (default /tmp/afeye-raw)/<layer>-<pid>.rec`:
```
u32 total_le | u8 kind | u8 flags | u16 rsvd=0 | u64 ts_ns_le | payload[total - 16]
```
`ts_ns` is `CLOCK_MONOTONIC` nanoseconds, identical clock domain in
every sink process, so all streams merge into one diff-able timeline.
First record in each file is kind 0 (`afeye-sink/<layer> v2 pid=...`).
Ring: 8 MiB, spinlock-guarded, overflow drops + counts; `Flush(500)`
at exit. The drain thread writes with raw `::write()` syscalls - there
is no libc stdio buffer to lose, and each process owns its own file
(no cross-writer locking needed); a hard SIGKILL can still lose the
last sub-millisecond of ring backlog (counted, see honest limits).

Kinds after v12.2 (no new kind numbers - 0025 reuses 34/31/16/17): 0
sink-hello, 1 script-source (v8, `iso:` names, **four funnels: eval /
streamed / buffered / wrapped, 0002+0022**),
3 wasm-module (**+ streaming + code-cache paths, 0020**), 8 call-origin
(**+ lazy-compile first-execution records, 0022**), 11 crypto-op (**+
crypto-out result, 0018**), 12 timer, 15
structured-clone, 16 fingerprint (device identities + webgl +
**canvas export result + cookie/storage values** + **v8-layer:
json-stringify plaintext, GOPD descriptor results, 0021/0022**), 17
net-request, 18 net-resp-body, 19 websocket (**+ outbound frames,
0017**), 23 input (**+ master funnel with dbg flag, 0015**), 24
event-dispatch, 25 dom-metric, 26 audio, 27 webrtc, 28 fetch, **29
dom-api**, **30 microtask**, **31 wasm-instance (+ firstcall + trap
records, 0020)**, **32
fn-tostring**, **33 clock (Date.now + performance.now + Date
constructor, 0012/0022)**, **34
isolate**, **35 worker**, **36
nav-start**, **37 taint-edge (0016: TextEncoder/TextDecoder/atob/
btoa/FormData/URLSearchParams - the plaintext boundaries)**, **38
error-stack (0021: every materialized Error.stack head)**, **39 sink-drop
(0023: the ring-overflow witness that makes `dead-end-proven` provable)**.
Silent (wire compat): 2, 4-7, 9-10, 13-14, 20-22.

`tools/rec_census.py` parses this format standalone (with the same
kind names as `src/collect.rs`) and carries `--expect layer:kind=MIN`
assertions - the CI smoke proves the binary actually captured at
runtime, not just that `.rec` files exist.

## collection (what changed in `src/collect.rs`)

High-frequency small-record kinds (dom-api, call-origin,
event-dispatch, input, clock, microtask, timer) now materialize as
per-(layer,kind) **part files** (~8 MiB, rolled), with the index
carrying `(p, o, len)` per record. Batching is storage packing, not
filtering - the filter unpacks by offset and nothing is lost. The
10k-one-kilo-file problem dies at materialization; `index.jsonl`
still holds every hash + ts + pid.

## the deep filter - `src/sinkfilter.rs`

- **chains** - script fragments merge per (pid, layer, name); with the
  `iso:` prefix that is per-isolate, and kind-35 records NAME the
  isolate ("worker: sw.js"). Report entries carry `isolate` + `worker`.
- **taint (backward slicing)** - a chain is HOT when its code carries a
  collector sink call, OR materialized inside a handler/timer window
  (`AF_SCRIPT_TRIGGER_MS`, default 250 ms), OR **two or more distinct
  fingerprint dom-api reads fired while its fragments materialized**
  (the eval-chunk-then-probe antifraud pattern). Chain entries carry
  the exact `fp_reads` list, `integrity_checks` (kind-32 samples),
  `clock_reads` cadence.
- **the FACT GRAPH (v11)** - selection by demonstrated byte identity, not by
  timer guessing. The v8 content-slice was 1-HOP (a carrier had to share a
  run DIRECTLY with a sink), so a transitive pipeline collector -> storage ->
  TextEncoder -> crypto was credited only by luck, and it could not answer
  WHY. v11 builds the real graph:
  - **nodes** = payload records: crypto-op, structured-clone, net-request
    (req-body AND the `method\0url` record - a payload can leave in the query
    string with no body at all, proven by this repo's own capture: analytics
    beacons with 500-1300 char queries and empty bodies), taint-edge,
    websocket.
  - **edges** = a shared content run: blake3 over 32 B windows, 16 B stride,
    monotone windows skipped so zero-padding never links. Adjacency is a flat
    sorted `Vec<(u64 key, u32 node)>` - 12 B/edge instead of a HashMap at
    ~50 B/entry. Key = first 8 bytes of the run hash; at 8 M edges the
    birthday-collision probability is ~1e-6 and a collision can only ADD an
    edge, so the failure mode is a thicker filtered zip, never a lost chain.
    Runs shared by >4096 records are skipped as boilerplate (a common JSON
    prefix would otherwise taint the whole page).
  - **seeds** = sink records: req-body, ws-frame-out, payload-forming crypto
    raw_data, crypto-out (0018), and a request URL whose query is >=96 B
    (body-less pixel/beacon transport). Sinks additionally carry base64 and
    hex VARIANT runs so a standard-alphabet envelope step still matches.
  - **slice** = BFS backwards from every seed, 6 hops max. A chain gets
    `graph-sink@N` when a tainted record falls inside its materialization
    window - N hops of DEMONSTRATED byte identity to the wire.
  - **CSR adjacency** (compressed sparse row): `adj_keys` (8 B per distinct
    key) + `adj_off` (4 B per key) + `adj_nodes` (4 B per edge). One binary
    search per key, then a direct slice - versus a tuple `Vec` at 16 B/edge
    (alignment padding) that also stored every key twice, or a `HashMap` at
    ~56 B/entry. ~96 MB worst case at the 8M-edge budget.
  - **sink-first admission**: the budget gates CARRIERS only, never sinks. A
    dropped sink is a dropped BFS seed, which silently deletes every chain
    upstream of it - and since records are ts-sorted, a single cutoff would
    have lost exactly the LATE token sends (the 10-30 s collect-then-send case
    this graph exists for).
  - **fanout cap, counted**: a run shared by >4096 records is boilerplate (a
    common JSON prefix) and is skipped for carriers, with every skipped edge
    reported as `edges_dropped_by_fanout`. Sink nodes bypass the cap. This is
    the ONE place the graph can produce an honest false-negative, so it is
    visible in the report rather than silent.
  - **URL-identity (pass 1b)**: a chain whose display name is a URL the net
    layer actually requested is DOWNLOADED code, not inline. Structural fact
    only - it never marks a chain proven by itself, because attributing a
    resp-body span to its URL needs per-request correlation the wire format
    does not carry (concurrent responses interleave in one pid).
  - **HONEST LIMIT, proven against this repo's own capture**
    (`afeye-20260918-144834.zip`, the 4 Cloudflare `.post` bodies): their
    wire charset is `$+,-./0-9:A-Za-z{}` with NO `=` padding anywhere, i.e.
    a vendor-specific alphabet, not base64. Variant runs cover STANDARD
    encodings only; a custom-alphabet envelope will NOT match and the chain
    is reported `unresolved` rather than guessed at. Crossing that needs the
    alphabet extracted from captured script-source plus a parameterized
    decoder - deliberately not built on a guess.
- **compile-provenance (v11, pass 2)** - the byte graph cannot see WHO
  eval'd the token code (an eval'd chunk's source is code, not payload). But
  when a PROVEN chain's first fragment materialized, some chain was the
  active C++->JS entry (kind-8) - that chain ran the eval / dynamic import /
  Function constructor. It is marked `spawned-proven` with the child names in
  the report. Direction is deliberately one-way UP: taint is NOT inherited
  downward, because a deobfuscator legitimately evals both the token pipeline
  and piles of library code - downward inheritance would drag every template
  engine into the filtered zip.
- **four-state verdict (v11, pass 3)** - every chain carries a `verdict`:
  - `proven` - graph-sink | send-initiator | token-access | spawned-proven:
    observed FACTS (byte identity to a sink, an entry that initiated the send,
    an entry that touched the stored token, an entry that compiled proven
    code).
  - `heuristic` - token-forming by evidence, not proof: sink-call text match,
    handler-born window, fp-probes, integrity-check, net-window. Kept in the
    filtered zip by default because the real collectors often live here.
  - `dead-end-proven` - no link AND a COMPLETENESS WITNESS: zero sink-ring
    drops (kind 39, 0023) in this pid up to the end of the chain's
    materialization window. Only then is the absence of a link evidence
    instead of a capture gap. Per-chain the report also carries
    `dead_end_witness.ring_drops_in_pid`.
  - `unresolved` - no link and no witness: the capture may have dropped the
    evidence, or the dataflow never crossed a C++ boundary (fingerprint ->
    closure variable -> sent 30 s later by another chain). NEVER claimed to
    be a proven dead end.
  `AF_STRICT_GRAPH=1` cuts the filtered zip to `proven` only; the run zip
  never changes. Still honest limits: a pure-JS transform chain (custom
  DEFLATE/RSA/encoder, CryptoJS-style AES with `subtle.crypto` never called)
  produces NO intermediate payload record, so nothing between collect and
  wire can be linked by bytes - those chains land in `unresolved` or
  `dead-end-proven`, and the token story survives through the assembling and
  sending chains that ARE proven.
- **dead-end classification (v7, hardened v9)** - every chain
  additionally gets `token_forming` + the `signals` that fired:
  `sink-call` (own code carries a collector/network sink call) |
  `handler-born` (materialized in an event/timer window; v9: triggers
  narrowed to CAUSAL kinds {input, event-dispatch, timer} - v7 counted
  read-kinds, so the load-phase fp storm trigger-marked every early
  chain and filtered==run; mousemove/pointer-move are ambient, not
  triggers) |
  `fp-probes` (>=2 distinct fingerprint reads during materialization) |
  `integrity-check` (kind-32 self-checks in window) |
  `net-window` (materialized inside a network request's 5 s
  payload-formation window; v9: seeds narrowed to requests that CAN
  carry a payload - non-GET/HEAD method, antifraud-vendor host, or a
  req-body span - v7 seeded with every subresource GET) |
  `content-sink` (v8: payload record sharing blake3 content-runs with
  a crypto/upload sink, no timer; v9 sinks: crypto-out 0018,
  ws-frame-out 0017; v9 carriers: taint-edge 0016) |
  `send-initiator` / `token-access` / `fp-probes-entry` (v9 ENTRY-JOIN,
  see below).
  No signal = **dead end**: the code ran but nothing it produced is
  observable in any token-feeding position.
- **entry-join (v9)** - the kind-8 call-completed stream (0003 Invoke
  funnel) is the ready-made caller identity: for every fetch
  initiation (kind 28), cookie/storage access (kind 16, 0013) and
  fingerprint read (kind 29) the last C++->JS entry at or before its
  ts in the same pid (250 ms window) names the executing script, which
  joins to a chain by display name. Signals: `send-initiator` (chain
  really initiated a send - observed, beats the sink-call TEXT match),
  `token-access` (chain read/wrote the stored token), `fp-probes-entry`
  (>=2 distinct fp reads with this chain as the entry - immune to the
  window false-positives). Honest limits: the entry is the nearest
  C++->JS boundary, not the exact reader (JS->JS calls skip Invoke);
  same-pid threads interleave (no tid in the wire format); main+worker
  same-URL chains in one pid collide. All strictly better than window
  guessing, all recomputable from the raw stream.
- **two zips** - the run zip keeps the v6 keep rule (hot OR
  token-forming OR `AF_SINK_KEEP_COLD=1` OR `AF_KEEP_BIG=1`+big -
  at least as complete as v6, no downgrade); the filtered zip is cut
  on its own copy to **token-forming chains only** ("what actually
  builds the challenge token"). v9 fix: the cut walks the UNCAPPED
  `prune` list in report.json, not the 4000-entry `chains[]` cap -
  before, chains past the cap silently escaped the cut and dead ends
  leaked into the token-only zip (eval storms produce thousands).
  Dead ends are dropped from the filtered zip but stay whole in the
  run zip - nothing is lost, only sorted.
- **payload formation** - every network request entry carries what fed
  it: trigger (closest preceding input/event/timer), the fingerprint
  reads in the preceding 5 s (`fp_reads_5s`), integrity checks and
  clock burns - all relative to nav-start ms.
- **wasm** - `.wasm` dump + offline import/export walk + the **imports
  as resolved at instantiation** attached to the closest preceding
  module of the same pid.
- attribution honesty: kind-29 reads have no JS-caller identity in C++
  (no stack walk). v9 recovers it EXTERNALLY via the entry-join above;
  the time-window attribution remains as the secondary column for
  records the entry-join cannot reach (no entry within 250 ms, native
  entries, cross-thread interleave). Both recomputable from the raw
  stream the index keeps.

## apply

```
cd chromium/src
git apply patches/0001-*.patch   # ... through 0025, in order
```

GN args (the CI build uses exactly these - `scripts/build-chromium.sh`):

```
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
```

The `extra_cflags` block is the v7 load-bearing fix: it puts the afeye
defines on the command line of EVERY compile (v8, blink, net, content,
host tools) so an `#ifdef`-guarded hook can never again depend on GN
scope propagation being right. The GN-side `if (v8_enable_afeye)
defines += [...]` blocks stay as a second belt.

Run with `--no-sandbox` and `AFEYE_SINK=1` in the environment. Without
the env var the patched build is stock behavior. Sinks read
`AFEYE_RAW_DIR` (default `/tmp/afeye-raw`); `AFEYE_TRACE_CALLS=0`
disables the call stream, `AFEYE_TRACE_CLOCK=0` the clock stream.

## honest limits

- ~~`WebAssembly.compileStreaming` decodes in chunks and never
  materializes one buffer at Sync/AsyncCompile~~ **FIXED (0020)**: the
  streaming wire bytes are captured at `AsyncStreamingProcessor::
  OnFinishedStream` and the code-cache restore at `Deserialize` (tag
  `cached`). What remains honestly out: per-call wasm export invocation
  logging - dispatch is generated machine code (JSToWasm wrappers,
  per-arch), no C++ funnel exists; the substitute is the firstcall
  record (which function indices executed, once each).
- **Intl resolvedOptions timeZone is NOT captured** (audit G8,
  rejected): the value is ICU/CppGCManaged-backed - safe extraction
  without a compile-verify loop was not achievable, and a half-hook
  that looks complete is worse than none. The timeZone still leaves
  the process through boundaries that ARE captured: it enters payload
  strings via JSON.stringify (0021) / TextEncoder (0016) before the
  wire. Locale-only capture was not shipped either - it would burn a
  1511-line TU for a field that never stands alone in a token.
- **Proxy birth/trap invocations are NOT captured** (audit R3):
  allocation and the hot trap dispatch are CSA/Torque-generated; the
  C++ fallbacks fire only on slow paths and would give a misleading
  partial picture. ~~Partial real coverage exists: proxy getOwnPropertyDescriptor traps do
  NOT cross the 0022 GOPD hook~~ **FIXED (0025)**: the proxy branch of
  JSReceiver::GOPD (the exact spot js-objects.cc:1985 where holders
  early-return into JSProxy::GetOwnPropertyDescriptor) now emits
  `gopd holder=proxy key=K` before the call - the probe fact is captured
  for PROXY holders too (the antifraud pattern: proxy-wrap navigator,
  then GOPD it to detect the wrap).
- **defineProperty/defineOwnProperty is NOT captured** (audit R4,
  deferred): the honest funnel is `JSReceiver::DefineOwnProperty`
  (js-objects.cc, same TU as 0022 - zero marginal cost), but it needs a
  noise filter first: Error construction itself defines properties
  (the stack accessor), bootstrapper defines hundreds; an unfiltered
  hook drowns the stream. Left as a follow-up with the filter designed
  against real .rec volume, not guessed.
- **The graph CANNOT see these, and says `unresolved` instead of guessing**
  (verified against pristine 153 + the repo's own capture):
  - *cross-chain closure handoff*: fingerprint collected at 200 ms, held in a
    closure variable, sent at 30 s by a DIFFERENT chain. No C++ boundary is
    crossed between collect and send, so no byte ever links them. The
    single-chain case IS proven (hop 0); the two-chain case is not.
  - *pure-JS transforms*: a vendor serializer that goes `charCodeAt` -> manual
    `Uint8Array.push` -> custom-alphabet encoder -> DEFLATE/RSA never touches
    TextEncoder, btoa, subtle.crypto or any hooked boundary. afeye sees the
    final wire body and nothing between. This is the hardest real limit: it is
    why `unresolved` is a first-class verdict rather than an error state.
  - *wasm internal computation*: the GROW pattern is now captured (0025:
    wasm-mem grow events at all three Grow exits) but the linear-memory
    CONTENTS are not - per-access capture needs CSA hooks that do not exist
    at this rev. Per-call export dispatch is generated machine code (no C++
    funnel exists). Input and output are visible if they cross a hooked
    boundary; kind-31 firstcall proves WHICH functions ran, kind-34 exec
    events (0025) name every wasm function as compiled.
  - ~~*cookie -> request header*~~ **FIXED (0025)**: `SetCookieHeaderAndStart`
    now emits the exact `Cookie:` line as a `cookie-attach` EmitSpan (net kind
    17) - the attach is a RECORD, and the graph joins it to the blink
    cookie-set VALUE bytes by content. The old inference-only path is dead.
  - *gzipped responses*: kind-18 resp-body is RAW WIRE bytes, script-source is
    DECOMPRESSED - they cannot byte-match, so a dynamic-import module is not
    linked to its response by content. The module is still attributed
    structurally via URL-identity (`fetched_url`), which is why kind-18 is
    deliberately kept OUT of the graph: it would spend the node budget on
    subresource responses that can never link.
- **G6 caller-edges are NOT walked at lazy-compile time.** The audit
  proposed a JavaScriptStackFrameIterator walk in Compiler::Compile to
  name caller->callee. Rejected for this pass: it runs on EVERY
  function's first call, and a frame-walk bug I cannot compile-verify
  risks bricking the whole capture. What ships instead: the callee
  first-execution fact (lazy-compile records, 0022) + caller chains
  from Error.stack materialization (0021) at the moments antifraud
  introspects + C++->JS entries from Invoke (0003). The caller-frame
  edge stays a follow-up to be landed with a compile loop available.
- Fast-API overloads (`NoAllocDirectCall`) bypass the 0008 thunk when
  argument types match; the slow path always lands. `getParameter` and
  friends are NOT fast-API, so the fingerprint sweep is fully covered.
- wasm-instance attribution is by time + pid window (5 s): two
  instantiations of different modules inside one window both carry the
  same resolved-import list. Documented, bounded, recomputable.
- time-correlated attribution (script triggers, fp-read windows,
  dead-end net-windows) is a heuristic; the raw stream keeps every
  exact ts, so any correlation can be recomputed offline.
- 0003's `Invoke` covers C++ -> JS entries; JS -> JS calls do not
  cross the boundary (interpreter hooks no longer exist). Invoke is
  strictly deeper than v6's api.cc hook: it also sees `Script::Run`,
  microtask jobs, revivers and v8-internal callers.
- workers: the v8 sink is in libv8 (every isolate hits the compile
  funnels); the blink sink is in blink_platform (workers link it);
  `DOMTimer` hooks are window-context only; kind-35 births join the
  `iso:` chains to worker names.
- a hard SIGKILL can lose the last ring backlog of a process (bounded
  by the 8 MiB ring; `Flush(500)` via atexit covers graceful exits).
  The drain thread uses raw `write()` - no stdio buffer to flush.
- v8 script-source records are head-capped at 1 MiB (flag `f:1`); blink
  spans cap at 64 KiB, net at 256 KiB. Full response bodies still come
  from the CDP capture side; the sink streams are structure +
  provenance.

## verification

- the series applies cumulatively to a pristine 153.0.8010.52 tree
  (11/11; v7-modified hunks re-validated against freshly fetched
  pristine `v8/BUILD.gn`, `execution.cc`, `api.cc`, `event_target.cc`,
  `event_dispatcher.cc`, `dom_timer.cc`, `resource_fetcher.cc`,
  `platform/BUILD.gn` - chromium.googlesource.com at the pinned refs)
- `tests/sink_roundtrip.rs`: the sink C++ shipping inside 0001/0005/
  0011 is extracted from the patches, compiled with g++, run with the
  battery, drained through the production collector and verified
  byte-exact - the bytes in the patch are provably the bytes that
  produced the timeline. Green, including the batched kinds. The
  Rust side: 53 tests green including the v7 dead-end classification
  (`net_window_overlap`, `dead_end_classification`).
- the funnel claims above cite the pinned source (file:line), not
  documentation
- the built chrome announces itself: first record in every `.rec` is
  the sink-hello; zero hellos means stock chrome - the crawler prints
  `sink layer DEAD` and the manifest carries `sink_alive=false`.
  v7 adds the CI-side teeth: `tools/rec_census.py` assertions on real
  captured kinds - a layer that compiled to nothing fails the smoke.
