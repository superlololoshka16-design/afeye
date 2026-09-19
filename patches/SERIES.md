# afeye chromium patch series v7

**11 patches** against **Chromium 153.0.8010.52** (v8 rev
`d1fed5cd7e3b114dea70f18b20d26f816322833d`). The whole series is
re-verified to apply cumulatively with plain `git apply` against a
pristine tree assembled from sources fetched at that tag
(11/11; v7 hunks re-validated on freshly fetched pristine files for
0001/0003/0006).

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
| `Invoke` (execution.cc:305) | **THE C++ -> JS funnel** (v7, replaces the api.cc hook): every entry - `v8::Function::Call`, `Script::Run`/`RunModule`, `Execution::New`, microtask callbacks, JSON revivers, comparators, v8-internal callers. Callee script:line. `AFEYE_TRACE_CALLS=0` off, 4M cap |
| `Isolate::New` (api.cc) | isolate birth record (kind 34) - the join key for `iso:` chains |
| `WasmEngine::SyncCompile` / `AsyncCompile` | full wasm module bytes (buffered `new WebAssembly.Module` / `compile` / `instantiate`) |
| `InstanceBuilder::ProcessImports` (module-instantiate.cc) | **the imports as RESOLVED at instantiation** - every `wasm-import <module.field> kind=` record, plus the instantiate header with the import count |

### engine fidelity - `0004` (the antifraud introspection surface)

| funnel | covers |
|---|---|
| `BUILTIN(FunctionPrototypeToString)` (builtins-function.cc) | WHO was toString-inspected: receiver name + script:line (kind 32) - the native-code integrity probe, pure observation, no result tampering. 2M cap |
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

~31 changed/new TUs total. The CI build (`scripts/build-chromium.sh`)
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

Kinds after v6: 0 sink-hello, 1 script-source (v8, `iso:` names),
3 wasm-module, 8 call-origin, 11 crypto-op, 12 timer, 15
structured-clone, 16 fingerprint (device identities + webgl), 17
net-request, 18 net-resp-body, 19 websocket, 23 input, 24
event-dispatch, 25 dom-metric, 26 audio, 27 webrtc, 28 fetch, **29
dom-api**, **30 microtask**, **31 wasm-instance**, **32
fn-tostring**, **33 clock**, **34 isolate**, **35 worker**, **36
nav-start**. Silent (wire compat): 2, 4-7, 9-10, 13-14, 20-22.

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
- **dead-end classification (v7)** - every chain additionally gets
  `token_forming` + the `signals` that fired:
  `sink-call` (own code carries a collector/network sink call) |
  `handler-born` (materialized in an event/timer window) |
  `fp-probes` (>=2 distinct fingerprint reads during materialization) |
  `integrity-check` (kind-32 self-checks in window) |
  `net-window` (materialized inside a network request's 5 s
  payload-formation window - the backward slice from the send).
  No signal = **dead end**: the code ran but nothing it produced is
  observable in any token-feeding position.
- **two zips** - the run zip keeps the v6 keep rule (hot OR
  token-forming OR `AF_SINK_KEEP_COLD=1` OR `AF_KEEP_BIG=1`+big -
  at least as complete as v6, no downgrade); the filtered zip is cut
  on its own copy to **token-forming chains only** ("what actually
  builds the challenge token"), via the `token_forming` flag in
  `report.json`. Dead ends are dropped from the filtered zip but
  stay whole in the run zip - nothing is lost, only sorted.
- **payload formation** - every network request entry carries what fed
  it: trigger (closest preceding input/event/timer), the fingerprint
  reads in the preceding 5 s (`fp_reads_5s`), integrity checks and
  clock burns - all relative to nav-start ms.
- **wasm** - `.wasm` dump + offline import/export walk + the **imports
  as resolved at instantiation** attached to the closest preceding
  module of the same pid.
- attribution honesty: kind-29 reads have no JS-caller identity in C++
  (no stack walk), so they are attributed BY TIME - documented, and
  recomputable from the raw stream the index keeps.

## apply

```
cd chromium/src
git apply patches/0001-*.patch   # ... through 0011, in order
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

- `WebAssembly.compileStreaming` decodes in chunks and never
  materializes one buffer at Sync/AsyncCompile; those modules are
  captured as network response bodies by the net-wire layer but not
  re-tagged as `wasm-module` records. Buffered wasm (embedded in JS -
  the antifraud case) is always captured whole; v6 additionally logs
  the streaming case's resolved imports at instantiation.
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
