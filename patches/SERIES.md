# afeye chromium patch series v6

**11 patches** against **Chromium 153.0.8010.52** (v8 rev
`d1fed5cd7e3b114dea70f18b20d26f816322833d`). The whole series is
re-verified to apply cumulatively with plain `git apply` against a
pristine tree assembled from sources fetched at that tag
(11/11, `scripts/validate_v6_apply.sh` on the real files).

v6 is the depth pass over v5's consolidation: **capture raw inside
Chrome at every true funnel, filter outside.** What v5 honestly
documented as "no single C++ chokepoint, JS-injection only" - the
`Function.prototype.toString` integrity probe and per-DOM-property
reads - now has real C++ funnels (0004 + 0008). Input is captured at
the source managers (0009), the page timeline is anchored at
navigation start in the sink clock domain (0010), workers are joined
by isolate pointer (0010 + the `iso:` script prefix), and the
collector batches the high-frequency streams so an eval-storm no
longer explodes into 10k one-kilo files (`src/collect.rs`), while
`src/sinkfilter.rs` slices backwards from network sends through the
new streams.

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
| `v8::Function::Call` (api.cc) | every C++-invoked JS entry: listener callbacks, promise continuations. Callee script:line. `AFEYE_TRACE_CALLS=0` off, 4M cap |
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
| 0003 v8-calls-wasm | 3 (`api.cc`, `wasm-engine.cc`, `module-instantiate.cc`) | v8 |
| 0004 v8-engine-fidelity | 3 (`builtins-function.cc`, `builtins-date.cc`, `microtask-queue.cc`) | v8 |
| 0005 blink-sink | +1 new (`platform/afeye/sink.cc`) + BUILD.gn | blink_platform |
| 0006 blink-flow | 3 (`event_dispatcher.cc`, `dom_timer.cc`, `resource_fetcher.cc`) | blink core/platform |
| 0007 blink-probes | 10 (`element.cc`, `html_element.cc`, `webgl_rendering_context_base.cc`, `base_rendering_context_2d.cc`, `offline_audio_destination_handler.cc`, `rtc_peer_connection.cc`, `media_device_info.cc`, `crypto.cc`, `subtle_crypto.cc`, `serialized_script_value.cc`) | blink core/modules |
| 0008 blink-dom-api | 1 (`idl_member_installer.cc`) | blink platform |
| 0009 blink-input | 2 (`mouse_event_manager.cc`, `keyboard_event_manager.cc`) | blink core |
| 0010 blink-context | 2 (`document_load_timing.cc`, `worker_or_worklet_global_scope.cc`) | blink core |
| 0011 net-wire | 3 (`url_loader.cc`, `websocket.cc`, + sink TU + BUILD.gn) | network service |

~30 changed/new TUs total. The CI build (`scripts/build-chromium.sh`)
runs `ccache -z` before ninja and `ccache -s` after: on a warm cache
only these TUs recompile - a series tweak costs minutes, not hours.
First build chains across 4h30m windows under the 6h runner cap
(`afeye-build.yml`: manual dispatch only, self-retriggering, ccache
carried by actions/cache). Target `headless_shell`: half the ninja
graph of `chrome`, still every patched layer (v8 / blink / net).

## wire format (unchanged v2)

Every sink appends to `$AFEYE_RAW_DIR (default /tmp/afeye-raw)/<layer>-<pid>.rec`:
```
u32 total_le | u8 kind | u8 flags | u16 rsvd=0 | u64 ts_ns_le | payload[total - 16]
```
`ts_ns` is `CLOCK_MONOTONIC` nanoseconds, identical clock domain in
every sink process, so all streams merge into one diff-able timeline.
First record in each file is kind 0 (`afeye-sink/<layer> v2 pid=...`).
Ring: 8 MiB, spinlock-guarded, overflow drops + counts; `Flush(500)`
at exit.

Kinds after v6: 0 sink-hello, 1 script-source (v8, `iso:` names),
3 wasm-module, 8 call-origin, 11 crypto-op, 12 timer, 15
structured-clone, 16 fingerprint (device identities + webgl), 17
net-request, 18 net-resp-body, 19 websocket, 23 input, 24
event-dispatch, 25 dom-metric, 26 audio, 27 webrtc, 28 fetch, **29
dom-api**, **30 microtask**, **31 wasm-instance**, **32
fn-tostring**, **33 clock**, **34 isolate**, **35 worker**, **36
nav-start**. Silent (wire compat): 2, 4-7, 9-10, 13-14, 20-22.

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
cc_wrapper = "ccache"
use_clang_modules = false
enable_nacl = false
v8_enable_afeye = true
blink_enable_afeye = true
network_enable_afeye = true
```

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
- time-correlated attribution (script triggers, fp-read windows) is a
  heuristic; the raw stream keeps every exact ts, so any correlation
  can be recomputed offline.
- 0003's `Function::Call` covers C++ -> JS entries; JS -> JS calls do
  not cross the API boundary (interpreter hooks no longer exist).
- workers: the v8 sink is in libv8 (every isolate hits the compile
  funnels); the blink sink is in blink_platform (workers link it);
  `DOMTimer` hooks are window-context only; kind-35 births join the
  `iso:` chains to worker names.
- a hard SIGKILL can lose the last ring backlog of a process (bounded
  by the 8 MiB ring; `Flush(500)` via atexit covers graceful exits).
- v8 script-source records are head-capped at 1 MiB (flag `f:1`); blink
  spans cap at 64 KiB, net at 256 KiB. Full response bodies still come
  from the CDP capture side; the sink streams are structure +
  provenance.

## verification

- the series applies cumulatively to a pristine 153.0.8010.52 tree
  (11/11 via `scripts/validate_v6_apply.sh`, pristine files fetched
  from chromium.googlesource.com at the pinned refs)
- `tests/sink_roundtrip.rs`: the sink C++ shipping inside 0001/0005/
  0011 is extracted from the patches, compiled with g++, run with the
  battery, drained through the production collector and verified
  byte-exact - the bytes in the patch are provably the bytes that
  produced the timeline. Green, including the batched kinds.
- the funnel claims above cite the pinned source (file:line), not
  documentation
- the built shell announces itself: first record in every `.rec` is the
  sink-hello; zero hellos means stock chrome - the crawler prints
  `sink layer DEAD` and the manifest carries `sink_alive=false`
