# afeye chromium patch series v4

19 unified diffs against **Chromium 153.0.8010.52** (v8 rev
`d1fed5cd7e3b114dea70f18b20d26f816322833d`). Every hunk context was generated
programmatically from the real source files fetched from
`chromium.googlesource.com` at that tag, and the full series is re-verified to
apply cumulatively with plain `git apply` against the fetched tree (19/19).

## what v4 adds on top of v3 (the user post-mortem)

v3 captured the executing code and the wire. v4 closes the gaps that made the
capture blind to *cause and effect*:

1. **raw trusted input** (0014) - `EventHandler::HandleMouseMoveEvent` /
   `HandleMousePressEvent` log coordinates, modifiers, click count before any
   dispatch decision. Without this the logger was blind to the input side of
   the T0 -> T1 -> T2 chain.
2. **every DOM event dispatch** (0015) - `EventDispatcher::DispatchEvent` is
   the single chokepoint every dispatched event funnels through: type,
   `isTrusted`, target node, mouse client/screen coords, key/code, ns
   timestamp. Synthetic (`isTrusted=false`) vs real input is now visible.
3. **DOM + canvas geometry probes** (0016) - `getClientRects`,
   `GetBoundingClientRectForBinding`, `measureText` (text + unparsed font -
   the font-probing fingerprint), `getImageData` geometry.
4. **offline audio fingerprint** (0017) - the rendered sample buffer head at
   `OfflineAudioDestinationHandler::FinishOfflineRendering` (what
   `OfflineAudioContext` fingerprinting actually digests).
5. **WebRTC SDP/ICE** (0017) - `createOffer`, `setLocalDescription` (full
   SDP), `addIceCandidate` (ICE candidates) - local IP / device leaks.
6. **C++ -> JS call origin** (0018) - the `v8::Function::Call` funnel logs
   the callee's script origin + line for every blink-invoked callback
   (event handlers, promise continuations). `AFEYE_TRACE_CALLS=0` disables;
   a 4M-record hard cap keeps the call stream from ever starving the
   script-source stream.
7. **renderer-side fetch provenance** (0019) - `ResourceFetcher::RequestResource`
   logs url + resource type + the **ambient tag** (see below) BEFORE the mojo
   hop to the network service, so each request carries "who was running".
8. **ambient tag** (0006/0007/0011) - a thread-local execution-context string
   in the blink sink. The input/event/timer hooks SET it (`evt:<type>`,
   `timer:<id>`), the script-source and fetch hooks READ it: every captured
   script and every request carries its cause directly in its name.
9. **deep filter** (Rust, `src/sinkfilter.rs`) - the 10k one-kilo-file
   post-mortem: fragments merge into per-origin chains, wasm imports/exports
   are indexed offline, cold chains are sliced away, and every network
   request is linked to its closest preceding trigger.

## the layer map

Each patch owns exactly one layer - nothing intercepts what another patch
already intercepts:

| layer | patch | hook (real 153 symbol) | captures |
|---|---|---|---|
| v8 api | 0002 | `ScriptCompiler::CompileUnboundInternal` | every script through the public compile api |
| v8 internal | 0003 | `GetSharedFunctionInfoForScriptImpl` | the single internal chokepoint: streams, workers, embedders |
| **v8 eval** | 0003 | `Compiler::GetFunctionFromEval` | every `eval()` / `new Function()` - where deobfuscated code materializes |
| v8 calls | 0018 | `Function::Call` funnel | callee script:line of every C++-invoked JS callback |
| v8 wasm | 0004 | `WasmEngine::SyncCompile` / `AsyncCompile` | full wasm module bytes (imports/exports indexed offline by the filter) |
| blink handoff | 0007 | `CompileScriptInternal` + `CompileModule` | full source at the blink layer + ambient cause in the name |
| blink input | 0014 | `EventHandler::HandleMouse*` | raw trusted input: coords, mods, clicks |
| blink dispatch | 0015 | `EventDispatcher::DispatchEvent` | every dispatched event: type, isTrusted, target, mouse/keys |
| blink geometry | 0016 | `Element::getClientRects` / `GetBoundingClientRectForBinding` / `measureText` / `getImageDataInternal` | DOM + font measurement probes |
| blink audio | 0017 | `FinishOfflineRendering` | rendered offline-audio buffer head |
| blink webrtc | 0017 | `createOffer` / `setLocalDescription` / `addIceCandidate` | SDP + ICE candidates |
| blink fetch | 0019 | `ResourceFetcher::RequestResource` | request origin + resource type + ambient cause |
| net wire | 0012 | `URLLoader::ScheduleStart` / `SetUpUpload` / `ContinueOnResponseStarted` / `DidRead` / `NotifyCompleted` | method, url, headers, bodies, raw response, completion |

## the rest of the series

| # | file(s) | hook points | captures |
|---|---|---|---|
| 0001 | `v8/src/afeye/sink.{h,cc}` + `v8/BUILD.gn` + flags | env-activated ring + drain, GN arg `v8_enable_afeye`, flag `--afeye-source` | shared v8 plumbing |
| 0005 | `microtask-queue.cc` + `api.cc` + `backing-store.cc` | `EnqueueMicrotask(Tagged<Microtask>)` funnel, `PerformCheckpointInternal` bounds, SAB / wasm memory geometry | microtask pipeline shape, buffer geometry |
| 0006 | `platform/afeye/sink.{h,cc}` + `platform/BUILD.gn` | ring + drain, kinds 23-28, `SetTag`/`Tag` ambient context | shared blink plumbing |
| 0008 | `modules/crypto/{crypto,subtle_crypto}.cc` | `getRandomValues` (after fill), `encrypt/decrypt/sign/digest/deriveBits` | nonces, plaintext before BoringSSL |
| 0009 | `serialized_script_value.cc` + messaging | `SerializedScriptValue(DataBufferPtr)` ctor, `postMessage` both directions | full structured-clone bytes |
| 0010 | permissions / mediastream / performance / canvas | `Permissions::query`, `enumerateDevices`, `MediaDeviceInfo` ctor, `Performance::mark`/`MeasureInternal`, `toDataURL` | permission probing, device identities, perf marks, canvas readback attempts |
| 0011 | `core/scheduler/dom_timer.cc` + perf observer | `DOMTimer` install / `Fired` (fires also SET the ambient tag) | timer installs/fires, observer registrations |
| 0013 | `modules/cache_storage/cache_storage.cc` | `CacheStorage::open` / `match` | SW/CacheStorage synthetic-request markers |

## wire format (unchanged v2)

Every sink appends to `$AFEYE_RAW_DIR (default /tmp/afeye-raw)/<layer>-<pid>.rec`:

```
u32 total_le | u8 kind | u8 flags | u16 rsvd=0 | u64 ts_ns_le | payload[total - 16]
```

`ts_ns` is `CLOCK_MONOTONIC` nanoseconds, identical clock domain in every
sink process, so all streams merge into one diff-able timeline. First record
in each file is kind 0 (`afeye-sink/<layer> v2 pid=...`). Ring: 8 MiB,
spinlock-guarded, overflow drops + counts; `Flush(500)` at exit.

Kinds: 0 sink-hello, 1 script-source (v8), 3 wasm-module, 4-5 wasm memory/
table, 6-7 microtasks, 8 call-origin (v4 repurposed: the Function::Call
funnel), 10 sab-backing, 11 crypto-op, 12 timer, 13 perf-entry, 14 message,
15 structured-clone, 16 fingerprint, 17 net-request, 18 net-resp-body,
19 websocket, 21 sw-cache, 22 script-source (blink), **23 input, 24
event-dispatch, 25 dom-metric, 26 audio, 27 webrtc, 28 fetch**.

## the deep filter (what leaves the runner)

`src/sinkfilter.rs` runs once after a crawl, over `collect/`:

- **chains** - all script-source fragments of one origin (pid + script
  name) merge into ONE file with `/* ==== [ts] hash ==== */` separators. A
  loader that evals itself in 10k micro-chunks lands as one stream.
- **taint (backward slicing)** - a chain is kept when it reaches a
  collector sink (`fetch(`/XHR/beacon/WebSocket/toDataURL/getImageData/
  measureText/OfflineAudioContext/RTCPeerConnection/...) or was compiled
  inside a handler/timer (its name carries `evt:` / `timer:` provenance).
  Cold chains are counted and dropped: dead branches that never feed the
  token don't waste disk. `AF_SINK_KEEP_COLD=1` keeps everything.
- **wasm** - modules dumped as `.wasm` + import/export sections parsed
  offline into `filtered/wasm-index.json`.
- **timing chains** - for every network request the closest preceding
  input/event/timer/dom record (within 250 ms) links into
  `filtered/report.json` (`net_chains`): the T0 input -> T1 dispatch ->
  T2 send timeline with deltas in ms.
- after a successful filter the per-record `collect/raw/` bins are pruned
  (the 10k-file problem); `collect/index.jsonl` keeps every hash + ts +
  pid, so every dropped byte stays traceable to its origin.

## apply

```
cd chromium/src
git apply patches/0001-*.patch   # ... through 0019, in order
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

**Build target: `headless_shell`** (`NINJA_TARGET` in the build script). It
cuts roughly half the ninja graph of full `chrome` (no browser UI layer)
while keeping every layer we patch - v8, blink, content, net. That plus the
ccache chain is what keeps the Actions build inside its 4h30m windows and
therefor under the 6h runner cap, always.

Run with `--no-sandbox` and `AFEYE_SINK=1` in the environment. Without the
env var the patched build is stock behavior. Sinks read `AFEYE_RAW_DIR`
(default `/tmp/afeye-raw`); `AFEYE_TRACE_CALLS=0` disables the 0018 call
stream (on by default, capped at 4M records per process).

## honest limits

- v8 script-source records are head-capped at 1 MiB (flag `f:1`); blink
  spans cap at 64 KiB, net at 256 KiB. Full response bodies still come
  from the CDP capture side; the sink streams are structure + provenance.
- `Function.prototype.toString` / native-integrity inspection has no C++
  chokepoint in 153 (Torque builtins). That layer is covered by the JS
  injection (`src/inject.rs` wraps `Function.prototype.toString` with
  stack capture), not by the patch series.
- per-DOM-property getter logging has no single C++ chokepoint either
  (bindings are generated per-IDL). The JS injection's getter proxies
  cover `navigator`/`screen`/`window`/element geometry instead.
- wasm imports/exports during EXECUTION are not tracked in C++ - the module
  bytes are captured at compile and the import/export tables are parsed
  offline by the filter, which answers "what could it call" without
  executing anything.
- workers: the v8 and blink sinks are compiled into the shared libraries
  (libv8 / blink platform), so worker and service-worker isolates hit the
  same compile chokepoints. `DOMTimer` hooks are window-context only.
- a hard SIGKILL can lose the last ring backlog of a process (bounded by
  the 8 MiB ring and drain rate; `Flush(500)` via atexit covers graceful
  exits).
- 0018's `Function::Call` covers C++ -> JS entries (every blink-invoked
  callback). JS -> JS calls do not cross the API boundary and are not
  logged (that would require interpreter hooks that no longer exist).

## verification

- every patch applies cumulatively to pristine 153.0.8010.52 (`git apply`,
  verified against the fetched tree: 19/19)
- the three sink translation units compile standalone with
  `g++ -std=c++17 -D{V8_AFEYE,BLINK_AFEYE,NET_AFEYE}`
- the built shell announces itself: first record in every `.rec` file is
  the sink-hello; `collect/stats.json` records=0 with zero sink-hellos
  means the running binary is not the patched build - the crawler prints
  `sink layer DEAD` and the manifest carries `sink_alive=false`
