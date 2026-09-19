# afeye chromium patch series v5

**7 patches** against **Chromium 153.0.8010.52** (v8 rev
`d1fed5cd7e3b114dea70f18b20d26f816322833d`). The whole series is
re-verified to apply cumulatively with plain `git apply` against a
pristine tree fetched from `chromium.googlesource.com` at that tag
(7/7, checked on the real fetched sources - see "verification").

v5 is the consolidation the project asked for: **capture raw inside
Chrome at the few true funnels, filter outside.** Nothing decides inside
the browser about what is "interesting" - the patched build streams
everything it sees to record files, and `src/sinkfilter.rs` (chain
merge, backward slicing, timing chains) turns that into the analysis
output afterwards. 19 patches became 7, ~29 changed Chromium
translation units became ~19 (16 existing + 3 new sink TUs), and every
funnel symbol below was verified against the actual pinned source, not
guessed.

## the funnels (all symbols verified in the pinned tree)

### scripts - every line of JS that executes, exactly once

`0002` hooks the three compiler.cc entry points that together see 100%
of script sources, workers and service workers included (the sink is
compiled into libv8, so every isolate hits it):

| funnel | covers | verified at |
|---|---|---|
| `GetSharedFunctionInfoForScriptImpl` | every **buffered** compile: classic scripts, modules, code-cache consume, compile hints, extensions, embedder API. All four `CompileUnboundInternal` variants (`GetSharedFunctionInfoForScript`, `...WithCachedData`, `...WithDeserializeTask`, `...WithCompileHints`) and `...WithExtension` funnel here | compiler.cc:3947; call sites 4117-4175 |
| `GetSharedFunctionInfoForStreamedScript` | every **streamed** compile - the normal path for external `<script src>` in Chrome (blink's `ScriptStreamer` hands over `ScriptCompiler::Compile(context, StreamedSource*, code, origin)`) | v8_script_runner.cc:142-147 -> api.cc:2931 -> compiler.cc:4295. **v4 missed this** - streamed scripts were only seen by the (now removed) blink duplicate |
| `Compiler::GetFunctionFromEval` | every `eval()` / `new Function()` - where deobfuscated code materializes. Own path: eval-cache lookup, then `CreateScript` + `CompileToplevel`, NOT through the Impl above | compiler.cc:3301 |

### calls + wasm - `0003`

| funnel | covers |
|---|---|
| `v8::Function::Call(v8::Isolate*, ...)` (api.cc) | every C++-invoked JS entry: event listener callbacks, promise continuations, blink scripting. Logs callee script:line. `AFEYE_TRACE_CALLS=0` disables; 4M-record hard cap |
| `WasmEngine::SyncCompile` / `AsyncCompile` (wasm-engine.cc) | full wasm module bytes (buffered `new WebAssembly.Module` / `compile` / `instantiate`) |

### the telemetry scripts consume - `0005` (flow)

| funnel | covers |
|---|---|
| `EventDispatcher::DispatchEvent` | **the** event funnel: every dispatched event, type + `isTrusted` + target node + mouse client/screen coords + key/code, ns timestamp. Sets the blink ambient tag `evt:<type>` |
| `DOMTimer` ctor + `DOMTimer::Fired` | timer installs (id/timeout/single) and fires (id/nesting). Fires set the ambient tag `timer:<id>` |
| `ResourceFetcher::RequestResource` | renderer-side request provenance: url + resource type + ambient cause, logged BEFORE the mojo hop (the network service is another process and cannot see the tag) |

### the probes - `0006` (what fingerprinting actually reads)

| funnel | covers |
|---|---|
| `Element::getClientRects` / `GetBoundingClientRectForBinding` | DOM geometry reads (tag + ambient cause) |
| `BaseRenderingContext2D::measureText` / `getImageData` | font-probe (text + unparsed font) + canvas readback geometry |
| `OfflineAudioDestinationHandler::FinishOfflineRendering` | rendered offline-audio channel-0 head - the actual audio-fingerprint digest |
| `RTCPeerConnection` `createOffer` / `setLocalDescription` / `addIceCandidate` | full SDP + ICE candidates (local IP / device leaks) |
| `MediaDeviceInfo` ctor | device id / group / label - real device identities, not a marker |
| `Crypto::getRandomValues` / `SubtleCrypto` encrypt/decrypt/sign/digest/deriveBits | nonces and plaintext BEFORE BoringSSL - the payload-forming crypto |
| `SerializedScriptValue(DataBufferPtr)` ctor | full structured-clone bytes: postMessage / BroadcastChannel payloads, worker <-> main channel |

### the wire - `0007`

| funnel | covers |
|---|---|
| `URLLoader::ScheduleStart` / `SetUpUpload` / `ContinueOnResponseStarted` / `DidRead` / `NotifyCompleted` | method + url, request headers, **upload bodies before TLS**, response headers/mime, response body spans, completion |
| `WebSocket` frame handler | WS frames both directions |

## what v5 dropped from v4, and why

Every removal was checked against the pinned source first:

| v4 patch | verdict |
|---|---|
| 0002 `ScriptCompiler::CompileUnboundInternal` (api.cc) | **duplicate**: all four variants funnel into `GetSharedFunctionInfoForScriptImpl` (verified compiler.cc:4117-4175) - v4 dumped every public-API script twice |
| 0005 microtasks + SAB + wasm memory grow | pipeline geometry, not payload-forming data; the JS injection covers the observable side |
| 0007 blink `CompileScriptInternal` / `CompileModule` | **duplicate** of the v8 compile funnels (streamed + buffered both covered in 0002 now). The ambient-cause it baked into script names moved to the external filter (time correlation, `AF_SCRIPT_TRIGGER_MS`) |
| 0009 `message_port` + `broadcast_channel` hooks | marker-only ("message-port-post"); the `SerializedScriptValue` ctor already captures the actual bytes |
| 0010 permissions / enumerateDevices / performance marks / toDataURL | marker-only; devices kept via the `MediaDeviceInfo` ctor (real data); perf marks are the script's own bookkeeping, visible in its source |
| 0011 `performance_observer` + `performance_entry` | marker-only |
| 0013 `cache_storage` open/match | marker-only; real requests hit the net wire |
| 0014 `EventHandler::HandleMouse*` | **duplicate** of the EventDispatcher funnel: same coords/mods/keys, and `isTrusted` already separates real from synthetic |
| 0004 `wasm-js.cc` part (Table.get/set, Memory.grow) | markers/geometry; import/export analysis runs offline on the module bytes |

Two v4 **compile bugs** fixed in v5's 0002 while consolidating:

1. `AfeyeDumpScriptSource` was *defined* ~650 lines *after* the
   `GetFunctionFromEval` call site - no forward declaration, the TU
   would not have compiled. The helper now lives at the top of the
   anonymous namespace, before all three call sites.
2. It took `Handle<String>` where the eval funnel passes
   `DirectHandle<String>` (and `Utils::ToLocal` wants the direct one).
   The parameter is now `DirectHandle<String>`, which accepts both
   callers in every build configuration.

## compile cost (what "only the changed files compile" means here)

| patch | Chromium TUs touched | libraries that relink |
|---|---|---|
| 0001 v8-sink | +1 new (`v8/src/afeye/sink.cc`) + BUILD.gn + flag header | v8 |
| 0002 v8-scripts | 1 (`compiler.cc`) | v8 |
| 0003 v8-calls-wasm | 2 (`api.cc`, `wasm-engine.cc`) | v8 |
| 0004 blink-sink | +1 new (`platform/afeye/sink.cc`) + BUILD.gn | blink_platform |
| 0005 blink-flow | 3 (`event_dispatcher.cc`, `dom_timer.cc`, `resource_fetcher.cc`) | blink core/platform |
| 0006 blink-probes | 8 (`element.cc`, `base_rendering_context_2d.cc`, `offline_audio_destination_handler.cc`, `rtc_peer_connection.cc`, `media_device_info.cc`, `crypto.cc`, `subtle_crypto.cc`, `serialized_script_value.cc`) | blink core/modules |
| 0007 net-wire | 3 (`url_loader.cc`, `websocket.cc`, + sink TU + BUILD.gn) | network service |

That is the entire compile surface. The CI build
(`scripts/build-chromium.sh`) runs `ccache -z` before ninja and prints
`ccache -s` after: on a warm cache the hit rate shows that only these
~19 TUs (plus cold misses on a fresh runner) actually recompile - a
patch-series tweak costs minutes of compile + relink, not hours. The
first build chains across 4h30m windows under the 6h runner cap
(`afeye-build.yml`: manual dispatch, self-retriggering, ccache carried
by actions/cache between runs). Target is `headless_shell`: half the
ninja graph of `chrome`, still every patched layer (v8 / blink / net).

## wire format (unchanged v2)

Every sink appends to `$AFEYE_RAW_DIR (default /tmp/afeye-raw)/<layer>-<pid>.rec`:

```
u32 total_le | u8 kind | u8 flags | u16 rsvd=0 | u64 ts_ns_le | payload[total - 16]
```

`ts_ns` is `CLOCK_MONOTONIC` nanoseconds, identical clock domain in every
sink process, so all streams merge into one diff-able timeline. First record
in each file is kind 0 (`afeye-sink/<layer> v2 pid=...`). Ring: 8 MiB,
spinlock-guarded, overflow drops + counts; `Flush(500)` at exit.

Kinds in play after v5: 0 sink-hello, 1 script-source (v8), 3 wasm-module,
8 call-origin, 11 crypto-op, 12 timer, 15 structured-clone, 16 fingerprint
(device identities), 17 net-request, 18 net-resp-body, 19 websocket,
22 (reserved, silent), 24 event-dispatch, 25 dom-metric, 26 audio,
27 webrtc, 28 fetch. Silent in v5 (kept for wire compat): 4-5, 6-7, 9-10,
13-14, 21, 23.

## the deep filter (what leaves the runner) - `src/sinkfilter.rs`

Runs once after a crawl, over `collect/`:

- **chains** - all script-source fragments of one origin (pid + script
  name) merge into ONE file with `/* ==== [ts] hash ==== */` separators.
  A loader that evals itself in 10k micro-chunks lands as one stream.
- **taint (backward slicing)** - a chain is HOT when its code carries a
  collector sink call (`fetch(`/XHR/beacon/WebSocket/toDataURL/
  getImageData/measureText/OfflineAudioContext/RTCPeerConnection/...)
  OR when it materialized inside a handler/timer. v5 links the second
  by time: the closest preceding event/timer record within
  `AF_SCRIPT_TRIGGER_MS` (default 250 ms) - the v4 blink ambient tag,
  reconstructed externally where it belongs. Every chain's report entry
  carries its trigger (kind, ts, delta_ms, what).
- **wasm** - modules dumped as `.wasm` + import/export sections parsed
  offline into `filtered/wasm-index.json`.
- **timing chains** - for every network request the closest preceding
  trigger (within 250 ms) links into `filtered/report.json`
  (`net_chains`): the T0 input -> T1 dispatch -> T2 send timeline.
- after a successful filter the per-record `collect/raw/` bins are pruned
  (the 10k-file problem); `collect/index.jsonl` keeps every hash + ts +
  pid, so every dropped byte stays traceable to its origin.

## apply

```
cd chromium/src
git apply patches/0001-*.patch   # ... through 0007, in order
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

Run with `--no-sandbox` and `AFEYE_SINK=1` in the environment. Without the
env var the patched build is stock behavior. Sinks read `AFEYE_RAW_DIR`
(default `/tmp/afeye-raw`); `AFEYE_TRACE_CALLS=0` disables the call stream.

## honest limits

- `WebAssembly.compileStreaming` decodes the module in chunks and never
  materializes one buffer at `SyncCompile`/`AsyncCompile`; those modules
  are captured as network response bodies by the net-wire layer (fetched
  .wasm crosses `URLLoader::DidRead`), but they are not re-tagged as
  `wasm-module` records. Buffered wasm (embedded-in-JS modules - the
  antifraud case) is always captured whole.
- v8 script-source records are head-capped at 1 MiB (flag `f:1`); blink
  spans cap at 64 KiB, net at 256 KiB. Full response bodies still come
  from the CDP capture side; the sink streams are structure + provenance.
- `Function.prototype.toString` / native-integrity inspection has no
  single C++ chokepoint in 153 (Torque builtins). Covered by the JS
  injection (`src/inject.rs` wraps it with stack capture), not here.
- per-DOM-property getter logging has no single C++ chokepoint either
  (bindings are generated per-IDL). The JS injection's getter proxies
  cover `navigator`/`screen`/`window`/element geometry instead.
- wasm imports/exports during EXECUTION are not tracked in C++ - the
  module bytes are captured at compile and the import/export tables
  are parsed offline by the filter, which answers "what could it call"
  without executing anything.
- workers: the v8 and blink sinks are compiled into the shared
  libraries (libv8 / blink platform), so worker and service-worker
  isolates hit the same compile chokepoints. `DOMTimer` hooks are
  window-context only.
- time-correlated script triggers are a heuristic, tunable via
  `AF_SCRIPT_TRIGGER_MS`; a mousemove storm can attribute a chain to
  the wrong neighboring event. The raw stream keeps the exact ts of
  every record, so the correlation can always be recomputed offline.
- a hard SIGKILL can lose the last ring backlog of a process (bounded
  by the 8 MiB ring and drain rate; `Flush(500)` via atexit covers
  graceful exits).
- 0003's `Function::Call` covers C++ -> JS entries. JS -> JS calls do
  not cross the API boundary and are not logged (interpreter hooks for
  that no longer exist).

## verification

- every patch applies cumulatively to a pristine 153.0.8010.52 tree
  (`git apply`, checked against freshly fetched sources: 7/7; the
  pristine files also accepted the eleven v4 patches whose files v5
  keeps, byte-for-byte)
- the three sink translation units compile standalone with
  `g++ -std=c++17 -D{V8,BLINK,NET}_AFEYE`
- the funnel claims above cite the pinned source (file:line), not
  documentation
- the built shell announces itself: first record in every `.rec` file
  is the sink-hello; `collect/stats.json` records=0 with zero
  sink-hellos means the running binary is not the patched build - the
  crawler prints `sink layer DEAD` and the manifest carries
  `sink_alive=false`
