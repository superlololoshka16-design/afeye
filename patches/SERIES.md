# afeye chromium patch series v3

13 unified diffs against **Chromium 153.0.8010.52** (v8 rev
`d1fed5cd7e3b114dea70f18b20d26f816322833d`). Every hunk context was generated
from the real source files fetched from `chromium.googlesource.com` at that tag
and the full series is verified to apply cumulatively with plain `git apply`.

## why v3 exists (v2 post-mortem)

The v2 series was written against an **imagined** tree: `backend_request_timer_`,
`CreateDataPipeForConsumerAndStartRequestIfNecessary`, the old
`EnqueueMicrotask(DirectHandle<CallableTask>)` overloads and
`Runtime_TraceUnoptimizedBytecodeEntry` do not exist in any released Chromium
(verified across 112-153). Anchors that exist nowhere can never apply, so the
sink layer could never be compiled - which is exactly what every run showed
(`sink_alive=false`, `collect/raw` empty). v3 anchors only in code fetched and
grepped from the 153.0.8010.52 tag.

## the duplication matrix (executing-script capture)

The user requirement: the same executing script must be captured redundantly
at several engine layers, so a miss at one layer is covered by another.

| layer | patch | hook (real 153 symbol) | catches |
|---|---|---|---|
| v8 api | 0002 | `ScriptCompiler::CompileUnboundInternal` | every script compiled through the public api entry (page scripts, modules, code-cache paths) |
| v8 internal | 0003 | `GetSharedFunctionInfoForScriptImpl` | the single internal chokepoint - everything the api entry does plus streams, workers, embedders |
| **v8 eval** | 0003 | `Compiler::GetFunctionFromEval` | **every `eval()` and `new Function()` - this is where deobfuscated code materializes and executes** |
| blink | 0007 | `CompileScriptInternal` + `CompileModule` | full source text at the blink hand-off (survives streamed compilation, which never reaches the v8 api entry) with the document URL for provenance |
| net | 0012 | `URLLoader::ScheduleStart` / `SetUpUpload` / `ContinueOnResponseStarted` / `DidRead` / `NotifyCompleted` | wire truth: method, url, request headers, request body, raw response headers, decoded body chunks, completion |

An obfuscated loader that unpacks itself with `eval()` is therefore caught at
the eval chokepoint the moment it compiles the unpacked payload - and the same
bytes are independently confirmed at the blink and net layers.

## the rest of the series

| # | file(s) | hook points | captures |
|---|---|---|---|
| 0001 | `v8/src/afeye/sink.{h,cc}` + `v8/BUILD.gn` + `v8/src/flags/flag-definitions.h` | env-activated ring + per-process `.rec` drain, GN arg `v8_enable_afeye`, flag `--afeye-source` | shared v8 plumbing |
| 0004 | `v8/src/wasm/wasm-engine.cc` + `wasm-js.cc` | `WasmEngine::SyncCompile` / `AsyncCompile` (wire bytes up to 1 MiB), `WebAssemblyTableGet/SetImpl`, `WebAssemblyMemoryGrowImpl` | full wasm module bytes, table traffic, memory growth |
| 0005 | `v8/src/execution/microtask-queue.cc` + `v8/src/api/api.cc` + `v8/src/objects/backing-store.cc` | the single `EnqueueMicrotask(Tagged<Microtask>)` funnel, `PerformCheckpointInternal` bounds, `SharedArrayBuffer::New`, `TryAllocateAndPartiallyCommitMemory` | microtask pipeline shape, SAB / wasm memory geometry |
| 0006 | `third_party/blink/renderer/platform/afeye/sink.{h,cc}` + `platform/BUILD.gn` | same ring design, layer "blink", new kind `kScriptSource=22` | shared blink plumbing |
| 0008 | `modules/crypto/{crypto,subtle_crypto}.cc` | `Crypto::getRandomValues` (after the fill), `encrypt/decrypt/sign/digest/deriveBits` entries | nonces handed to the page, plaintext before BoringSSL |
| 0009 | `serialized_script_value.cc`, `core/messaging/message_port.cc`, `modules/broadcastchannel/broadcast_channel.cc` | the `SerializedScriptValue(DataBufferPtr)` constructor, `postMessage` both directions | full structured-clone bytes, message markers |
| 0010 | `permissions.cc`, `media_devices.cc`, `media_device_info.cc`, `performance.cc`, `html_canvas_element.cc` | `Permissions::query`, `enumerateDevices`, `MediaDeviceInfo` ctor, `Performance::mark` / `MeasureInternal`, `HTMLCanvasElement::toDataURL` | permission probing, real device identities, perf marks, canvas readback attempts |
| 0011 | `core/scheduler/dom_timer.cc` (moved from core/dom in 153), `performance_observer.cc`, `performance_entry.cc` | `DOMTimer::DOMTimer` (install), `DOMTimer::Fired`, `PerformanceObserver::observe`, `PerformanceEntry` ctor | timer installs/fires, observer registrations, entry timings |
| 0013 | `modules/cache_storage/cache_storage.cc` | `CacheStorage::open`, `CacheStorage::match` | SW/CacheStorage synthetic-request layer markers |

## wire format (unchanged v2)

Every sink appends to `$AFEYE_RAW_DIR (default /tmp/afeye-raw)/<layer>-<pid>.rec`:

```
u32 total_le | u8 kind | u8 flags | u16 rsvd=0 | u64 ts_ns_le | payload[total - 16]
```

`total` counts the whole record including the 16-byte header. `flags` bit0 =
truncated. `ts_ns` is `CLOCK_MONOTONIC` nanoseconds, identical clock domain in
every sink process, so v8/blink/net streams merge into one diff-able timeline.
First record in each file is kind 0 (`afeye-sink/<layer> v2 pid=...`) - instant
proof whether the C++ side is alive. Ring: 8 MiB, spinlock-guarded
multi-producer, overflow drops + counts; `Flush(ms)` drains at exit.

Kinds: 0 sink-hello, 1 script-source (v8), 2 bytecode-entry (reserved), 3
wasm-module, 4 wasm-memory, 5 wasm-table, 6 microtask-enqueue, 7
microtask-run, 8 call-completed, 9 atomics, 10 sab-backing, 11 crypto-op, 12
timer, 13 perf-entry, 14 message, 15 structured-clone, 16 fingerprint, 17
net-request, 18 net-resp-body, 19 websocket, 20 client-hints, 21 sw-cache,
**22 script-source (blink layer)**.

## apply

```
cd chromium/src
git apply patches/0001-*.patch   # ... through 0013, in order
```

GN args (the CI build uses exactly these - `scripts/build-chromium.sh`):

```
is_debug = false
is_official_build = false
is_component_build = false
symbol_level = 0
v8_symbol_level = 0
blink_symbol_level = 0
treat_warnings_as_errors = false
v8_enable_afeye = true
blink_enable_afeye = true
network_enable_afeye = true
```

`symbol_level=0` everywhere (no debug info) is the big build-time lever:
roughly a third of a default build's time is debug info generation.

Run chrome with `--no-sandbox` and `AFEYE_SINK=1` in the environment. Without
the env var the patched build is stock behavior. The sinks read
`AFEYE_RAW_DIR` (default `/tmp/afeye-raw`).

## honest limits

- v8 script-source records are head-capped at 1 MiB (flag `f:1`); blink spans
  cap at 64 KiB, net at 256 KiB. Full response bodies still come from the CDP
  capture side; the sink streams are structure + provenance.
- 0010's toDataURL hook records the call and mime, not the returned data URL
  (the function has many exits; the value is reconstructed from the net layer
  or CDP when it is exfiltrated).
- The per-bytecode interpreter trace from v2 is gone:
  `Runtime_TraceUnoptimizedBytecodeEntry` no longer exists in v8 13.x+.
- A hard SIGKILL can lose the last ring backlog of a process (bounded by the
  8 MiB ring and drain rate; `Flush(500)` via atexit covers graceful exits).

## verification

- every patch applies cumulatively to pristine 153.0.8010.52 (`git apply`,
  verified in CI setup and locally against a mock tree of the fetched files)
- the three sink translation units compile standalone with
  `g++ -std=c++17 -D{V8_AFEYE,BLINK_AFEYE,NET_AFEYE}`
- the built chrome announces itself: first record in every `.rec` file is the
  sink-hello; `collect/stats.json` records=0 with zero sink-hellos means the
  running chrome is not the patched build - the crawler prints
  `sink layer DEAD` and the manifest carries `sink_alive=false`
