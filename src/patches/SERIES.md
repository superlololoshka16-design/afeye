# afeye chromium patch series v2

13 numbered unified diffs. Patches 0001/0002/0013 are rebased BYTE-EXACT against the
pinned reference: **Chromium 133.0.6943.98, V8 79c3c1ab7faee8247b740b4ec660a998f2881633**
(build workflow default) - they `git apply` cleanly there, verified by roundtrip.
0003-0012 were written against the 128-133 line; apply with `git apply --3way` or
`patch -p1 --fuzz=3`, rebase hunks onto the anchor functions listed per patch.

**Build once, download forever**: `.github/workflows/afeye-build.yml` (workflow_dispatch)
builds the patched chrome through artifact-carrying stages and publishes it as the
repo release `chrome-build` (asset `afeye-chrome-linux64.tzst`). The crawl workflow
downloads it from there with an actions/cache keyed on the release timestamp - no
rebuild ever happens on the cron path; stock chrome is only a loud fallback
(sink_alive=false in the manifest).

## what changed in v2 (and why)

The v1 series looked deep but shipped dead code. The holes, confirmed by reading v121 line
by line and fixed here:
1. **the sinks never emitted anything.** `Enabled()` only became true from `StartDrain`,
   which only ran inside `Emit()`, which every hook guarded with `if (!Enabled()) return`.
   Chicken-and-egg: zero records, forever. v2 activates via the `AFEYE_SINK` env var
   (`std::call_once` inside `Enabled()` itself), so a patched build is stock chrome until
   the crawler flips one variable.
2. **the collector could never connect.** Sinks dialed `/tmp/afeye-*.sock` as clients and
   the Rust collector dialed the same sockets as a client too - nobody listened. v2 drops
   sockets entirely: every sink process appends length-prefixed records to
   `/tmp/afeye-raw/<layer>-<pid>.rec` (per-process file = no cross-process contention,
   O_APPEND single-writer = whole-record atomicity, survives collector crashes).
3. **the framing parser was byte-shifted.** v1 collector read `kind` at offset 0 (where
   the u32 length lives) and `len` at offset 4 (where kind lives). v2 parses the actual
   wire format and byte-verifies payloads (see tests/sink_roundtrip.rs).
4. **payloads were cut to 256 bytes of base64.** v2 writes full raw payloads to
   `collect/raw/*.bin` + a blake3-hashed index line per record; nothing trimmed but
   records that exceed the 1 MiB sink cap (flagged `f:1`).
5. **v8 timestamps were microseconds labeled as ns** (TimeTicks::ToInternalValue) while
   blink/net used ms - cross-layer diffs were impossible. v2: every layer stamps
   `clock_gettime(CLOCK_MONOTONIC)` ns - one clock, comparable across all processes.
6. **the ring was not multi-producer safe** and `Emit(len==0)` broadcast ~1 MiB of
   uninitialized stack. v2: spinlock-guarded ring, zero-length guard, resync-on-corrupt
   drain, `Flush(timeout_ms)` + `atexit` for clean tail drain.
7. **URLLoader::StartRequest computed the POST body and discarded it.** The one place the
   raw pre-TLS telemetry exists - thrown away. v2 emits method+url, the full wire headers
   (`request_.headers.ToString()`, which includes the client hints), every kBytes body
   element (256 KiB span cap) and the total body size. `OnReceiveResponse` adds the raw
   response header block. Content-layer hooks (client_hints.cc, SW fetch context) were
   dropped: everything they saw also crosses URLLoader, now captured there.
8. **0003 would not compile** (truncated CallRuntime, missing Goto) and nothing ever
   called `UpdateAfeyeTraceFlag`. v2 hooks the body of the existing
   `Runtime_TraceUnoptimizedBytecodeEntry` - the same runtime the interpreter invokes
   per bytecode under `--trace-ignition-exec`.
9. **0004 grow hook referenced an undefined variable**; instance-imports recorded an
   empty string. v2: grow emits (pages, delta) from the JS arguments; instance finalize
   walks `module_->import_table` / `export_table` and records (offset,length,kind)
   windows into the wire bytes already captured by kWasmModule - exact, no string API
   guessing.
10. **0007 captured crypto inputs only, no algorithm names, no getRandomValues.** v2 adds
    the algorithm to every tag and hooks `Crypto::getRandomValues` after the fill - the
    nonces anti-fraud schemes derive keystreams from.
11. **0008 only saw string messages** (`v->IsString()`) - every object payload invisible.
    v2 hooks the `SerializedScriptValue::Serialize` return: the structured-clone bytes of
    every postMessage/BroadcastChannel/worker/IndexedDB payload regardless of type, plus
    the unpacking ctor for the receive side.
12. **0009's enumerateDevices emitted `audio=HasPendingActivity()`** - literal noise. v2
    records the real MediaDeviceInfo identities in the ctor where the promise materializes
    them, and actually calls the previously-dead `AfeyeToDataURL` at the readback return.
13. **0010 timed nothing** - timer fires had start stamps only. v2: RAII scope in
    `DOMTimer::Fire()` emits (id, start_ns, end_ns) on every exit path.
14. **blink BUILD.gn declared `blink_enable_afeye` at the bottom of the file** (GN
    evaluates top-to-bottom - the target referencing it errored) and defined BLINK_AFEYE
    only on the platform target while the hooks live in modules/core. v2: declare_args at
    the top, `public_configs +=` so the define propagates to every blink target.

## apply

```
cd chromium/src
git am --3way /path/to/patches/0001-*.patch   (or: git apply --3way)
```

GN args for the patched build:

```
v8_enable_afeye = true
blink_enable_afeye = true
network_enable_afeye = true
is_debug = false
is_component_build = false
```

Run chrome with `--no-sandbox` (required: the sink file drain lives in renderer
processes, which otherwise sit in a private mount namespace where /tmp is unreachable)
and `AFEYE_SINK=1` in the environment. Without the env var the patched build is
byte-for-byte stock behavior. `AFEYE_V8_TRACE=1` additionally passes
`--js-flags=--afeye-trace` for per-bytecode capture sessions.

Runtime switches (V8):

- `--afeye-source` (default on): dump raw script sources before parse
- `--afeye-trace` (default off): mirror per-bytecode tuples; extreme volume, dedicated
  capture passes only

Collector: built into `afeye` itself (spun up before chrome, drained after every chrome
is dead, lands in `<stage>/collect/` inside the pushed zip). Standalone probing:
`AF_RAW_DIR=... AF_COLLECT_OUT=... ./target/release/afeye-collect`.

## wire format v2 (all three sinks)

Every sink appends records to `$AFEYE_RAW_DIR (default /tmp/afeye-raw)/<layer>-<pid>.rec`:

```
u32 total_le | u8 kind | u8 flags | u16 rsvd=0 | u64 ts_ns_le | payload[total - 16]
```

`total` counts the whole record including the 16-byte header. `flags` bit0 = truncated.
`ts_ns` is `CLOCK_MONOTONIC` nanoseconds - identical clock domain in every sink process,
so the v8/blink/net streams merge into one exact diff-able timeline. First record in
each file is kind 0 (`afeye-sink/<layer> v2 pid=...`): instant proof whether the C++
side is alive. Ring: 8 MiB, spinlock-guarded multi-producer, overflow drops + counts,
never blocks the engine; `Flush(ms)` drains at exit (atexit-registered, 500 ms).

Collector materializes per record: `collect/raw/<layer>-<kind>-<seq>.bin` (full
payload), `collect/index.jsonl` (ts / layer / kind / flags / len / blake3-16 / path /
4 KiB text preview), `collect/stats.json` (running counters). Torn-record tails
complete on the next scan; corruption resyncs by scanning for the next plausible
header (counted in `corrupt`).

## patches and anchors

| # | file | hook point | captures |
|---|------|-----------|----------|
| 0001 | v8 `src/afeye/sink.{h,cc}` + `BUILD.gn` + `src/flags/flag-definitions.h` | env-activated ring + file drain, GN arg `v8_enable_afeye`, runtime flags | shared plumbing for every V8 patch |
| 0002 | v8 `src/api/api.cc` | `ScriptCompiler::Compile`, `CompileModule`, `CompileFunctionInContext` entry | raw source text of every script: page, eval, new Function, workers, modules, with origin name |
| 0003 | v8 `src/runtime/runtime-test.cc` | body of `Runtime_TraceUnoptimizedBytecodeEntry` (fires per bytecode under `--trace-ignition-exec`) | (offset, opcode, length) tuple per executed bytecode; flag-gated |
| 0004 | v8 `src/wasm/wasm-engine.cc` + `wasm-js.cc` + `wasm-objects.{h,cc}` + `wasm-module-instantiate.cc` | `SyncCompile`/`AsyncCompile` entry; `WebAssemblyTableGet/Set`; `Memory.grow` from JS args; instance finalize over import/export tables | full wasm wire bytes, table traffic, grow (pages, delta), import/export (offset,len,kind) windows |
| 0005 | v8 `src/execution/microtask-queue.{h,cc}` + `src/objects/backing-store.{h,cc}` + `src/api/api.cc` | `EnqueueMicrotask` (all four overloads), `PerformCheckpointInternal` bounds, `SharedArrayBuffer::New` | enqueue records with context id, checkpoint (sizes before/after + duration), SAB geometry |
| 0006 | blink `platform/afeye/sink.{h,cc}` + `platform/BUILD.gn` | same ring design, layer "blink", GN arg `blink_enable_afeye` (declare_args first, public_configs propagation) | shared plumbing for blink patches 0007-0010, 0012 |
| 0007 | blink `modules/crypto/subtle_crypto.cc` + `modules/crypto/crypto.cc` + `crypto_key.cc` | `EncryptOrEncryptInternal`, `digest`, `sign`, `importKey`, `deriveBits`, `Crypto::getRandomValues` (after fill), `CryptoKey::CryptoKey` | plaintext + algorithm per call before BoringSSL, random material actually handed to the page, key geometry |
| 0008 | blink `modules/messaging/message-port.cc` + `modules/broadcastchannel/broadcast_channel.cc` + `bindings/core/v8/serialization/serialized_script_value.{h,cc}` | `postMessage` markers + the `Serialize` return and the unpacking ctor | full structured-clone bytes of every message both directions - objects included |
| 0009 | blink `modules/permissions/permissions.cc` + `modules/mediastream/media_devices.cc` + `modules/mediastream/media_device_info.cc` + `core/timing/performance.{h,cc}` + `core/html/canvas/html_canvas_element.{h,cc}` + `core/offscreencanvas/offscreencanvas.cc` | `Permissions::query`, `enumerateDevices` + `MediaDeviceInfo` ctor, `Performance::measure/mark`, `toDataURL` (tainted branch + readback), `OffscreenCanvas::Commit` | permission probing, real device identities, perf channel, canvas fingerprint values |
| 0010 | blink `core/dom/dom_timer.cc` + `core/timing/performance_observer.cc` + `performance_entry.cc` | `DOMTimer::DOMTimer` (install), RAII scope over `DOMTimer::Fire` (id, start, end), `PerformanceObserver::observe`, `PerformanceEntry` ctor | timer installs, fire durations, observer registrations, entry timings |
| 0011 | `services/network/public/cpp/afeye_sink.{h,cc}` + `public/cpp/BUILD.gn` + `services/network/url_loader.cc` + `web_socket.cc` | `URLLoader::StartRequest` (method, url, wire headers, every body element), `OnReceiveResponse` (raw response headers, mime, code), `OnComplete` (error, decoded size), `WebSocket::OnDataFrame` | the pre-TLS ground truth: what the anti-fraud actually sends and receives |
| 0012 | blink `modules/cache_storage/cache_storage.cc` | `CacheStorage::open`, `Cache::put`, `Cache::matchAll` | SW/CacheStorage synthetic-request layer: what the SW fabricates and caches |
| 0013 | v8 `src/codegen/compiler.cc` | `Compiler::GetFunctionFromEval` entry | **the eval/Function chokepoint**: every dynamic compilation (the decrypted payload a packer hands to the engine) - the api.cc hooks of 0002 never see eval |

## verification

`cargo test --release` compiles the sink code extracted from the .patch files themselves
(g++ -DV8_AFEYE / -DBLINK_AFEYE / -DNET_AFEYE), runs an emission battery (script
sources, wasm bytes, spans, a 2 MiB truncation case, an 8-thread x 500-record storm,
zero-length guard, env-off silence) and reads everything back through the production
collector asserting byte-exact payloads, per-thread record integrity, corrupt=0 and the
truncation flag. `tools/recount_patches.py` recomputes hunk headers so counts always
match bodies.

## analysis pipeline (what the traces feed)

The patches emit raw material; reduction happens offline on the jsonl streams:

1. taint analysis: seed taint at `kScriptSource` boundaries (env-derived constants:
   navigator getters, canvas readbacks from 0009, timing entries from 0010), propagate
   through `kBytecodeEntry` tuples - any operation consuming tainted operands marks its
   result.
2. dead-code elimination: bytecodes never feeding a `kCryptoOp`/`kNetReq` payload are
   cut, BUT side-effect records (kWasmTable writes, kAtomics, kSwCache puts) pin control
   dependencies the same way the page runtime would - this is why the series captures
   them.
3. crypto primitive recognition: constant tables and round structure show up in
   `kBytecodeEntry` opcode streams feeding `kCryptoOp` sinks; classify MD5/SHA/RC4/TEA/
   S-box patterns from the tuple stream around the sink. `getRandomValues` output makes
   XOR-stream ciphertexts directly decodable.
4. backward slicing: start from `kNetReq` `req-body` spans (the wire POST), walk the
   records in reverse on the shared CLOCK_MONOTONIC timeline; control-dependency pinning
   via 0004/0005/0010 events keeps branch-carried data from vanishing.
5. multi-run intersection: run the same URL twice, intersect invariant tuples, the delta
   is the session-bound core (mouse paths, timestamps) vs the static environment
   snapshot.

## honest limits

- 0003 per-bytecode tracing only covers Ignition (unoptimized tier). Tier-up to
  Sparkplug / TurboFan is recorded only at compile boundaries (0002) - for full coverage
  pin `--no-opt --no-sparkplug` in the DBA capture profile; that changes timing, so run
  it as a separate capture pass, not the default crawl profile.
- record payloads are head-capped (64 KiB spans blink / 256 KiB spans net, 1 MiB modules
  and script sources) - full response bodies still come from the CDP capture side of
  afeye; the sink traces are for structure, not bulk storage.
- a hard SIGKILL can lose the last ring backlog of a process (bounded by the 8 MiB ring
  and the drain rate; `Flush(500)` via atexit covers graceful exits). The collector's
  final scan happens after every chrome is dead, so normal runs lose nothing.
- context lines were written against a reference tree; treat anchors as the source of
  truth when rebasing. hunk counts are recomputed by tools/recount_patches.py.
