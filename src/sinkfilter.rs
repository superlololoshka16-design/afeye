//! afeye sink deep-filter (v6).
//!
//! Post-run pass over `collect/index.jsonl` + `collect/raw/*.bin` (what the
//! patched C++ sinks streamed). The collector (v6) materializes
//! high-frequency kinds as per-(layer,kind) PART files and references them
//! by (path, offset, len) - batching is storage packing, never filtering,
//! and this module unpacks by (p, o, len) so no byte is lost or decided
//! here.
//!
//!  1. script chains - all script-source fragments of one origin merge
//!     into ONE file. v6 script names carry the "iso:<isolate> " prefix
//!     (compiler.cc sink), so an eval-storm lands per-isolate: a
//!     dedicated worker's stream never mixes with the main thread even
//!     inside a shared renderer process. Worker records (kind 35) then
//!     NAME the isolate - the chain report says which worker it was.
//!  2. wasm modules - dumped as real `.wasm` plus an offline walk of the
//!     import/export sections. v6 wasm-instance records (kind 31) carry
//!     the imports AS RESOLVED at instantiation; the filter attaches
//!     them to the closest preceding module of the same pid.
//!  3. backward slicing (taint) - a chain is HOT when:
//!       - its code carries a collector/network sink call (v5), or
//!       - it materialized inside a handler/timer window (v5, time
//!         correlation, AF_SCRIPT_TRIGGER_MS), or
//!       - fingerprint DOM reads fired while its fragments materialized
//!         (v6: the idl_member_installer stream, kind 29 - "dom
//!         Navigator.get userAgent" and friends), or
//!       - Function.prototype.toString integrity checks fired in its
//!         window (v6: kind 32 - the antifraud self-check), or
//!  4. timing chains - for every network request: the closest preceding
//!     input/event/timer record (T0 -> T1 -> T2), the fingerprint reads
//!     and integrity checks in the 5 s before the send (what fed the
//!     payload), all in ms relative to nav-start (v6: kind 36 anchors
//!     the page timeline in the sink clock domain).
//!  5. dead-end classification (v7) - every chain is split into
//!     TOKEN-FORMING vs DEAD-END. A chain feeds the challenge token
//!     when any of these signals fires:
//!       - sink-call: its own code carries a collector/network sink call
//!         (fetch/XHR/beacon/WebSocket/canvas/audio/webrtc...), or
//!       - handler-born: it materialized right after an event/timer
//!         (compiled inside that handler - the v5 trigger window), or
//!       - fp-probes: >=2 distinct fingerprint reads while its fragments
//!         materialized (the eval-chunk-then-probe pattern), or
//!       - integrity-check: Function.prototype.toString self-checks fired
//!         in its window, or
//!       - net-window: it materialized inside a network request's
//!         payload-formation window (backward slice from the send).
//!     The filtered zip keeps ONLY token-forming chains ("what actually
//!     builds the token"); dead ends are dropped there but survive
//!     untouched in the raw run zip - no byte is lost, only sorted.
//!
//! Attribution honesty: the C++ dom-api thunk cannot know its JS caller
//! without a stack walk, so kind-29 reads are attributed BY TIME - to a
//! chain while its fragments materialize (the eval-chunk-then-probe
//! antifraud pattern), and to every network request in the preceding
//! 5 s window (payload formation). Both are recomputable from the raw
//! stream; the index keeps every ts.

use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;

#[derive(Default, Debug, Clone, Copy)]
pub struct SinkFilterStats {
    pub records: u64,
    pub fragments: u64,
    pub chains: u64,
    pub hot_chains: u64,
    pub cold_chains: u64,
    pub chain_bytes: u64,
    pub wasm_modules: u64,
    pub wasm_imports: u64,
    pub wasm_exports: u64,
    pub net_chains: u64,
    pub keep_cold: bool,
    // v6 taint counters
    pub fp_reads: u64,
    pub fp_chains: u64,
    pub integrity_checks: u64,
    pub integrity_chains: u64,
    pub wasm_instantiated: u64,
    // v7 dead-end classification
    pub token_chains: u64,
    pub dead_end_chains: u64,
    pub net_adjacent_chains: u64,
    pub content_sink_chains: u64,
}

/// sink calls that mark a chain as reaching the collector / the network
const HOT_PATTERNS: &[&str] = &[
    "fetch(",
    "XMLHttpRequest",
    "sendBeacon",
    "WebSocket",
    "toDataURL",
    "toBlob",
    "getImageData",
    "measureText",
    "OfflineAudioContext",
    "RTCPeerConnection",
    "createDataChannel",
    "getChannelData",
    "getRandomValues",
    "crypto.subtle",
    "importScripts",
    "postMessage",
    "Worker(",
    "ServiceWorker",
    "WebAssembly",
];

const TRIGGER_KINDS: &[&str] = &[
    "input",
    "event-dispatch",
    "timer",
    "dom-metric",
    "fingerprint",
    "crypto-op",
    "webrtc",
    "audio",
];

/// fingerprint-relevant dom-api reads. The kind-29 "what" strings look
/// like "dom Navigator.get userAgent" / "dom WebGLRenderingContext.call
/// getParameter" - matched by substring, on the interface.member level.
const FP_API_NEEDLES: &[&str] = &[
    // identity
    "Navigator.get userAgent",
    "Navigator.get appVersion",
    "Navigator.get platform",
    "Navigator.get vendor",
    "Navigator.get oscpu",
    "Navigator.get languages",
    "Navigator.get hardwareConcurrency",
    "Navigator.get deviceMemory",
    "Navigator.get plugins",
    "Navigator.get mimeTypes",
    "Navigator.get connection",
    "Navigator.get userAgent",
    // screen geometry
    "Screen.get width",
    "Screen.get height",
    "Screen.get colorDepth",
    "Screen.get pixelDepth",
    "Screen.get availLeft",
    "Screen.get availTop",
    "Screen.get availWidth",
    "Screen.get availHeight",
    // storage / cookies
    "Document.get cookie",
    // webgl
    "getParameter",
    "getExtension",
    "getShaderPrecisionFormat",
    // canvas
    "toDataURL",
    "toBlob",
    "getImageData",
    "measureText",
    // element geometry (font probing)
    "getBoundingClientRect",
    "getClientRects",
    // audio
    "getChannelData",
    // webrtc / devices
    "createOffer",
    "createDataChannel",
    "enumerateDevices",
    "getGamepads",
    "getBattery",
];

/// a kind-29 read matched against FP_API_NEEDLES
struct FpRead {
    ts: u64,
    needle: &'static str,
}

/// grace after a chain's last fragment within which a fingerprint read
/// still counts as "while it materialized" (eval-chunk -> immediate probe)
const FP_GRACE_NS: u64 = 50_000_000;
/// lookback before a network send that counts fingerprint activity as
/// payload formation for that request
const NET_FP_WINDOW_NS: u64 = 5_000_000_000;
/// lookback for a wasm-instantiate to still belong to a module
const WASM_INST_WINDOW_NS: u64 = 5_000_000_000;

// --- v8 content-based backward slice (the net-window fix) -----------------
// The v7 `net-window` signal is a FIXED 5 s timer before a send. That drops
// the fp-init phase: Cloudflare/DataDome/Kasada collect the base fingerprint
// in the first ~200 ms, stash it (IndexedDB via structured-clone, or a
// closure), and only encrypt+send it 10-30 s later on a focus/mousemove/
// captcha-decision event. A timer window throws that init chain into the
// dead-end bucket.
//
// Encryption destroys content (ciphertext != plaintext), but the PLAINTEXT
// records still match byte-for-byte across the gap: the IDB put payload
// (kind-15 structured-clone, "ssv") IS the same bytes the later
// SubtleCrypto.encrypt/sign raw_data (kind-11 crypto-op) carries, and the
// net req-body span (kind-17) is the upload that left. So we link payload
// records by CONTENT (blake3 over fixed windows), not by clock: any payload
// record sharing a content-run with a SINK record (payload-forming crypto
// or an upload body) is "sink-linked", no matter how far apart in time. A
// chain that materialized while a sink-linked payload was written feeds the
// token -> `content-sink` signal. This is the backward slice the fixed timer
// could not express.
/// content-run window: blake3 over this many bytes of a payload
const CONTENT_RUN_BYTES: usize = 32;
/// content-run stride (< window -> overlapping runs survive byte-offset
/// between the stored blob and the re-read plaintext)
const CONTENT_RUN_STEP: usize = 16;
/// hard cap on runs per record (bounded memory on big blobs)
const CONTENT_MAX_RUNS: usize = 8192;
/// grace around a sink-linked payload's timestamp within which a chain that
/// materialized counts as feeding it
const CONTENT_LINK_GRACE_NS: u64 = 200_000_000;
/// hard bound on payload records walked for the content slice (memory)
const CONTENT_MAX_RECORDS: usize = 50_000;
/// hard bound on distinct sink runs retained (32 B each -> ~128 MB ceiling)
const CONTENT_MAX_TOTAL_RUNS: usize = 4_000_000;
/// crypto-op tags whose raw_data is payload-forming for the outbound token
/// (decrypt is inbound; getRandomValues is a nonce source, not the payload)
const SINK_CRYPTO_OPS: &[&str] = &["encrypt", "sign", "deriveBits", "digest"];

#[derive(Debug)]
struct Rec {
    ts: u64,
    pid: u64,
    layer: String,
    kind: String,
    len: u64,
    h: String,
    path: String,
    /// v6: offset inside a batched part file ("o" in the index). None for
    /// per-record files.
    off: Option<u64>,
    txt: Option<String>,
}

/// payload of a record, offset-aware for batched kinds
fn read_payload(raw_dir: &Path, r: &Rec) -> Option<Vec<u8>> {
    let b = fs::read(raw_dir.join(&r.path)).ok()?;
    let start = r.off.unwrap_or(0) as usize;
    if start == 0 && b.len() == r.len as usize {
        return Some(b);
    }
    let end = start.checked_add(r.len as usize)?;
    Some(b.get(start..end)?.to_vec())
}

fn txt_head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn name_of(payload: &[u8]) -> (String, Vec<u8>) {
    match payload.iter().position(|&c| c == 0) {
        Some(i) => (
            String::from_utf8_lossy(&payload[..i]).to_string(),
            payload[i + 1..].to_vec(),
        ),
        None => (String::new(), payload.to_vec()),
    }
}

/// v6 script names are "iso:<isolate> <real name>" (compiler.cc sink).
fn split_iso(name: &str) -> (Option<String>, String) {
    if let Some(rest) = name.strip_prefix("iso:") {
        if let Some(sp) = rest.find(' ') {
            return (Some(rest[..sp].to_string()), rest[sp + 1..].to_string());
        }
    }
    (None, name.to_string())
}

/// kind-35 payload: "worker-scope iso=<ptr> name=<n> secure=<0|1>"
fn worker_of(txt: &str) -> Option<(String, String)> {
    let rest = txt.strip_prefix("worker-scope iso=")?;
    let sp = rest.find(' ')?;
    let iso = rest[..sp].to_string();
    let tail = &rest[sp + 1..];
    let name = tail.strip_prefix("name=").unwrap_or(tail);
    let name = name.split(" secure=").next().unwrap_or(name);
    Some((iso, name.to_string()))
}

fn is_hot(name: &str, body: &[u8]) -> bool {
    // compiled inside an antifraud handler/timer: provenance says so
    if name.starts_with("evt:") || name.starts_with("timer:") {
        return true;
    }
    let head = &body[..body.len().min(1 << 20)];
    let s = String::from_utf8_lossy(head);
    HOT_PATTERNS.iter().any(|p| s.contains(p))
}

/// v7 dead-end classification: does this chain's materialization window
/// overlap any network request's payload-formation window?
/// Chain window: [first_ts, last_ts + FP_GRACE_NS]; request window:
/// [t - NET_FP_WINDOW_NS, t]. Overlap = the classic interval overlap.
fn overlaps_net_window(net_ts: &[u64], first_ts: u64, last_ts: u64) -> bool {
    let lo = first_ts;
    let hi = last_ts
        .saturating_add(FP_GRACE_NS)
        .saturating_add(NET_FP_WINDOW_NS);
    // any net ts in [lo, hi]
    let a = net_ts.partition_point(|t| *t < lo);
    a < net_ts.len() && net_ts[a] <= hi
}

/// v8 content-sink: does this chain's materialization window overlap any
/// SINK-LINKED payload's timestamp? Unlike overlaps_net_window the link is
/// by CONTENT (a payload that shares bytes with a crypto/upload sink), so
/// the chain is credited no matter how long before the actual send it ran.
/// Chain window: [first_ts - grace, last_ts + FP_GRACE + grace].
fn overlaps_content_bridge(content_ts: &[u64], first_ts: u64, last_ts: u64) -> bool {
    let lo = first_ts.saturating_sub(CONTENT_LINK_GRACE_NS);
    let hi = last_ts
        .saturating_add(FP_GRACE_NS)
        .saturating_add(CONTENT_LINK_GRACE_NS);
    let a = content_ts.partition_point(|t| *t < lo);
    a < content_ts.len() && content_ts[a] <= hi
}

/// true when every byte is identical (zero runs, padding) - such runs collide
/// across unrelated records and would create false content links.
fn is_monotone(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(|&x| x == b[0])
}

/// blake3 content-runs of a payload body: fixed windows, overlapping stride,
/// monotone windows skipped. Two records sharing a run carry the same bytes
/// somewhere in their body - the data-dependency the backward slice follows.
fn content_runs(body: &[u8]) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    if body.len() < CONTENT_RUN_BYTES {
        if !is_monotone(body) && !body.is_empty() {
            out.push(*blake3::hash(body).as_bytes());
        }
        return out;
    }
    let mut off = 0usize;
    while off + CONTENT_RUN_BYTES <= body.len() && out.len() < CONTENT_MAX_RUNS {
        let win = &body[off..off + CONTENT_RUN_BYTES];
        if !is_monotone(win) {
            out.push(*blake3::hash(win).as_bytes());
        }
        off += CONTENT_RUN_STEP;
    }
    out
}

/// v7: the token-forming signals of a chain (why it is NOT a dead end).
/// Empty result = dead end: the code executed, but nothing it produced is
/// observable in any challenge-token-feeding position.
fn chain_signals(c: &Chain, net_ts: &[u64], content_ts: &[u64]) -> (Vec<String>, bool, bool) {
    let mut signals: Vec<String> = Vec::new();
    if c.hot_pattern {
        signals.push("sink-call".into());
    }
    if c.trigger.is_some() {
        signals.push("handler-born".into());
    }
    if c.fp_reads.len() >= 2 {
        signals.push("fp-probes".into());
    }
    if c.integrity > 0 {
        signals.push("integrity-check".into());
    }
    let net_adjacent = overlaps_net_window(net_ts, c.first_ts, c.last_ts);
    if net_adjacent {
        signals.push("net-window".into());
    }
    // v8: content-linked backward slice - the chain materialized while a
    // payload that shares bytes with a crypto/upload sink was written. Catches
    // the fp-init -> IDB/closure -> encrypt -> send-30s-later chain the fixed
    // net-window drops.
    let content_sink = overlaps_content_bridge(content_ts, c.first_ts, c.last_ts);
    if content_sink {
        signals.push("content-sink".into());
    }
    (signals, net_adjacent, content_sink)
}

// ---------------------------------------------------------------------------
// wasm section walk (offline, no execution)
// ---------------------------------------------------------------------------

struct WasmReader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> WasmReader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.p)?;
        self.p += 1;
        Some(v)
    }
    fn leb(&mut self) -> Option<u64> {
        let mut r: u64 = 0;
        let mut shift = 0;
        loop {
            let byte = self.u8()?;
            r |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Some(r);
            }
            shift += 7;
            if shift > 63 {
                return None;
            }
        }
    }
    fn bytes(&mut self, n: u64) -> Option<&'a [u8]> {
        let n = n as usize;
        let sl = self.b.get(self.p..self.p.checked_add(n)?)?;
        self.p += n;
        Some(sl)
    }
    fn name(&mut self) -> Option<String> {
        let n = self.leb()?;
        let sl = self.bytes(n)?;
        Some(String::from_utf8_lossy(sl).to_string())
    }
    /// limits: flags + min (+ max)
    fn limits(&mut self) -> Option<()> {
        let flags = self.u8()?;
        self.leb()?;
        if flags & 1 != 0 {
            self.leb()?;
        }
        Some(())
    }
}

fn wasm_imports_exports(b: &[u8]) -> (Vec<String>, Vec<String>) {
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    if b.len() < 8 || &b[0..4] != b"\0asm" {
        return (imports, exports);
    }
    let mut r = WasmReader { b, p: 8 };
    while r.p < b.len() {
        let _sec_id = match r.u8() {
            Some(v) => v,
            None => break,
        };
        let sec_len = match r.leb() {
            Some(v) => v,
            None => break,
        };
        let end = match r.p.checked_add(sec_len as usize) {
            Some(e) if e <= b.len() => e,
            _ => break,
        };
        let sec = &b[r.p..end];
        if _sec_id == 2 {
            // import section
            let mut s = WasmReader { b: sec, p: 0 };
            if let Some(count) = s.leb() {
                for _ in 0..count.min(4096) {
                    if s.p >= sec.len() {
                        break;
                    }
                    let _module = s.name().unwrap_or_default();
                    let field = match s.name() {
                        Some(f) => f,
                        None => break,
                    };
                    imports.push(field);
                    // skip the import description
                    let kind = match s.u8() {
                        Some(k) => k,
                        None => break,
                    };
                    match kind {
                        0 => {
                            let _ = s.leb();
                        }
                        1 => {
                            let _ = s.u8();
                            let _ = s.limits();
                        }
                        2 => {
                            let _ = s.limits();
                        }
                        3 => {
                            let _ = s.u8();
                            let _ = s.u8();
                        }
                        _ => {}
                    }
                }
            }
        } else if _sec_id == 7 {
            // export section
            let mut s = WasmReader { b: sec, p: 0 };
            if let Some(count) = s.leb() {
                for _ in 0..count.min(4096) {
                    if s.p >= sec.len() {
                        break;
                    }
                    match s.name() {
                        Some(f) => exports.push(f),
                        None => break,
                    }
                    let _kind = s.u8();
                    let _idx = s.leb();
                }
            }
        }
        r.p = end;
    }
    (imports, exports)
}

// ---------------------------------------------------------------------------
// main pass
// ---------------------------------------------------------------------------

struct Chain {
    file: Option<std::fs::File>,
    /// raw chain name (with the "iso:<ptr> " prefix when present)
    name: String,
    frags: u64,
    bytes: u64,
    hot: bool,
    /// v7: is_hot() matched the chain's own code (sink-call signal)
    hot_pattern: bool,
    first_ts: u64,
    last_ts: u64,
    path: String,
    // v5: what was running when this chain first materialized - the closest
    // preceding event/timer/crypto/... record inside the trigger window.
    trigger: Option<TriggerRef>,
    // v6 taint columns
    iso: Option<String>,
    worker: Option<String>,
    fp_reads: Vec<String>,
    integrity: u64,
    integrity_samples: Vec<String>,
    clock_reads: u64,
    // v7 dead-end classification
    token_forming: bool,
    signals: Vec<String>,
    net_adjacent: bool,
    content_sink: bool,
}

#[derive(Debug, Clone)]
struct TriggerRef {
    kind: String,
    ts: u64,
    what: String,
}

/// The latest trigger record at or before `ts`, within `window_ns`.
/// recs must be ts-sorted (they are - `recs.sort_by_key` runs before).
fn latest_trigger_before(recs: &[Rec], ts: u64, window_ns: u64) -> Option<TriggerRef> {
    // rightmost index with rec.ts <= ts (binary search - this runs per chain)
    let hi = recs.partition_point(|r| r.ts <= ts);
    let floor = ts.saturating_sub(window_ns);
    let mut walked = 0usize;
    let mut i = hi;
    while i > 0 {
        let r = &recs[i - 1];
        if r.ts < floor {
            break;
        }
        walked += 1;
        if walked > 4096 {
            break; // dense noise (mousemove storm) - bounded walk
        }
        if TRIGGER_KINDS.contains(&r.kind.as_str()) {
            return Some(TriggerRef {
                kind: r.kind.clone(),
                ts: r.ts,
                what: r.txt.as_deref().map(|s| txt_head(s, 120)).unwrap_or_default(),
            });
        }
        i -= 1;
    }
    None
}

/// first FP_API_NEEDLES substring the kind-29 "what" carries, if any
fn fp_needle_of(txt: &str) -> Option<&'static str> {
    FP_API_NEEDLES.iter().copied().find(|n| txt.contains(n))
}

/// v8: one kind-23 input record -> (event type, optional widget coords).
/// Formats (0009): "input/mouse <type> x=.. y=.. sx=.. sy=.. btn=.. clicks=..
/// mods=.." and "input/key type=.. vk=.. code=.. key=.. mods=..". Coord parse
/// is lossy-tolerant: any unparseable value yields None, never a wrong point.
fn parse_input_rec(txt: &str) -> Option<(&str, Option<(f64, f64)>)> {
    if let Some(rest) = txt.strip_prefix("input/mouse ") {
        let etype = rest.split(' ').next().unwrap_or("?");
        let mut x = None;
        let mut y = None;
        for tok in rest.split(' ') {
            if let Some(v) = tok.strip_prefix("x=") {
                x = v.parse::<f64>().ok();
            } else if let Some(v) = tok.strip_prefix("y=") {
                y = v.parse::<f64>().ok();
            }
        }
        Some((etype, match (x, y) {
            (Some(x), Some(y)) => Some((x, y)),
            _ => None,
        }))
    } else if txt.starts_with("input/key ") {
        Some(("key", None))
    } else {
        None
    }
}

fn median_of(mut v: Vec<u64>) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    Some(v[v.len() / 2])
}

/// v8: the mouse/keyboard cadence summary - "how often input went, where,
/// and when". Built from the kind-23 stream (0009, at the source, before any
/// DOM decision), so it reflects what the OS pipeline delivered, not what JS
/// happened to log.
struct InputCadence {
    total: u64,
    per_type: BTreeMap<String, u64>,
    median_delta_us: Option<u64>,
    p90_delta_us: Option<u64>,
    path_px: u64,
    span_ms: u64,
    /// ts-sorted (ts, type, Option<(x,y)>) for per-request correlation
    events: Vec<(u64, &'static str, Option<(f64, f64)>)>,
}

fn build_input_cadence(recs: &[Rec]) -> InputCadence {
    let mut per_type: BTreeMap<String, u64> = BTreeMap::new();
    let mut deltas: Vec<u64> = Vec::new();
    let mut path_px = 0.0f64;
    let mut prev_xy: Option<(f64, f64)> = None;
    let mut prev_ts = 0u64;
    let mut first_ts = 0u64;
    let mut last_ts = 0u64;
    let mut events: Vec<(u64, &'static str, Option<(f64, f64)>)> = Vec::new();
    let mut total = 0u64;
    for r in recs {
        if r.kind != "input" {
            continue;
        }
        let txt = r.txt.as_deref().unwrap_or("");
        let (etype, xy) = match parse_input_rec(txt) {
            Some(v) => v,
            None => continue,
        };
        total += 1;
        *per_type.entry(etype.to_string()).or_insert(0) += 1;
        if first_ts == 0 {
            first_ts = r.ts;
        }
        if prev_ts != 0 && r.ts > prev_ts {
            deltas.push((r.ts - prev_ts) / 1000); // us
        }
        prev_ts = r.ts;
        last_ts = r.ts;
        if let Some((x, y)) = xy {
            if let Some((px, py)) = prev_xy {
                path_px += ((x - px) * (x - px) + (y - py) * (y - py)).sqrt();
            }
            prev_xy = Some((x, y));
        }
        // static etype keys: the two formats are closed ("input/mouse X"
        // types are browser-fixed; anything else falls to "other")
        let key: &'static str = match etype {
            "mousemove" => "mousemove",
            "mousedown" => "mousedown",
            "mouseup" => "mouseup",
            "click" => "click",
            "wheel" => "wheel",
            "key" => "key",
            _ => "other",
        };
        events.push((r.ts, key, xy));
    }
    let n = deltas.len();
    let p90 = if n > 0 {
        let mut d = deltas.clone();
        d.sort_unstable();
        Some(d[((n as f64) * 0.9) as usize])
    } else {
        None
    };
    InputCadence {
        total,
        per_type,
        median_delta_us: median_of(deltas),
        p90_delta_us: p90,
        path_px: path_px as u64,
        span_ms: if first_ts != 0 && last_ts >= first_ts {
            (last_ts - first_ts) / 1_000_000
        } else {
            0
        },
        events,
    }
}

pub fn run(collect_dir: &Path) -> Result<SinkFilterStats, String> {
    let index_p = collect_dir.join("index.jsonl");
    let raw_dir = collect_dir.join("raw");
    let mut stats = SinkFilterStats {
        keep_cold: std::env::var("AF_SINK_KEEP_COLD").map(|v| v == "1").unwrap_or(false),
        ..Default::default()
    };
    let index = match fs::read_to_string(&index_p) {
        Ok(s) => s,
        Err(_) => return Ok(stats), // no sink stream at all (stock chrome)
    };

    let mut recs: Vec<Rec> = Vec::new();
    for line in index.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        stats.records += 1;
        let kind = v.get("k").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if kind == "sink-hello" {
            continue;
        }
        recs.push(Rec {
            ts: v.get("ts").and_then(|x| x.as_u64()).unwrap_or(0),
            pid: v.get("pid").and_then(|x| x.as_u64()).unwrap_or(0),
            layer: v.get("l").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            kind,
            len: v.get("len").and_then(|x| x.as_u64()).unwrap_or(0),
            h: v.get("h").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            path: v.get("p").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            off: v.get("o").and_then(|x| x.as_u64()),
            txt: v.get("txt").and_then(|x| x.as_str()).map(|s| s.to_string()),
        });
    }

    let filt = collect_dir.join("filtered");
    let scripts_dir = filt.join("scripts");
    let wasm_dir = filt.join("wasm");
    let _ = fs::create_dir_all(&scripts_dir);
    let _ = fs::create_dir_all(&wasm_dir);

    recs.sort_by_key(|r| r.ts);

    // ---- v6 pre-scans (sorted by ts, binary-searched later) ---------------
    // fingerprint reads, integrity checks, clock cadence, worker names
    let mut fp_reads: Vec<FpRead> = Vec::new();
    let mut fnts: Vec<(u64, String)> = Vec::new();
    let mut clock_ts: Vec<u64> = Vec::new();
    let mut workers: Vec<(u64, String, String)> = Vec::new(); // (ts, iso, name)
    let mut wasm_inst: Vec<(u64, u64, bool, String)> = Vec::new(); // (ts, pid, is_imports_header, txt)
    let mut nav_start: Option<u64> = None;
    for r in &recs {
        let txt = r.txt.as_deref().unwrap_or("");
        match r.kind.as_str() {
            "dom-api" => {
                if let Some(n) = fp_needle_of(txt) {
                    fp_reads.push(FpRead { ts: r.ts, needle: n });
                }
            }
            "fn-tostring" => {
                if txt.starts_with("fnts") {
                    fnts.push((r.ts, txt.to_string()));
                }
            }
            "clock" => clock_ts.push(r.ts),
            "worker" => {
                if let Some((iso, name)) = worker_of(txt) {
                    workers.push((r.ts, iso, name));
                }
            }
            "wasm-instance" => {
                let header = txt.starts_with("wasm-instantiate");
                wasm_inst.push((r.ts, r.pid, header, txt.to_string()));
            }
            "nav-start" => {
                if nav_start.map(|t| r.ts < t).unwrap_or(true) {
                    nav_start = Some(r.ts);
                }
            }
            _ => {}
        }
    }
    stats.fp_reads = fp_reads.len() as u64;
    stats.integrity_checks = fnts.len() as u64;

    // ---- 1+2+3: chains + wasm + taint ------------------------------------
    let mut chains: HashMap<(u64, String, String), usize> = HashMap::new();
    let mut chain_list: Vec<Chain> = Vec::new();
    let mut wasm_index: Vec<serde_json::Value> = Vec::new();
    let mut wasm_seen: HashMap<String, ()> = HashMap::new();

    for r in &recs {
        // payloads are read ONLY for the kinds that need the full bytes
        // (script-source and wasm-module are never batched; the batched
        // kinds are consumed through their index txt previews above)
        if r.kind == "script-source" {
            let payload = match read_payload(&raw_dir, r) {
                Some(p) => p,
                None => continue,
            };
            let (name, body) = name_of(&payload);
            if body.is_empty() {
                continue;
            }
            stats.fragments += 1;
            let key = (r.pid, r.layer.clone(), name.clone());
            let idx = match chains.get(&key) {
                Some(i) => *i,
                None => {
                    let idx = chain_list.len();
                    let fname = format!(
                        "{}-{}-{}-{}.js",
                        r.layer,
                        r.pid,
                        if name.is_empty() { "anon" } else { "chain" },
                        &r.h[..8.min(r.h.len())]
                    );
                    let fpath = scripts_dir.join(sanitize(&fname));
                    let file = fs::File::create(&fpath).ok();
                    let (iso, display) = split_iso(&name);
                    // join the worker name for this isolate (latest worker
                    // record at or before this fragment)
                    let worker = worker_name_for(&workers, r.ts, &iso);
                    let c = Chain {
                        file,
                        name: display,
                        frags: 0,
                        bytes: 0,
                        hot: false,
                        hot_pattern: false,
                        first_ts: r.ts,
                        last_ts: r.ts,
                        path: format!("filtered/scripts/{}", fname),
                        trigger: None,
                        iso,
                        worker,
                        fp_reads: Vec::new(),
                        integrity: 0,
                        integrity_samples: Vec::new(),
                        clock_reads: 0,
                        token_forming: false,
                        signals: Vec::new(),
                        net_adjacent: false,
                        content_sink: false,
                    };
                    chain_list.push(c);
                    chains.insert(key, idx);
                    idx
                }
            };
            let c = &mut chain_list[idx];
            if let Some(f) = c.file.as_mut() {
                if c.frags == 0 {
                    let _ = writeln!(
                        f,
                        "/* afeye chain layer={} pid={} name={} */",
                        r.layer,
                        r.pid,
                        printable(&c.name, 160)
                    );
                }
                let _ = writeln!(
                    f,
                    "/* ==== ts={} len={} h={} ==== */",
                    r.ts, r.len, r.h
                );
                let _ = f.write_all(&body);
                let _ = f.write_all(b"\n");
            }
            c.frags += 1;
            c.bytes += body.len() as u64;
            c.last_ts = r.ts;
            if is_hot(&name, &body) {
                c.hot = true;
                c.hot_pattern = true;
            }
        } else if r.kind == "wasm-module" {
            if wasm_seen.contains_key(&r.h) {
                continue;
            }
            wasm_seen.insert(r.h.clone(), ());
            let payload = match read_payload(&raw_dir, r) {
                Some(p) => p,
                None => continue,
            };
            let wp = wasm_dir.join(format!("{}.wasm", &r.h[..16.min(r.h.len())]));
            if fs::write(&wp, &payload).is_ok() {
                let (im, ex) = wasm_imports_exports(&payload);
                stats.wasm_modules += 1;
                stats.wasm_imports += im.len() as u64;
                stats.wasm_exports += ex.len() as u64;
                // v6: attach the imports AS RESOLVED at instantiation -
                // the closest following wasm-instantiate of the same pid
                let mut entry = json!({
                    "hash": r.h,
                    "bytes": payload.len(),
                    "ts": r.ts,
                    "pid": r.pid,
                    "imports": im.iter().take(256).cloned().collect::<Vec<_>>(),
                    "exports": ex.iter().take(256).cloned().collect::<Vec<_>>(),
                });
                let hdr = wasm_inst
                    .iter()
                    .find(|(ts, pid, header, _)| *header && *pid == r.pid && *ts >= r.ts && *ts <= r.ts + WASM_INST_WINDOW_NS);
                if let Some((hts, _, _, txt)) = hdr {
                    let n = txt
                        .split("imports=")
                        .nth(1)
                        .and_then(|s| s.trim().parse::<u64>().ok())
                        .unwrap_or(0);
                    entry["instantiated"] = json!(true);
                    entry["instantiated_imports"] = json!(n);
                    // resolved import names: the wasm-import records after
                    // that header, same pid, until the next header
                    let mut resolved: Vec<String> = Vec::new();
                    for (ts, pid, header, txt) in wasm_inst.iter() {
                        if *pid != r.pid || *ts <= *hts || *ts > *hts + WASM_INST_WINDOW_NS {
                            continue;
                        }
                        if *header {
                            break; // next instantiate took over
                        }
                        if let Some(name) = txt.strip_prefix("wasm-import ") {
                            let name = name.split(" kind=").next().unwrap_or(name);
                            if !resolved.contains(&name.to_string()) {
                                resolved.push(name.to_string());
                            }
                            if resolved.len() >= 256 {
                                break;
                            }
                        }
                    }
                    entry["resolved_imports"] = json!(resolved);
                    stats.wasm_instantiated += 1;
                }
                wasm_index.push(entry);
            }
        }
    }

    // drop cold chains from disk (they stay counted in the report)
    //
    // v5 trigger correlation: a chain whose FIRST fragment materialized
    // right after an event/timer/... record was compiled inside that
    // handler/timer - the exact information the v4 ambient tag carried at
    // the (now removed) blink hand-off, reconstructed here externally.
    let trigger_window_ns: u64 = {
        let ms: u64 = std::env::var("AF_SCRIPT_TRIGGER_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(250);
        ms.saturating_mul(1_000_000)
    };
    for c in &mut chain_list {
        if let Some(t) = latest_trigger_before(&recs, c.first_ts, trigger_window_ns) {
            c.hot = true;
            c.trigger = Some(t);
        }
    }

    // v6 taint columns: fingerprint reads / integrity checks / clock
    // cadence INSIDE each chain's materialization window
    for c in &mut chain_list {
        let lo = c.first_ts;
        let hi = c.last_ts.saturating_add(FP_GRACE_NS);
        let mut seen: Vec<&'static str> = Vec::new();
        let a = fp_reads.partition_point(|x| x.ts < lo);
        let b = fp_reads.partition_point(|x| x.ts <= hi);
        for fr in &fp_reads[a..b] {
            if !seen.contains(&fr.needle) {
                seen.push(fr.needle);
            }
        }
        if !seen.is_empty() {
            c.fp_reads = seen.iter().map(|s| s.to_string()).take(32).collect();
            if c.fp_reads.len() >= 2 {
                // two or more distinct fingerprint probes while this
                // chain's fragments materialized - the antifraud pattern
                c.hot = true;
                stats.fp_chains += 1;
            }
        }
        let fa = fnts.partition_point(|x| x.0 < lo);
        let fb = fnts.partition_point(|x| x.0 <= hi);
        c.integrity = (fb - fa) as u64;
        if c.integrity > 0 {
            stats.integrity_chains += 1;
            c.integrity_samples = fnts[fa..fb.min(fa + 8)]
                .iter()
                .map(|(_, t)| txt_head(t, 120))
                .collect();
        }
        let ca = clock_ts.partition_point(|x| *x < lo);
        let cb = clock_ts.partition_point(|x| *x <= hi);
        c.clock_reads = (cb - ca) as u64;
    }

    // ---- v7 dead-end classification ----------------------------------------
    // net-request timestamps (ts-sorted like recs) for the backward slice
    let net_ts: Vec<u64> = recs
        .iter()
        .filter(|r| r.kind == "net-request")
        .map(|r| r.ts)
        .collect();

    // ---- v8 content-based backward slice -----------------------------------
    // Build the set of content-runs that belong to SINK records (payload-forming
    // crypto: encrypt/sign/deriveBits/digest raw_data, and upload bodies), then
    // credit every payload record that shares a run with that set. A chain that
    // materialized while a credited payload was written feeds the token even
    // when the actual send is 10-30 s later - the case the fixed net-window
    // drops. Payload kinds read here (per-record .bin, never batched):
    //   crypto-op (kind 11)      - "encrypt"/"sign"/... + NUL + raw_data
    //   structured-clone (kind 15)- "ssv" + NUL + IDB/postMessage payload
    //   net-request (kind 17)     - "req-body" + NUL + upload bytes
    let payload_kinds = ["crypto-op", "structured-clone", "net-request"];
    let mut sink_runs: HashSet<[u8; 32]> = HashSet::new();
    let mut carriers: Vec<(u64, Vec<[u8; 32]>)> = Vec::new();
    let mut payload_records = 0usize;
    let mut total_runs = 0usize;
    let mut sink_full = false;
    for r in &recs {
        if !payload_kinds.contains(&r.kind.as_str()) {
            continue;
        }
        if payload_records >= CONTENT_MAX_RECORDS {
            break;
        }
        let payload = match read_payload(raw_dir, r) {
            Some(p) => p,
            None => continue,
        };
        let (tag, body) = name_of(&payload);
        if body.is_empty() {
            continue;
        }
        payload_records += 1;
        let is_crypto_sink =
            r.kind == "crypto-op" && SINK_CRYPTO_OPS.iter().any(|o| tag.contains(o));
        let is_upload = r.kind == "net-request" && tag == "req-body";
        // runs are retained for the carrier pass ONLY while the global
        // budget lasts - past CONTENT_MAX_TOTAL_RUNS total retained runs
        // later records contribute nothing (empty vec), keeping memory
        // bounded at ~128 MB regardless of blob sizes.
        let mut runs = Vec::new();
        if total_runs < CONTENT_MAX_TOTAL_RUNS {
            runs = content_runs(&body);
            if runs.len() > CONTENT_MAX_TOTAL_RUNS - total_runs {
                runs.truncate(CONTENT_MAX_TOTAL_RUNS - total_runs);
            }
            total_runs += runs.len();
        }
        if (is_crypto_sink || is_upload) && !sink_full {
            for h in &runs {
                if sink_runs.len() >= CONTENT_MAX_TOTAL_RUNS {
                    sink_full = true;
                    break;
                }
                sink_runs.insert(*h);
            }
        }
        carriers.push((r.ts, runs));
    }
    // carriers sharing >=1 run with the sink set are "sink-linked": their
    // timestamp marks a position where token-feeding bytes were handled.
    let mut content_ts: Vec<u64> = Vec::new();
    for (ts, runs) in &carriers {
        if runs.iter().any(|h| sink_runs.contains(h)) {
            content_ts.push(*ts);
        }
    }
    content_ts.sort_unstable();
    content_ts.dedup();

    for c in &mut chain_list {
        let (signals, net_adjacent, content_sink) = chain_signals(c, &net_ts, &content_ts);
        if net_adjacent {
            stats.net_adjacent_chains += 1;
        }
        if content_sink {
            stats.content_sink_chains += 1;
        }
        if !signals.is_empty() {
            c.token_forming = true;
            stats.token_chains += 1;
        } else {
            stats.dead_end_chains += 1;
        }
        c.signals = signals;
        c.net_adjacent = net_adjacent;
        c.content_sink = content_sink;
    }

    let mut hot = 0usize;
    let mut cold = 0usize;
    let mut chain_report = Vec::new();
    let big_keep = 96 * 1024usize;
    // v7 keep rule (the RUN zip - "almost untouched, as now"):
    //   hot (v6 rule: sink-call/trigger/fp) OR token-forming (v7 signals)
    //   OR keep_cold OR AF_KEEP_BIG=1 + big. The raw .bin payloads are
    //   pruned after this pass, so the kept chain files are the only copy
    //   of the executed code - the run zip must stay at least as complete
    //   as v6 (no downgrade).
    // The FILTERED zip (main.rs) is cut down further, to token-forming
    // chains ONLY, on its own copy of this directory (report.json carries
    // the token_forming flag per chain).
    let keep_big = std::env::var("AF_KEEP_BIG").map(|v| v == "1").unwrap_or(false);
    for c in &mut chain_list {
        let keep = c.hot || c.token_forming || stats.keep_cold || (keep_big && c.bytes as usize >= big_keep);
        if keep {
            hot += 1;
            if let Some(f) = c.file.as_mut() {
                let _ = f.sync_all();
            }
        } else {
            cold += 1;
            let rel = c.path.strip_prefix("filtered/").map(|x| x.to_string());
            if let Some(rel) = rel {
                let _ = fs::remove_file(collect_dir.join(&rel));
            }
            c.path = String::new();
        }
        stats.chain_bytes += c.bytes;
    }
    stats.chains = chain_list.len() as u64;
    stats.hot_chains = hot as u64;
    stats.cold_chains = cold as u64;

    for c in chain_list.iter().filter(|c| !c.path.is_empty()).take(4000) {
        let mut entry = json!({
            "name": printable(&c.name, 200),
            "frags": c.frags,
            "bytes": c.bytes,
            "hot": c.hot,
            "token_forming": c.token_forming,
            "ts0": c.first_ts,
            "ts1": c.last_ts,
            "path": c.path,
        });
        if !c.signals.is_empty() {
            entry["signals"] = json!(c.signals);
        }
        if c.content_sink {
            entry["content_sink"] = json!(true);
        }
        if let Some(t) = &c.trigger {
            entry["trigger"] = json!({
                "kind": t.kind,
                "ts": t.ts,
                "delta_ms": (c.first_ts - t.ts) / 1_000_000,
                "what": t.what,
            });
        }
        if let Some(iso) = &c.iso {
            entry["isolate"] = json!(iso);
        }
        if let Some(w) = &c.worker {
            entry["worker"] = json!(w);
        }
        if !c.fp_reads.is_empty() {
            entry["fp_reads"] = json!(c.fp_reads);
        }
        if c.integrity > 0 {
            entry["integrity_checks"] = json!(c.integrity);
            entry["integrity_samples"] = json!(c.integrity_samples);
        }
        if c.clock_reads > 0 {
            entry["clock_reads"] = json!(c.clock_reads);
        }
        if let Some(t0) = nav_start {
            if c.first_ts >= t0 {
                entry["ts0_rel_ms"] = json!((c.first_ts - t0) / 1_000_000);
                entry["ts1_rel_ms"] = json!((c.last_ts - t0) / 1_000_000);
            }
        }
        chain_report.push(entry);
    }

    // ---- v8 input cadence: how often the mouse went, where, when -----------
    let cadence = build_input_cadence(&recs);

    // ---- 4: timing chains: trigger -> network ------------------------------
    // recs are ts-sorted; a moving cursor finds, for every network request,
    // the latest trigger (input/event/timer/dom/fingerprint) before it, and
    // the v6 taint columns for the payload-formation window before the send.
    let mut net_chains: Vec<serde_json::Value> = Vec::new();
    let mut cursor = 0usize;
    let mut best: Option<usize> = None;
    for r in recs.iter().filter(|r| r.kind == "net-request") {
        while cursor < recs.len() && recs[cursor].ts <= r.ts {
            if TRIGGER_KINDS.contains(&recs[cursor].kind.as_str()) {
                best = Some(cursor);
            }
            cursor += 1;
        }
        let mut entry = match best.map(|i| &recs[i]) {
            Some(t) if r.ts.saturating_sub(t.ts) <= 250_000_000 => json!({
                "t_net": r.ts,
                "url": r.txt.as_deref().map(|s| txt_head(s, 160)).unwrap_or_default(),
                "trigger": {
                    "kind": t.kind,
                    "ts": t.ts,
                    "delta_ms": (r.ts - t.ts) / 1_000_000,
                    "what": t.txt.as_deref().map(|s| txt_head(s, 120)).unwrap_or_default(),
                },
            }),
            _ => json!({
                "t_net": r.ts,
                "url": r.txt.as_deref().map(|s| txt_head(s, 160)).unwrap_or_default(),
                "trigger": serde_json::Value::Null,
            }),
        };
        // v6: what fed this request - fingerprint reads, integrity checks
        // and clock cadence in the NET_FP_WINDOW_NS before the send
        let lo = r.ts.saturating_sub(NET_FP_WINDOW_NS);
        let a = fp_reads.partition_point(|x| x.ts < lo);
        let b = fp_reads.partition_point(|x| x.ts <= r.ts);
        if b > a {
            let mut seen: Vec<&'static str> = Vec::new();
            for fr in &fp_reads[a..b] {
                if !seen.contains(&fr.needle) {
                    seen.push(fr.needle);
                }
            }
            entry["fp_reads_5s"] = json!(seen.iter().map(|s| s.to_string()).take(64).collect::<Vec<_>>());
        }
        let fa = fnts.partition_point(|x| x.0 < lo);
        let fb = fnts.partition_point(|x| x.0 <= r.ts);
        if fb > fa {
            entry["integrity_5s"] = json!((fb - fa) as u64);
        }
        let ca = clock_ts.partition_point(|x| *x < lo);
        let cb = clock_ts.partition_point(|x| *x <= r.ts);
        if cb > ca {
            entry["clock_5s"] = json!((cb - ca) as u64);
        }
        // v8: the human-input fact feeding THIS send - how many mouse/key
        // events landed in the 5 s window before it, how many were moves,
        // and the median inter-event gap. A send with zero input behind it
        // is a bot-shaped cadence; a dense mousemove storm is a bot-shaped
        // the other way. Both readable here without the raw stream.
        let ia = cadence.events.partition_point(|e| e.0 < lo);
        let ib = cadence.events.partition_point(|e| e.0 <= r.ts);
        if ib > ia {
            let slice = &cadence.events[ia..ib];
            let mut deltas: Vec<u64> = Vec::new();
            for w in slice.windows(2) {
                if w[1].0 > w[0].0 {
                    deltas.push((w[1].0 - w[0].0) / 1000);
                }
            }
            entry["input_5s"] = json!({
                "n": slice.len(),
                "moves": slice.iter().filter(|e| e.1 == "mousemove").count(),
                "keys": slice.iter().filter(|e| e.1 == "key").count(),
                "median_delta_us": median_of(deltas),
            });
        }
        if let Some(t0) = nav_start {
            if r.ts >= t0 {
                entry["t_net_rel_ms"] = json!((r.ts - t0) / 1_000_000);
            }
        }
        if net_chains.len() < 4000 {
            net_chains.push(entry);
        }
    }
    stats.net_chains = net_chains.len() as u64;

    // ---- report -------------------------------------------------------------
    let mut per_kind: BTreeMap<String, u64> = BTreeMap::new();
    for r in &recs {
        *per_kind.entry(format!("{}/{}", r.layer, r.kind)).or_insert(0) += 1;
    }
    let report = json!({
        "records": stats.records,
        "records_indexed": recs.len(),
        "nav_start_ts": nav_start,
        "per_kind": per_kind,
        "scripts": {
            "fragments": stats.fragments,
            "chains": stats.chains,
            "hot": stats.hot_chains,
            "cold_dropped": stats.cold_chains,
            "keep_cold": stats.keep_cold,
            "chain_bytes": stats.chain_bytes,
        },
        "dead_end": {
            "token_forming": stats.token_chains,
            "dead_end": stats.dead_end_chains,
            "net_adjacent": stats.net_adjacent_chains,
            "content_sink": stats.content_sink_chains,
            "rule": "token-forming = sink-call | handler-born | fp-probes>=2 | integrity-check | net-window | content-sink; content-sink is the v8 data-dependency backward slice (payload records sharing content-runs with a crypto/upload sink, no timer) - dead ends stay whole in the raw run zip",
        },
        "taint": {
            "fp_reads": stats.fp_reads,
            "fp_chains": stats.fp_chains,
            "integrity_checks": stats.integrity_checks,
            "integrity_chains": stats.integrity_chains,
            "clock_reads": clock_ts.len(),
        },
        "input_cadence": {
            "total": cadence.total,
            "per_type": cadence.per_type,
            "median_delta_us": cadence.median_delta_us,
            "p90_delta_us": cadence.p90_delta_us,
            "path_px": cadence.path_px,
            "span_ms": cadence.span_ms,
        },
        "wasm": {
            "modules": stats.wasm_modules,
            "instantiated": stats.wasm_instantiated,
            "imports": stats.wasm_imports,
            "exports": stats.wasm_exports,
            "index": wasm_index,
        },
        "chains": chain_report,
        "net_chains": net_chains,
    });
    let _ = fs::write(
        filt.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap_or_default(),
    );

    Ok(stats)
}

/// latest worker record at or before `ts` with this isolate pointer
fn worker_name_for(workers: &[(u64, String, String)], ts: u64, iso: &Option<String>) -> Option<String> {
    let iso = iso.as_ref()?;
    let mut name: Option<&(u64, String, String)> = None;
    for w in workers {
        if w.0 <= ts && &w.1 == iso {
            match name {
                Some(n) if n.0 >= w.0 => {}
                _ => name = Some(w),
            }
        }
    }
    name.map(|w| w.2.clone())
}

fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => c,
            _ => '_',
        });
        if out.len() > 120 {
            break;
        }
    }
    out
}

fn printable(s: &str, n: usize) -> String {
    s.chars()
        .map(|c| if (0x20..0x7f).contains(&(c as u32)) { c } else { '?' })
        .take(n)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_import_export_walk() {
        // (module (import "e" "f" (func)) (export "g" (func 0)))
        let b = vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x02, 0x07, 0x01, 0x01,
            b'e', 0x01, b'f', 0x00, 0x00, 0x07, 0x05, 0x01, 0x01, b'g', 0x00, 0x00,
        ];
        let (im, ex) = wasm_imports_exports(&b);
        assert_eq!(im, vec!["f".to_string()]);
        assert_eq!(ex, vec!["g".to_string()]);
    }

    #[test]
    fn name_split_and_hot() {
        let (n, b) = name_of(b"evt:mousemove | https://x/y.js\0fetch('/t')");
        assert!(n.starts_with("evt:"));
        assert_eq!(b, b"fetch('/t')");
        assert!(is_hot(&n, &b));
        assert!(!is_hot("cold.js", b"var a=1;"));
    }

    #[test]
    fn iso_split_and_worker_join() {
        let (iso, name) = split_iso("iso:0x7f00 https://af.io/main.js");
        assert_eq!(iso.as_deref(), Some("0x7f00"));
        assert_eq!(name, "https://af.io/main.js");
        let (iso, name) = split_iso("plain.js");
        assert!(iso.is_none());
        assert_eq!(name, "plain.js");

        let (iso, w) = worker_of("worker-scope iso=0x7f00 name=sw.js secure=1").unwrap();
        assert_eq!(iso, "0x7f00");
        assert_eq!(w, "sw.js");
        let workers = vec![(100u64, "0x7f00".into(), "sw.js".into())];
        assert_eq!(
            worker_name_for(&workers, 200, &Some("0x7f00".into())),
            Some("sw.js".into())
        );
        assert_eq!(worker_name_for(&workers, 200, &None), None);
        assert_eq!(
            worker_name_for(&workers, 50, &Some("0x7f00".into())),
            None // before the worker existed
        );
    }

    #[test]
    fn fp_needle_match() {
        assert_eq!(
            fp_needle_of("dom Navigator.get userAgent"),
            Some("Navigator.get userAgent")
        );
        assert_eq!(
            fp_needle_of("dom WebGLRenderingContext.call getParameter"),
            Some("getParameter")
        );
        assert_eq!(fp_needle_of("dom Document.getElementById"), None);
    }

    #[test]
    fn batched_payload_slice() {
        // two records share one part file: [rec0][rec1]
        let dir = std::env::temp_dir().join("afeye-batched-test");
        let _ = fs::create_dir_all(&dir);
        let p = dir.join("blink-dom-api-p0000.bin");
        let _ = fs::write(&p, b"dom Navigator.get userAgent|dom Screen.get width");
        let r0 = Rec {
            ts: 1, pid: 1, layer: "blink".into(), kind: "dom-api".into(),
            len: 27, h: String::new(), path: p.to_string_lossy().into(),
            off: Some(0), txt: None,
        };
        let r1 = Rec {
            ts: 2, pid: 1, layer: "blink".into(), kind: "dom-api".into(),
            len: 20, h: String::new(), path: p.to_string_lossy().into(),
            off: Some(28), txt: None,
        };
        assert_eq!(read_payload(&dir, &r0).unwrap(), b"dom Navigator.get userAgent");
        assert_eq!(read_payload(&dir, &r1).unwrap(), b"dom Screen.get width");
        let _ = fs::remove_file(&p);
    }

    fn tr(ts: u64, kind: &str) -> Rec {
        Rec {
            ts,
            pid: 1,
            layer: "blink".into(),
            kind: kind.into(),
            len: 8,
            h: String::new(),
            path: String::new(),
            off: None,
            txt: Some("evt mousemove".into()),
        }
    }

    #[test]
    fn trigger_correlation_window() {
        // ns timestamps, 250 ms window = 250_000_000 ns
        let mut recs = vec![
            tr(100_000_000_000, "script-source"),
            tr(100_010_000_000, "event-dispatch"), // +10 ms
            tr(100_200_000_000, "script-source"),   // +200 ms
        ];
        recs.sort_by_key(|r| r.ts);
        // 90ms after the dispatch -> inside the 250ms window
        let t = latest_trigger_before(&recs, 100_100_000_000, 250_000_000).unwrap();
        assert_eq!(t.kind, "event-dispatch");
        // 400ms after the dispatch -> outside
        assert!(latest_trigger_before(&recs, 100_410_000_000, 250_000_000).is_none());
        // before anything -> nothing
        assert!(latest_trigger_before(&recs, 10, 250_000_000).is_none());
    }

    #[test]
    fn net_window_overlap() {
        // net sends at t=100s (ns domain)
        let net_ts = vec![100_000_000_000u64];
        // chain materialized 1s before the send -> inside the 5s window
        assert!(overlaps_net_window(&net_ts, 99_000_000_000, 99_900_000_000));
        // chain materialized 10s before the send -> outside
        assert!(!overlaps_net_window(&net_ts, 89_000_000_000, 89_900_000_000));
        // chain started long ago but still materializing (last frag) 2s
        // before the send -> overlaps
        assert!(overlaps_net_window(&net_ts, 10_000_000_000, 98_000_000_000));
        // chain entirely AFTER the send -> outside
        assert!(!overlaps_net_window(&net_ts, 101_000_000_000, 102_000_000_000));
        // empty net stream -> nothing is adjacent
        assert!(!overlaps_net_window(&[], 1, 2));
    }

    fn chain_with(
        hot_pattern: bool,
        trigger: bool,
        fp: usize,
        integrity: u64,
    ) -> Chain {
        Chain {
            file: None,
            name: "x.js".into(),
            frags: 1,
            bytes: 10,
            hot: hot_pattern,
            hot_pattern,
            first_ts: 1_000,
            last_ts: 2_000,
            path: String::new(),
            trigger: if trigger {
                Some(TriggerRef { kind: "timer".into(), ts: 900, what: "w".into() })
            } else {
                None
            },
            iso: None,
            worker: None,
            fp_reads: vec!["a".to_string(); fp],
            integrity,
            integrity_samples: Vec::new(),
            clock_reads: 0,
            token_forming: false,
            signals: Vec::new(),
            net_adjacent: false,
            content_sink: false,
        }
    }

    #[test]
    fn dead_end_classification() {
        // no signals anywhere: dead end
        let c = chain_with(false, false, 0, 0);
        let (s, net, content) = chain_signals(&c, &[], &[]);
        assert!(s.is_empty());
        assert!(!net);
        assert!(!content);

        // sink-call in the chain's own code
        let c = chain_with(true, false, 0, 0);
        let (s, _, _) = chain_signals(&c, &[], &[]);
        assert_eq!(s, vec!["sink-call".to_string()]);

        // handler-born (compiled inside an event/timer)
        let c = chain_with(false, true, 0, 0);
        let (s, _, _) = chain_signals(&c, &[], &[]);
        assert_eq!(s, vec!["handler-born".to_string()]);

        // two distinct fingerprint probes during materialization
        let c = chain_with(false, false, 2, 0);
        let (s, _, _) = chain_signals(&c, &[], &[]);
        assert_eq!(s, vec!["fp-probes".to_string()]);
        // ONE probe alone is not enough (analytics reads one field too)
        let c = chain_with(false, false, 1, 0);
        let (s, _, _) = chain_signals(&c, &[], &[]);
        assert!(s.is_empty());

        // integrity self-checks in the window
        let c = chain_with(false, false, 0, 3);
        let (s, _, _) = chain_signals(&c, &[], &[]);
        assert_eq!(s, vec!["integrity-check".to_string()]);

        // net-window: chain materialized right before a send
        let c = chain_with(false, false, 0, 0);
        let net_ts = vec![100_000]; // FP_GRACE_NS + NET_FP_WINDOW_NS spans it
        let (s, net, _) = chain_signals(&c, &net_ts, &[]);
        assert_eq!(s, vec!["net-window".to_string()]);
        assert!(net);
    }
}
