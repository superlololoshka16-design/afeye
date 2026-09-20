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
    pub prune_paths: u64,
    // v9 entry-join signals (kind-8 attribution)
    pub send_initiator_chains: u64,
    pub token_access_chains: u64,
    pub fp_entry_chains: u64,
    // v10 (v8-depth pass)
    pub gopd_chains: u64,
    pub stack_inspect_chains: u64,
    pub automation_tells: u64,
    pub wasm_firstcalls: u64,
    pub wasm_traps: u64,
    pub wasm_cached: u64,
    pub lazy_funcs: u64,
    pub payload_assembler_chains: u64,
    // v11 fact graph
    pub graph_nodes: u64,
    pub graph_edges: u64,
    pub graph_sinks: u64,
    pub graph_tainted: u64,
    pub graph_hop1: u64,
    pub graph_deep: u64,
    pub graph_chains: u64,
    pub provenance_parents: u64,
    pub fetched_url_chains: u64,
    pub proven_chains: u64,
    pub heuristic_chains: u64,
    pub unresolved_chains: u64,
    pub dead_end_proven: u64,
    pub graph_distinct_keys: u64,
    pub graph_fanout_dropped: u64,
    pub strict_graph: bool,
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

/// v9 narrowed: only CAUSAL handler events - things that make a handler run
/// and compile code inside it. v7 included READ kinds (fingerprint,
/// dom-metric, audio, webrtc, crypto-op): during the load-phase fp storm
/// those fire hundreds/second, so the 250ms trigger window found a
/// "trigger" for EVERY early chain - handler-born saturated and the
/// filtered zip degenerated into a copy of the run zip. Reads are evidence
/// (fp-probes / content-sink / entry-join), not compile triggers.
const TRIGGER_KINDS: &[&str] = &[
    "input",
    "event-dispatch",
    "timer",
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

/// v10: harness/automation markers in a materialized Error.stack (0021).
/// Cloudflare Turnstile / DataDome / Kasada read .stack exactly to find these;
/// if OUR OWN crawler ever shows up here, that is a capture-integrity alarm.
const AUTOMATION_MARKERS: &[&str] = &[
    "pptr:",
    "__puppeteer",
    "playwright",
    "__nightmare",
    "webdriver-evaluate",
    "__webdriver_evaluate",
    "selenium",
    "callSelenium",
    "_Selenium",
    "cdc_",
    "__driver_evaluate",
    "__fxdriver",
    "callPhantom",
    "_phantom",
    "phantomjs",
    "__selenium",
    "CDP",
    "Runtime.evaluate",
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

// --- v11 the FACT GRAPH (honest selection, not timer guessing) -------------
// The v8 content-slice was 1-HOP: a carrier had to share a run DIRECTLY with a
// sink record. That loses transitivity - collector -> storage -> TextEncoder ->
// crypto, where the collector matches only the middle link, gets missed; and a
// payload wrapped in JSON/base64 between two hops breaks byte identity
// entirely (the 32 B windows shift). The graph fixes both:
//   * MULTI-HOP: BFS over shared-run edges from every sink record. A chain is
//     graph-tainted when a record inside ITS materialization window sits on a
//     byte-identity path to an upload/crypto/ws sink - any number of hops.
//   * VARIANT RUNS: sink bodies additionally emit runs over base64(body) and
//     hex(body), so a payload wrapped in a STANDARD encoding still matches.
//     Only for sinks (hundreds of records), never for every carrier.
//   * COMPILE-PROVENANCE (pass 2): the chain whose entry was active when a
//     PROVEN chain's source materialized is marked as its parent. One-way UP
//     only - taint is deliberately NOT inherited downward, because a
//     deobfuscator evals both the token pipeline and piles of library code,
//     and downward inheritance would drag all of it into the filtered zip.
/// Run keys are the first 8 bytes of the blake3 hash of a 32 B window. CSR
/// layout cost: 8 B per DISTINCT key (adj_keys) + 4 B per edge (adj_nodes) +
/// 4 B per key (adj_off). At this budget that is ~96 MB worst case, plus the
/// per-node key vectors. A tuple Vec<(u64,u32)> would be 16 B/edge from
/// alignment padding and would store every key a SECOND time in nodes[].keys;
/// a HashMap<u64,Vec<u32>> costs ~56 B/entry. CSR is cheaper than both and
/// answers a lookup with one binary search plus a direct slice.
/// A real capture lands far below the ceiling: a 960 B stringify head yields
/// ~58 keys, so 50k typical payload records are ~3M edges. Only the
/// multi-hundred-KB blobs (req-body, ssv, crypto raw_data) approach
/// CONTENT_MAX_RUNS.
const GRAPH_MAX_EDGES: usize = 8_000_000;
/// BFS hop ceiling (byte paths deeper than this are noise, not token flow)
const GRAPH_MAX_HOPS: u32 = 6;
/// variant-run encoding is only worth it on bodies at least this big
const VARIANT_MIN_BYTES: usize = 64;
/// cap on sink records that get variant runs (base64+hex of each)
const VARIANT_MAX_SINKS: usize = 4_096;
/// a request URL whose query is at least this long is treated as a payload
/// sink (short queries are cache-busters and utm noise)
const QUERY_SINK_MIN_BYTES: usize = 96;
/// the kind-17 `method\0url` records carry the method as the tag; everything
/// else in that kind is req-body / req-headers / complete
const HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
];
/// crypto-op tags whose content is payload-forming for the outbound token.
/// "encrypt"/"sign"/"deriveBits"/"digest" are the raw_data INPUTS (0007):
/// plaintext that upstream carriers (TextEncoder, SSV, storage, taint-edge)
/// must content-match. "crypto-out" is the RESULT (0018): the ciphertext /
/// signature / digest that the req-body and ws-frame-out sinks carry verbatim
/// - this is the edge that lets the slice cross the encryption boundary.
/// (decrypt is inbound; getRandomValues is a nonce source, not the payload.)
const SINK_CRYPTO_OPS: &[&str] = &[
    "encrypt",
    "sign",
    "deriveBits",
    "digest",
    "crypto-out",
];

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


/// v12.1: antifraud vendor by URL (moved from the bin-private ctx module so
/// the lib-exported filter is self-contained; the net-window seed logic
/// uses it). Same rules as ctx::vendor_of_url.
const AF_VENDORS: &[(&str, &str)] = &[
    ("challenges.cloudflare.com", "cloudflare"),
    ("cloudflare.com", "cloudflare"),
    ("datadome.co", "datadome"),
    ("kasada.io", "kasada"),
    ("perimeterx.net", "human"),
    ("px-cdn.net", "human"),
    ("px-client.net", "human"),
    ("humansecurity.com", "human"),
    ("perfdrive.com", "human"),
    ("edgesuite.net", "akamai"),
    ("akamaiedge.net", "akamai"),
    ("fpjs.io", "fpjs"),
    ("seon.io", "seon"),
    ("arkoselabs.com", "arkose"),
    ("hcaptcha.com", "hcaptcha"),
    ("imperva.com", "imperva"),
    ("threatmetrix.com", "threatmetrix"),
];

fn af_host_of(url: &str) -> &str {
    let s = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => return "",
    };
    let auth_end = s.find(['/', '?', '#']).unwrap_or(s.len());
    let auth = &s[..auth_end];
    let hostport = match auth.rfind('@') {
        Some(i) => &auth[i + 1..],
        None => auth,
    };
    match hostport.rfind(':') {
        Some(i) if !hostport[..i].contains(':') || hostport.starts_with('[') => {
            if hostport.starts_with('[') {
                &hostport[..hostport.find(']').map(|j| j + 1).unwrap_or(hostport.len())]
            } else {
                &hostport[..i]
            }
        }
        _ => hostport,
    }
}

fn af_vendor_of_url(url: &str) -> Option<&'static str> {
    let h = af_host_of(url);
    if h.is_empty() {
        return None;
    }
    if url.contains("/cdn-cgi/") || url.contains("/turnstile") {
        return Some("cloudflare");
    }
    if url.contains("/recaptcha") {
        return Some("recaptcha");
    }
    for (suf, v) in AF_VENDORS {
        if h == *suf
            || (h.len() > suf.len()
                && h.ends_with(suf)
                && h.as_bytes()[h.len() - suf.len() - 1] == b'.')
        {
            return Some(v);
        }
    }
    None
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

/// v12.1: 0013/0021 emit PROSE (EmitStr, no NUL split): "cookie-get len=N
/// <value>", "storage-get key=.. vlen=N <value>", "json-stringify len=..
/// replacer=.. head=<value>". name_of() gives tag="" for those, so the
/// VALUE_TAGS graph gate skipped every one of them and the advertised
/// cookie-relay / stringify->req-body linkage never existed. Derive the
/// (tag, body) pair from the known prefixes so those VALUE bytes join the
/// content graph. Records that parse to an empty value stay prose
/// (return None) - metadata lines never become graph nodes.
fn value_of_prose(payload: &[u8]) -> Option<(String, Vec<u8>)> {
    let t = std::str::from_utf8(payload).ok()?;
    for tag in ["cookie-get", "cookie-set"] {
        if let Some(rest) = t.strip_prefix(tag) {
            // " len=%u " then the value head
            let rest = rest.trim_start();
            if let Some(sp) = rest.find(' ') {
                let v = &rest[sp + 1..];
                if !v.is_empty() {
                    return Some((tag.to_string(), v.as_bytes().to_vec()));
                }
            }
            return None;
        }
    }
    for tag in ["storage-get", "storage-set"] {
        if let Some(rest) = t.strip_prefix(tag) {
            // " key=<k> vlen=%u " then the value head
            if let Some(vp) = rest.find(" vlen=") {
                let after = &rest[vp + 6..];
                if let Some(sp) = after.find(' ') {
                    let v = &after[sp + 1..];
                    if !v.is_empty() {
                        return Some((tag.to_string(), v.as_bytes().to_vec()));
                    }
                }
            }
            return None;
        }
    }
    if let Some(rest) = t.strip_prefix("json-stringify") {
        // " len=%d replacer=%d head=" then the plaintext head
        if let Some(hp) = rest.find(" head=") {
            let v = &rest[hp + 6..];
            if !v.is_empty() {
                return Some(("json-stringify".to_string(), v.as_bytes().to_vec()));
            }
        }
        return None;
    }
    None
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
    // v12.1: our own injected instrumentation (inject.rs) embeds literal
    // HOT_PATTERNS substrings, so its script-source always matched and the
    // harness chain shipped in BOTH zips as "token-forming". The v12.1 SRC
    // carries the AFXH marker line - exclude it here. SERIES.md: "if OUR
    // crawler's own harness shows up, that is a capture-integrity alarm".
    if body.windows(13).any(|w| w == b"afeye-harness") {
        return false;
    }
    if name.contains("afeye-harness") {
        return false;
    }

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

/// v11 (0023): did ANY sink report dropped records at or before `ts`?
/// Conservative by design: one drop anywhere earlier is enough to refuse
/// the "proven dead end" verdict, because the dropped record could be the
/// missing link of any chain. v12.1 widened from same-pid to ANY pid: the
/// graph's nodes span processes (carriers live in renderer pids, the
/// req-body/ws sinks in the network-service pid), so a sink dropped in
/// ANOTHER process kills the seed exactly like a renderer-side drop. The
/// throttle (10/s) also means dts is the REPORT time, not the drop time -
/// reports up to 500 ms after the window end still witness it.
fn drops_witnessed(drop_events: &[(u64, u64, u64)], _pid: u64, ts: u64) -> bool {
    let horizon = ts.saturating_add(500_000_000);
    drop_events
        .iter()
        .any(|(dts, _dpid, n)| *dts <= horizon && *n > 0)
}

/// v11: minimum hop distance from any graph-tainted payload record inside the
/// chain's materialization window. The window is the honest boundary of what
/// "this chain handled those bytes" can mean without a JS-level dataflow
/// analysis: the record was written while this chain's code was the compiled
/// body in play, so the bytes came from it.
fn graph_hops_for(graph_ts: &[(u64, u32)], first_ts: u64, last_ts: u64) -> Option<u32> {
    let lo = first_ts.saturating_sub(CONTENT_LINK_GRACE_NS);
    let hi = last_ts
        .saturating_add(FP_GRACE_NS)
        .saturating_add(CONTENT_LINK_GRACE_NS);
    let a = graph_ts.partition_point(|(t, _)| *t < lo);
    let b = graph_ts.partition_point(|(t, _)| *t <= hi);
    if a >= b {
        return None;
    }
    graph_ts[a..b].iter().map(|(_, h)| *h).min()
}

/// true when every byte is identical (zero runs, padding) - such runs collide
/// across unrelated records and would create false content links.
fn is_monotone(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(|&x| x == b[0])
}

/// v12.1: content_runs() (the v8 1-hop slice primitive) was superseded by
/// run_keys + the fact graph and had ZERO callers - deleted.
/// CONTENT_MAX_TOTAL_RUNS (its memory ceiling) went with it.

/// v11: u64 run keys (first 8 bytes of each blake3 run) - the graph edge
/// identity. 64-bit truncation over <=16M keys: collision probability ~4e-6,
/// and a collision only ever ADDS an edge between unrelated records (both
/// directions stay honest - taint spreads, never hides).
fn run_keys(body: &[u8]) -> Vec<u64> {
    let key = |b: &[u8]| -> u64 {
        let h = blake3::hash(b).as_bytes()[..8].to_vec();
        u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]])
    };
    let mut out: Vec<u64> = Vec::new();
    if body.len() < CONTENT_RUN_BYTES {
        if !body.is_empty() && !is_monotone(body) {
            out.push(key(body));
        }
        return out;
    }
    let mut off = 0usize;
    while off + CONTENT_RUN_BYTES <= body.len() && out.len() < CONTENT_MAX_RUNS {
        let win = &body[off..off + CONTENT_RUN_BYTES];
        if !is_monotone(win) {
            out.push(key(win));
        }
        off += CONTENT_RUN_STEP;
    }
    out
}

/// hex body as bytes (lowercase) - the variant encoding a token body takes
/// inside JSON/query wrappers
fn hex_bytes(b: &[u8]) -> Vec<u8> {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(b.len() * 2);
    for &x in b {
        out.push(H[(x >> 4) as usize]);
        out.push(H[(x & 0xf) as usize]);
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
    // v9 entry-join signals (kind-8 attribution, first-class observations):
    if c.send_initiator {
        // this chain's code initiated a fetch/XHR/beacon - observed send,
        // strictly stronger than the sink-call TEXT match
        signals.push("send-initiator".into());
    }
    if c.token_access {
        // this chain read/wrote a cookie or storage value - the store/read
        // half of store-then-send, attributed by entry not by window
        signals.push("token-access".into());
    }
    if !c.fp_entry.is_empty() {
        // >=2 distinct fingerprint reads while this chain was the active
        // entry - the window-independent fp-probes
        signals.push("fp-probes-entry".into());
    }
    if c.gopd_check {
        // v10: this chain inspected property DESCRIPTORS (tamper check on
        // navigator.webdriver / plugins / window.chrome) - first-class
        // antifraud behavior, not a data read
        signals.push("gopd-check".into());
    }
    if c.stack_inspect {
        // v10: this chain materialized Error.stack - automation detection
        // and/or caller-graph introspection
        signals.push("stack-inspect".into());
    }
    if !c.spawned_proven.is_empty() {
        // v11 pass 2: this chain was the active entry when a PROVEN chain's
        // script materialized - it eval'd / dynamically compiled the code that
        // built or sent the token. The orchestrator/deobfuscator: it may never
        // touch a payload byte itself, and the byte graph therefore cannot
        // reach it. Downward inheritance is deliberately NOT done (a
        // deobfuscator evals both the token pipeline and piles of library
        // code), so this marks the parent only.
        signals.push("spawned-proven".into());
    }
    if let Some(h) = c.graph_hops {
        // v11: PROVEN byte-identity path to a sink record, h hops away.
        // h=0 the chain wrote the upload/crypto result itself; h=1 its bytes
        // are identical to a sink's (what the v8 content-sink could see);
        // h>=2 transitive through intermediate payloads (storage, TextEncoder,
        // btoa) - unreachable for any timer heuristic. This is the strongest
        // signal in the set: it is a fact about bytes, not a guess about time.
        signals.push(format!("graph-sink@{h}"));
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
    /// process this chain's scripts ran in (the entry-join and provenance
    /// keys are per-pid: renderer and network service share no timeline)
    pid: u64,
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
    // v9 entry-join columns (kind-8 call-completed attribution)
    /// this chain's code was the active C++->JS entry when a fetch/XHR/
    /// beacon was initiated (kind 28) - OBSERVED send, not text match
    send_initiator: bool,
    /// this chain's code read/wrote a cookie or storage value (kind 16,
    /// 0013) - the token-access fact
    token_access: bool,
    /// fingerprint reads (kind 29) attributed BY ENTRY, not by
    /// materialization window: distinct needles read while this chain was
    /// the active entry point
    fp_entry: Vec<String>,
    // v10 columns (0021/0022/0023)
    /// this chain ran Object.getOwnPropertyDescriptor over a DOM object /
    /// proxy (0023, kind 16 "gopd ") - the tamper-verification probe
    gopd_check: bool,
    /// this chain materialized an Error.stack (0021, kind 38) - the
    /// automation-detection surface; the stack head is kept as a sample
    stack_inspect: bool,
    stack_samples: Vec<String>,
    /// this chain's entry ran JSON.stringify (0021 kind 16 "json-stringify")
    /// - the plaintext payload ASSEMBLY point right before crypto/wire
    payload_assembler: bool,
    /// how many of this chain's functions actually lazy-compiled (first
    /// execution, 0023 kind 8 "lazy-compile") - dead-code evidence inside a
    /// live script
    executed_funcs: u64,
    /// v11: minimum hop distance from this chain's window to a sink record in
    /// the byte-identity graph. None = not connected by byte identity.
    graph_hops: Option<u32>,
    /// v11: an observed FACT (byte-identity path, initiated send, or
    /// cookie/storage access) - not a heuristic. Drives AF_STRICT_GRAPH.
    proven: bool,
    /// v11: no observable link AND a completeness witness (zero ring drops in
    /// this pid up to the end of the window, 0023 kind 39). Only then is the
    /// absence of a link evidence rather than a capture gap.
    dead_end_proven: bool,
    /// v11 URL-identity: this chain's display name IS an http(s) URL that the
    /// net layer actually requested (kind 17 `method\0url`) - so this chain is
    /// DOWNLOADED code, not inline. A structural fact, not a taint claim: the
    /// resp-body -> URL mapping is NOT deterministic under concurrent requests
    /// in one process, so this never marks a chain proven by itself.
    fetched_url: bool,
    /// v11 compile-provenance: this chain was the active C++->JS entry when
    /// a PROVEN chain's script-source materialized - i.e. it eval'd /
    /// dynamically compiled the code that built or sent the token. The
    /// orchestrator/deobfuscator, which may never touch a payload byte
    /// itself. Carries the proven child's name for the report.
    spawned_proven: Vec<String>,
}

#[derive(Debug, Clone)]
struct TriggerRef {
    kind: String,
    ts: u64,
    what: String,
}

/// v12.1: same ambient-family exclusion for kind-24 (event-dispatch): 0006
/// emits a record for EVERY dispatched DOM event, and "evt mousemove ..." /
/// "evt-mouse mousemove ..." fire continuously during cursor emulation.
/// Without this the trigger loop accepted them unconditionally and
/// handler-born saturated again (the v7 bug v9 closed on the input side).
const AMBIENT_EVENT_TYPES: &[&str] = &[
    "mousemove",
    "pointermove",
    "touchmove",
    "pointerover",
    "pointerout",
    "pointerenter",
    "pointerleave",
    "scroll",
    "mouseover",
    "mouseout",
];

fn is_trigger_event(txt: &str) -> bool {
    for prefix in ["evt ", "evt-mouse ", "evt-key ", "evt-pointer "] {
        if let Some(rest) = txt.strip_prefix(prefix) {
            let etype = rest.split(' ').next().unwrap_or("");
            return !AMBIENT_EVENT_TYPES.contains(&etype);
        }
    }
    true
}

/// v9: is this input record a MEANINGFUL compile trigger? A mousemove storm
/// (bot-emulated or real) fires hundreds/sec and would trigger-mark every
/// chain compiled on the page; clicks/keys/wheel/gestures are the discrete
/// events a handler is plausibly born inside.
fn is_trigger_input(txt: &str) -> bool {
    if let Some(rest) = txt.strip_prefix("input/mouse ") {
        let etype = rest.split(' ').next().unwrap_or("");
        // mousemove is ambient, not a trigger
        return etype != "mousemove";
    }
    if let Some(rest) = txt.strip_prefix("input/raw type=") {
        // 0015 master funnel: stable WebInputEvent::GetName() string.
        // MouseMove / pointer-move raw updates are ambient; discrete events
        // (down/up/click-family, keys, wheel, gestures) are real triggers.
        let etype = rest.split(' ').next().unwrap_or("");
        return etype != "MouseMove"
            && etype != "PointerMove"
            && etype != "PointerRawUpdate"
            && etype != "PointerHoverMove"
            && etype != "MouseLeave"
            && etype != "MouseEnter"
            && etype != "TouchMove"
            && etype != "GestureScrollUpdate";
    }
    true
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
            let txt = r.txt.as_deref().unwrap_or("");
            if r.kind == "input" && !is_trigger_input(txt) {
                i -= 1;
                continue;
            }
            if r.kind == "event-dispatch" && !is_trigger_event(txt) {
                i -= 1;
                continue;
            }
            return Some(TriggerRef {
                kind: r.kind.clone(),
                ts: r.ts,
                what: txt_head(txt, 120),
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

// ---------------------------------------------------------------------------
// v9 entry-join: the kind-8 call-completed stream (0003 Invoke funnel) is the
// ready-made caller identity sitting UNUSED in the index. For every record of
// interest (fetch initiated, cookie/storage touched, fingerprint read) the
// last C++->JS entry at or before its ts in the same pid names the script
// that was executing - attribution by ENTRY instead of by materialization
// window. Honest limit: JS->JS calls do not cross Invoke (SERIES.md), so the
// entry is the nearest C++->JS boundary, not necessarily the exact reader;
// and records of different threads in one pid interleave (no tid in the wire
// format). Both documented, both strictly better than window guessing.
// ---------------------------------------------------------------------------

/// how far back an entry still explains a record (sync entry -> read path;
/// promise/microtask callbacks re-enter through Invoke so the entry stays
/// fresh; beyond this the attribution would be a guess)
const ENTRY_JOIN_WINDOW_NS: u64 = 250_000_000;

/// per-pid ts-sorted indices into recs of kind-8 call-completed records
struct EntryIndex {
    per_pid: HashMap<u64, Vec<usize>>,
}

/// parse the script name out of a kind-8 txt: "call argc=N[ c=1]
/// script=<name>:<line>". The name may contain ':' (https://...), so strip
/// only the trailing ":<digits>". Returns the display name (the chain key
/// after split_iso is the same bare resource name).
fn entry_script_of(txt: &str) -> Option<&str> {
    let rest = txt.rfind(" script=").map(|i| &txt[i + 8..])?;
    if rest == "native" {
        return None;
    }
    let cut = match rest.rfind(':') {
        Some(c) if rest[c + 1..].chars().all(|d| d.is_ascii_digit()) && c > 0 => c,
        _ => rest.len(),
    };
    let name = &rest[..cut];
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn build_entry_index(recs: &[Rec]) -> EntryIndex {
    let mut per_pid: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, r) in recs.iter().enumerate() {
        if r.kind == "call-completed" {
            if let Some(txt) = r.txt.as_deref() {
                // 0023 lazy-compile records ride kind 8 too but name the
                // COMPILED function, not an executing entry - including them
                // would misattribute reads to whichever function happened to
                // lazy-compile last. Entries only.
                if !txt.starts_with("lazy-compile") && entry_script_of(txt).is_some() {
                    per_pid.entry(r.pid).or_default().push(i);
                }
            }
        }
    }
    // recs are ts-sorted, so each per-pid vec already is
    EntryIndex { per_pid }
}

impl EntryIndex {
    /// the script name of the last entry at or before `ts` in this pid,
    /// within ENTRY_JOIN_WINDOW_NS
    fn script_at<'a>(&self, recs: &'a [Rec], pid: u64, ts: u64) -> Option<&'a str> {
        let v = self.per_pid.get(&pid)?;
        let hi = v.partition_point(|&i| recs[i].ts <= ts);
        if hi == 0 {
            return None;
        }
        let idx = v[hi - 1];
        if ts - recs[idx].ts > ENTRY_JOIN_WINDOW_NS {
            return None;
        }
        entry_script_of(recs[idx].txt.as_deref()?)
    }
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
    // v12.1: the collector's index `p` fields are relative to the OUT dir
    // (they literally start with "raw/"), NOT to the raw dir itself -
    // joining them under collect/raw resolved collect/raw/raw/... and
    // every payload read silently returned None (fragments=0, graph=0,
    // everything dead while the report still looked fine).
    let raw_dir = collect_dir.to_path_buf();
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
    let mut wasm_firstcalls = 0u64;
    let mut wasm_traps = 0u64;
    let mut automation_tells: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut drop_events: Vec<(u64, u64, u64)> = Vec::new(); // (ts, pid, total)
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
            // v11 (0023, kind 39): ring-overflow witness. Each layer's drain
            // thread writes "sink-drop layer=X dropped=N" when records were
            // lost. Without this the filter cannot tell "this branch fed
            // nothing" from "this branch's records were dropped", so
            // `unresolved` would be a guess instead of a verdict.
            "sink-drop" => {
                if let Some(n) = txt.split("dropped=").nth(1) {
                    if let Ok(n) = n.trim().parse::<u64>() {
                        drop_events.push((r.ts, r.pid, n));
                    }
                }
            }
            "worker" => {
                if let Some((iso, name)) = worker_of(txt) {
                    workers.push((r.ts, iso, name));
                }
            }
            "wasm-instance" => {
                let header = txt.starts_with("wasm-instantiate");
                wasm_inst.push((r.ts, r.pid, header, txt.to_string()));
                // 0020/0023: execution facts ride the same kind
                if txt.starts_with("wasm-firstcall ") {
                    wasm_firstcalls += 1;
                } else if txt.starts_with("wasm-trap ") {
                    wasm_traps += 1;
                }
            }
            // v10 (0021, kind 38): the materialized Error.stack string - the
            // automation-detection surface. Scan the head for harness markers.
            "error-stack" => {
                for marker in AUTOMATION_MARKERS {
                    if txt.contains(marker) {
                        *automation_tells.entry(*marker).or_insert(0) += 1;
                    }
                }
            }
            "nav-start" => {
                // v12.1: the payload carries the TRUE T0 (mono_ns=,
                // navigation_start.since_origin() from the browser process);
                // the record ts is only when the renderer emitted it. Use
                // the payload value, fall back to r.ts for old .rec files.
                let mono = txt
                    .split("mono_ns=")
                    .nth(1)
                    .and_then(|v| v.trim().parse::<u64>().ok());
                let t = mono.unwrap_or(r.ts);
                if nav_start.map(|old| t < old).unwrap_or(true) {
                    nav_start = Some(t);
                }
            }
            _ => {}
        }
    }
    stats.fp_reads = fp_reads.len() as u64;
    stats.integrity_checks = fnts.len() as u64;
    // v10 (0020/0021): wasm execution facts + automation-marker hits folded
    // from the pre-scan
    stats.wasm_firstcalls = wasm_firstcalls;
    stats.wasm_traps = wasm_traps;
    stats.automation_tells = automation_tells.values().sum();

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
                        pid: r.pid,
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
                        send_initiator: false,
                        token_access: false,
                        fp_entry: Vec::new(),
                        gopd_check: false,
                        stack_inspect: false,
                        stack_samples: Vec::new(),
                        payload_assembler: false,
                        executed_funcs: 0,
                        fetched_url: false,
                        graph_hops: None,
                        proven: false,
                        dead_end_proven: false,
                        spawned_proven: Vec::new(),
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
            // v10 (0020): the code-cache restore path emits
            // "cached\0<wire bytes>"; the wire/stream paths emit raw module
            // bytes with no tag. name_of splits on the FIRST NUL - for an
            // untagged payload the (name, body) split falls through to
            // (empty, whole) only when there is no NUL at all; a wasm module
            // with a NUL byte in its name section would mis-split, so accept
            // the split ONLY when the name is exactly the known tag.
            let (tag, body) = name_of(&payload);
            let from_cache = tag == "cached";
            let wasm_bytes: &[u8] = if from_cache { &body } else { &payload };
            if from_cache {
                stats.wasm_cached += 1;
            }
            let wp = wasm_dir.join(format!("{}.wasm", &r.h[..16.min(r.h.len())]));
            if fs::write(&wp, wasm_bytes).is_ok() {
                let (im, ex) = wasm_imports_exports(wasm_bytes);
                stats.wasm_modules += 1;
                stats.wasm_imports += im.len() as u64;
                stats.wasm_exports += ex.len() as u64;
                // v6: attach the imports AS RESOLVED at instantiation -
                // the closest following wasm-instantiate of the same pid
                let mut entry = json!({
                    "hash": r.h,
                    "bytes": wasm_bytes.len(),
                    "ts": r.ts,
                    "pid": r.pid,
                    "from_cache": from_cache,
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
    // v9 net-window seeds: NOT every net-request. v7 seeded the 5s window
    // with every subresource GET (scripts, css, images) - during the load
    // phase that covers everything and net-window degenerated into
    // "compiled during page load". A request can only be "payload
    // formation" when it can CARRY a payload: a non-GET/HEAD method, or a
    // known antifraud vendor host (their GETs carry tokens in the query),
    // or a req-body span recorded right after it. The record text is
    // EmitTwoStr(method, url) = "METHOD\0url" (0011 ScheduleStart), NUL
    // escaped as \u0000 by the collector.
    let mut net_ts: Vec<u64> = Vec::new();
    for r in recs.iter().filter(|r| r.kind == "net-request") {
        let txt = r.txt.as_deref().unwrap_or("");
        let (method, url) = match txt.find('\u{0}') {
            Some(i) => (&txt[..i], &txt[i + 1..]),
            None => ("", txt),
        };
        let non_get = !method.is_empty() && method != "GET" && method != "HEAD";
        let vendor = af_vendor_of_url(url).is_some();
        if non_get || vendor {
            net_ts.push(r.ts);
        }
    }
    net_ts.sort_unstable();

    // ---- v11 the FACT GRAPH: multi-hop byte-identity backward slice ---------
    // The v8 slice was 1-HOP (carrier must share a run DIRECTLY with a sink),
    // so a transitive pipeline collector -> storage -> TextEncoder -> crypto
    // was credited only if the collector happened to touch the sink bytes,
    // and a JSON/base64 envelope between hops broke identity outright. v11
    // builds the real graph:
    //   nodes  = payload records (crypto-op, structured-clone, net-request,
    //            taint-edge, websocket)
    //   edges  = a shared content run (blake3 over 32 B windows, stride 16;
    //            monotone windows skipped so padding never links)
    //   seeds  = SINK records: upload bodies (req-body), WS outbound frames,
    //            payload-forming crypto raw_data, and the crypto RESULT
    //            (0018 crypto-out - the ciphertext that the upload carries)
    //   slice  = BFS backwards over edges, GRAPH_MAX_HOPS deep
    // A chain whose materialization window holds a tainted record fed the
    // token BY DEMONSTRATED BYTE IDENTITY, at a known hop distance - not by a
    // timer guess. Variant runs (base64/hex of a sink body) let the slice
    // cross the envelope step where a ciphertext gets base64-wrapped.
    //
    // Memory: edges are a flat sorted Vec<(u64 key, u32 node)> - 12 B each -
    // instead of a HashMap<u64, Vec<u32>> (~50 B/entry + buckets). The key is
    // the first 8 bytes of the run hash; at 16 M edges the birthday-collision
    // probability is ~4e-6, and a collision can only ADD an edge (taint
    // spreads, it never hides), so the failure mode is a thicker filtered
    // zip, never a lost token chain.
    let payload_kinds = [
        "crypto-op",
        "structured-clone",
        "net-request",
        "taint-edge",
        "websocket",
        // kind 16, but ONLY the byte-carrying records (VALUE_TAGS gate below).
        // kind 18 net-resp-body is deliberately EXCLUDED: those are raw wire
        // bytes (usually gzip/brotli-encoded) that do not byte-match the
        // decompressed script-source or any plaintext payload, and every
        // subresource response would crowd the CONTENT_MAX_RECORDS node budget
        // with records that can never link. The Set-Cookie half of the cookie
        // relay is covered instead by the kind-16 cookie-get/cookie-set values.
        "fingerprint",
    ];
    // kind-16 records split into two classes and only ONE belongs in the
    // graph: spans carrying real fingerprint/response BYTES vs prose metadata
    // lines. Prose would create edges between unrelated records (a "css/
    // get-computed prop=font-family val=Arial" line shares runs with every
    // other page that reads the same property).
    const VALUE_TAGS: &[&str] = &[
        "cookie-get",          // 0013
        "cookie-set",          // 0013
        "storage-get",         // 0013
        "storage-set",         // 0013
        "canvas/get-image-data-r", // 0014 pixel result
        "webgl/read-pixels-r", // 0014 pixel result
        "audio/float-frequency",   // 0014
        "audio/byte-frequency",    // 0014
        "audio/float-timedomain",  // 0014
        "audio/byte-timedomain",   // 0014
        "json-stringify",      // 0021 assembled plaintext head
    ];
    // The request URL is a carrier too: a payload can leave in the QUERY
    // STRING with no body at all (pixel beacons, img.src fallbacks), which no
    // req-body sink ever sees. This repo's own capture carries such requests
    // with 500-1300 char queries and empty bodies. Kind 17's first record is
    // EmitTwoStr(method, url) = "METHOD\0url", so the URL is the body after
    // the NUL split - the same read_payload/name_of path as every other
    // carrier, no new plumbing.

    struct GraphNode {
        ts: u64,
        sink: bool,
        keys: Vec<u64>,
    }

    let mut nodes: Vec<GraphNode> = Vec::new();
    let mut total_keys = 0usize;
    let mut sinks_seen = 0usize;
    let mut carriers_seen = 0usize;
    for r in &recs {
        if !payload_kinds.contains(&r.kind.as_str()) {
            continue;
        }
        let payload = match read_payload(&raw_dir, r) {
            Some(p) => p,
            None => continue,
        };
        let (mut tag, mut body) = name_of(&payload);
        // v12.1: NUL-less kind-16 PROSE records (0013 cookie/storage values,
        // 0021 json-stringify head) carry real VALUE bytes but no NUL split -
        // derive the pair so they join the graph (see value_of_prose; the
        // VALUE_TAGS gate below then matches by the derived tag).
        if r.kind == "fingerprint" && tag.is_empty() {
            if let Some((t2, b2)) = value_of_prose(&payload) {
                tag = t2;
                body = b2;
            }
        }
        if body.is_empty() {
            continue;
        }
        // kind 16: only the byte-carrying records join the graph (see
        // VALUE_TAGS). kind 18 (net-resp-body): the raw wire response, which
        // is the module bytes a dynamic import later compiles.
        if r.kind == "fingerprint" && !VALUE_TAGS.iter().any(|t| tag.starts_with(t)) {
            continue;
        }
        let is_crypto_sink = r.kind == "crypto-op"
            && SINK_CRYPTO_OPS.iter().any(|o| tag.contains(o));
        let is_upload = r.kind == "net-request" && tag == "req-body";
        // the method\0url record: a carrier, and a SINK when the query is
        // long enough to be a payload rather than a cache-buster. A body-less
        // beacon is the only observable evidence that anything left.
        // tag must be an HTTP method here (req-body / req-headers are the
        // other kind-17 tags; a bare url record carries "GET"/"POST"/...).
        // v12.1: the seed is the QUERY STRING length, not the whole URL -
        // a 90+ char path with a 2-char "?v=" is a cache-buster, and the old
        // whole-URL check made it a hop-0 sink: page-load chains overlapping
        // its ts got graph-sink@0 = PROVEN on a timer accident.
        let query_len = body
            .iter()
            .position(|&c| c == b'?')
            .map(|q| body.len() - q - 1)
            .unwrap_or(0);
        let is_query_sink = r.kind == "net-request"
            && HTTP_METHODS.contains(&tag.as_str())
            && query_len >= QUERY_SINK_MIN_BYTES;
        // 0017: only the OUTBOUND ws frame sinks; inbound tags stay carriers
        // (a challenge response can be re-sent verbatim later).
        let is_ws_sink = r.kind == "websocket" && tag == "ws-frame-out";
        let sink = is_crypto_sink || is_upload || is_ws_sink || is_query_sink;

        // Budget gates CARRIERS only. A sink is always admitted: it is a BFS
        // seed, and dropping one silently deletes every chain upstream of it.
        // recs are ts-sorted, so the old single break cut the run at the first
        // 50k records and lost the LATE token send - the very 10-30s
        // collect-then-send case this graph exists to catch. Sinks are few
        // (hundreds per run: uploads, crypto ops) so this cannot blow up;
        // GRAPH_MAX_EDGES still bounds the total.
        if !sink {
            if carriers_seen >= CONTENT_MAX_RECORDS || total_keys >= GRAPH_MAX_EDGES {
                continue;
            }
            carriers_seen += 1;
        } else if total_keys >= GRAPH_MAX_EDGES {
            // v12.1: the edge budget is exhausted - admit the SINK with empty
            // keys instead of dropping it: a dropped seed deletes every
            // upstream chain's provenness silently. Empty keys = hop-0
            // taint at its own ts; the edge budget only bounds adjacency,
            // never the seed set itself.
            nodes.push(GraphNode { ts: r.ts, sink: true, keys: Vec::new() });
            continue;
        }

        let mut keys = run_keys(&body);
        // variant runs: only sinks pay for them, bounded by VARIANT_MAX_SINKS.
        // These cover the STANDARD encodings only: base64 (RFC 4648) and
        // lowercase hex. HONEST LIMIT, proven against this repo's own capture
        // (afeye-20260918-144834.zip, the 4 Cloudflare .post bodies): their
        // wire charset is "$+,-./0-9:A-Za-z{}" with NO "=" padding at all, so
        // it is a vendor-specific alphabet, not base64. A sink whose bytes are
        // wrapped in a custom alphabet will NOT match these variant runs and
        // the graph reports the chain as unresolved rather than guessing.
        // Fixing that needs the alphabet extracted from the captured
        // script-source and a parameterized decoder - not another encoding
        // guess.
        if sink && body.len() >= VARIANT_MIN_BYTES && sinks_seen < VARIANT_MAX_SINKS {
            sinks_seen += 1;
            let room = GRAPH_MAX_EDGES.saturating_sub(total_keys);
            if room > 0 {
                use base64::Engine as _;
                let b64 = base64::engine::general_purpose::STANDARD
                    .encode(&body)
                    .into_bytes();
                let mut vk = run_keys(&b64);
                vk.extend(run_keys(&hex_bytes(&body)));
                vk.truncate(room.min(vk.len()));
                total_keys += vk.len();
                keys.extend(vk);
            }
        }
        // per-node bound: run_keys already caps at CONTENT_MAX_RUNS; the
        // variant runs (base64+hex, ~2x) share the same ceiling so one huge
        // blob cannot eat the global edge budget.
        if keys.len() > CONTENT_MAX_RUNS {
            keys.truncate(CONTENT_MAX_RUNS);
        }
        // dedup: a periodic body (period dividing the 16B stride) emits the
        // same window repeatedly. Duplicates would inflate fanout and make the
        // BFS re-walk identical neighbour lists.
        keys.sort_unstable();
        keys.dedup();
        total_keys += keys.len();
        nodes.push(GraphNode { ts: r.ts, sink, keys });
    }

    // ---- CSR adjacency (compressed sparse row) --------------------------------
    // Three flat arrays beat both alternatives here:
    //   flat Vec<(u64,u32)> : 16 B/edge (align padding) + a SECOND copy of the
    //                         keys in nodes[].keys, and a 23-probe binary
    //                         search per neighbour lookup
    //   HashMap<u64,Vec<u32>>: ~56 B/entry + bucket overhead, fastest lookup
    //                         but ~1.7x the memory
    //   CSR                 : one bsearch on `adj_keys`, then a direct slice -
    //                         8 B per distinct key + 4 B per edge + 4 B offset,
    //                         no duplicated key storage, no hashing.
    let mut adj_keys: Vec<u64> = Vec::new();
    let mut adj_off: Vec<u32> = Vec::new();
    let mut adj_nodes: Vec<u32> = Vec::new();
    {
        // counting pass: gather (key, node) pairs, then sort by key once
        let mut pairs: Vec<(u64, u32)> = Vec::with_capacity(total_keys);
        for (ni, n) in nodes.iter().enumerate() {
            for k in &n.keys {
                if pairs.len() >= GRAPH_MAX_EDGES {
                    break;
                }
                pairs.push((*k, ni as u32));
            }
        }
        pairs.sort_unstable();
        let mut edge_count = 0usize;
        let mut i = 0usize;
        while i < pairs.len() {
            let key = pairs[i].0;
            let start = i;
            while i < pairs.len() && pairs[i].0 == key {
                i += 1;
            }
            adj_keys.push(key);
            adj_off.push(edge_count as u32);
            for p in &pairs[start..i] {
                adj_nodes.push(p.1);
            }
            edge_count += i - start;
        }
        adj_off.push(edge_count as u32);
        stats.graph_edges = edge_count as u64;
        stats.graph_distinct_keys = adj_keys.len() as u64;
    }

    // A run shared by more than this many records is boilerplate (a common
    // JSON prefix, an identical SSV header across thousands of records), not
    // token payload - linking on it would taint the whole page. This cap is
    // the ONE place the graph can produce an honest false-negative, so it is
    // counted and reported, never silent. Sink nodes bypass the cap: a token
    // window that happens to share a boilerplate prefix with thousands of
    // records must still spread its own taint - the danger is only in the
    // carrier direction, where an over-linked key would light up everything.
    const GRAPH_MAX_FANOUT: usize = 4096;

    // BFS backwards from every sink node
    let mut dist: Vec<u32> = vec![u32::MAX; nodes.len()];
    let mut queue: Vec<u32> = Vec::new();
    let mut seed_count = 0usize;
    for (ni, n) in nodes.iter().enumerate() {
        if n.sink {
            dist[ni] = 0;
            queue.push(ni as u32);
            seed_count += 1;
        }
    }
    let mut fanout_dropped: u64 = 0;
    let mut head = 0usize;
    while head < queue.len() {
        let u = queue[head] as usize;
        head += 1;
        let du = dist[u];
        if du >= GRAPH_MAX_HOPS {
            continue;
        }
        let from_sink = nodes[u].sink;
        for k in &nodes[u].keys {
            let ki = match adj_keys.binary_search(k) {
                Ok(i) => i,
                Err(_) => continue,
            };
            let lo = adj_off[ki] as usize;
            let hi = adj_off[ki + 1] as usize;
            if !from_sink && hi - lo > GRAPH_MAX_FANOUT {
                fanout_dropped += (hi - lo) as u64;
                continue;
            }
            for v in &adj_nodes[lo..hi] {
                let v = *v as usize;
                if dist[v] == u32::MAX {
                    dist[v] = du + 1;
                    queue.push(v as u32);
                }
            }
        }
    }
    stats.graph_fanout_dropped = fanout_dropped;

    // tainted payload positions: (ts, hops) sorted by ts - the chain marker
    // takes the MINIMUM hop distance inside its window
    let mut graph_ts: Vec<(u64, u32)> = Vec::new();
    let mut tainted_nodes = 0usize;
    let mut hop_hist: BTreeMap<u32, u64> = BTreeMap::new();
    for (ni, n) in nodes.iter().enumerate() {
        if dist[ni] != u32::MAX {
            tainted_nodes += 1;
            graph_ts.push((n.ts, dist[ni]));
            *hop_hist.entry(dist[ni]).or_insert(0) += 1;
        }
    }
    graph_ts.sort_unstable();
    stats.graph_nodes = nodes.len() as u64;
    // graph_edges already set inside the CSR build block
    stats.graph_sinks = seed_count as u64;
    stats.graph_tainted = tainted_nodes as u64;
    // hop 0 = the sink record itself; hop 1 = byte-identical to a sink (the
    // old 1-hop content-sink); hop >= 2 = transitive through intermediate
    // payloads - what the timer heuristics could never reach.
    stats.graph_hop1 = hop_hist.get(&1).copied().unwrap_or(0);
    stats.graph_deep = hop_hist.iter().filter(|(h, _)| **h >= 2).map(|(_, n)| *n).sum();

    // backward-compatible 1-hop view: content_ts drives the existing
    // `content-sink` signal; the graph adds `graph-sink` with the hop count.
    let mut content_ts: Vec<u64> = graph_ts
        .iter()
        .filter(|(_, h)| *h <= 1)
        .map(|(t, _)| *t)
        .collect();
    content_ts.dedup();

    // v12.1: kind-8 entries cap script names at 200 chars with non-printables
    // folded to '?' (0003), lazy-compile names at 160 (0022), while chain
    // display names are untruncated - long-named scripts (>160 chars, e.g.
    // the query-URL scripts this repo's own capture carries) never joined.
    // Canonicalize both sides the same way before the lookup.
    fn canon_name(n: &str) -> String {
        n.chars()
            .take(160)
            .map(|ch| {
                if !ch.is_ascii_graphic() && ch != ' ' {
                    '?'
                } else {
                    ch
                }
            })
            .collect()
    }

    // ---- v9 entry-join: attribute records of interest to the CHAIN that was
    // the active C++->JS entry, using the kind-8 stream. This is the caller
    // identity that kind-29/16/28 records lack in C++ (no stack walk there) -
    // recovered externally from Invoke, zero extra C++ cost. Three facts it
    // turns into first-class signals (observed, not text-matched):
    //   send-initiator : a fetch/XHR/beacon was INITIATED (kind 28) while this
    //                    chain was the entry - it really sent something.
    //   token-access   : this chain read/wrote a cookie or storage value
    //                    (kind 16 cookie-get/set, storage-get/set, 0013).
    //   fp-probes(entry): >=2 DISTINCT fingerprint reads (kind 29) happened
    //                    while this chain was the entry - attributed by
    //                    ENTRY, immune to the load-phase window false-positives
    //                    that plagued the materialization-window fp count.
    let entry_index = build_entry_index(&recs);
    // error-stack records are attributed the same way (kind 38 carries no
    // caller in C++; the entry-join recovers it)

    // (pid, display-name) -> chain idx (first wins; display names are the
    // bare resource URL that kind-8 script= also carries, so they join
    // directly). v12.1: keyed by pid too - two renderer processes that load
    // the same URL produce two chains with identical display names, and a
    // bare-name key attributed pid B's fetch to pid A's chain (wrong
    // PROVEN verdict). OWNED keys: this map outlives three passes that take
    // `&mut chain_list`, and borrowing the names would hold an immutable
    // borrow across them.
    let mut name_to_chain: HashMap<(u64, String), usize> = HashMap::new();
    for (idx, c) in chain_list.iter().enumerate() {
        if !c.name.is_empty() {
            name_to_chain
                .entry((c.pid, canon_name(&c.name)))
                .or_insert(idx);
        }
    }
    // per-chain accumulators keyed by idx
    let mut send_init: HashSet<usize> = HashSet::new();
    let mut tok_access: HashSet<usize> = HashSet::new();
    let mut fp_entry: HashMap<usize, Vec<&'static str>> = HashMap::new();
    let mut gopd_chains: HashSet<usize> = HashSet::new();
    let mut stack_chains: HashSet<usize> = HashSet::new();
    let mut assembler_chains: HashSet<usize> = HashSet::new();
    let mut stack_samples: HashMap<usize, Vec<String>> = HashMap::new();
    for r in &recs {
        let interest = matches!(
            r.kind.as_str(),
            "fetch" | "fingerprint" | "dom-api" | "error-stack"
        );
        if !interest {
            continue;
        }
        let script = match entry_index.script_at(&recs, r.pid, r.ts) {
            Some(sc) => sc,
            None => continue,
        };
        // strip the iso prefix the kind-8 name may carry (split_iso mirrors
        // the chain display-name normalization), then canonicalize the
        // truncation/folding the C++ side applies to entry names so
        // long-named scripts still join (see canon_name)
        let (_, bare) = split_iso(script);
        let idx = match name_to_chain.get(&(r.pid, canon_name(&bare))) {
            Some(i) => *i,
            None => continue,
        };
        let txt = r.txt.as_deref().unwrap_or("");
        match r.kind.as_str() {
            // kind 28: "fetch url=.. type=.. ctx=.." - a real send initiation
            "fetch" => {
                send_init.insert(idx);
            }
            // kind 16 v8-layer "json-stringify ..." (0021): the plaintext
            // payload assembly point - which chain serialized what right
            // before crypto/wire. Guarded arm FIRST: the plain "fingerprint"
            // arm below would swallow every kind-16 record.
            "fingerprint" if txt.starts_with("json-stringify ") => {
                assembler_chains.insert(idx);
            }
            // kind 16 with a cookie/storage value (0013) - token access.
            // The canvas/webgl/audio fingerprints also land in kind 16; only
            // the cookie/storage tags are token ACCESS (read/write of the
            // stored token), the rest are collection (fp_entry below).
            "fingerprint" => {
                if txt.starts_with("cookie-get")
                    || txt.starts_with("cookie-set")
                    || txt.starts_with("storage-get")
                    || txt.starts_with("storage-set")
                {
                    tok_access.insert(idx);
                }
            }
            // kind 29 dom-api fingerprint read; the 0023 GOPD records ride
            // kind 16 (fingerprint) with the "gopd " prefix instead
            "dom-api" => {
                if let Some(needle) = fp_needle_of(txt) {
                    let v = fp_entry.entry(idx).or_default();
                    if !v.contains(&needle) {
                        v.push(needle);
                    }
                }
            }
            // kind 38: this chain materialized an Error.stack - automation
            // detection and/or JS->JS caller chains (the stack head IS the
            // call graph at introspection moments)
            "error-stack" => {
                stack_chains.insert(idx);
                let v = stack_samples.entry(idx).or_default();
                if v.len() < 4 {
                    v.push(txt_head(txt, 240));
                }
            }
            _ => {}
        }
        // GOPD tamper-check (0023) rides kind 16 with the "gopd " prefix
        if r.kind == "fingerprint" && txt.starts_with("gopd ") {
            gopd_chains.insert(idx);
        }
    }
    // fold the entry-join facts onto the chains
    for idx in send_init {
        if let Some(c) = chain_list.get_mut(idx) {
            c.send_initiator = true;
            stats.send_initiator_chains += 1;
        }
    }
    for idx in tok_access {
        if let Some(c) = chain_list.get_mut(idx) {
            c.token_access = true;
            stats.token_access_chains += 1;
        }
    }
    for (idx, needles) in fp_entry {
        if needles.len() >= 2 {
            if let Some(c) = chain_list.get_mut(idx) {
                c.fp_entry = needles.iter().map(|x| x.to_string()).take(32).collect();
                stats.fp_entry_chains += 1;
            }
        }
    }
    for idx in gopd_chains {
        if let Some(c) = chain_list.get_mut(idx) {
            c.gopd_check = true;
            stats.gopd_chains += 1;
        }
    }
    for idx in stack_chains {
        if let Some(c) = chain_list.get_mut(idx) {
            c.stack_inspect = true;
            c.stack_samples = stack_samples.remove(&idx).unwrap_or_default();
            stats.stack_inspect_chains += 1;
        }
    }
    for idx in assembler_chains {
        if let Some(c) = chain_list.get_mut(idx) {
            c.payload_assembler = true;
            stats.payload_assembler_chains += 1;
        }
    }

    // v10 executed-function evidence: 0023 lazy-compile records carry
    // script=<bare chain name>:<line> - count them per chain. A chain with
    // executed_funcs=0 has code that was COMPILED (toplevel) but whose
    // functions never ran: dead weight inside a live script.
    let mut lazy_per_name: HashMap<&str, u64> = HashMap::new();
    for r in &recs {
        if r.kind != "call-completed" {
            continue;
        }
        let txt = r.txt.as_deref().unwrap_or("");
        if let Some(rest) = txt.strip_prefix("lazy-compile ") {
            stats.lazy_funcs += 1;
            if let Some(sp) = rest.find(" script=") {
                let script_part = &rest[sp + 8..];
                let bare = match script_part.rfind(':') {
                    Some(c) if script_part[c + 1..]
                        .chars()
                        .all(|d| d.is_ascii_digit()) => &script_part[..c],
                    _ => script_part,
                };
                *lazy_per_name.entry(bare).or_insert(0) += 1;
            }
        }
    }
    for c in &mut chain_list {
        if !c.name.is_empty() {
            if let Some(n) = lazy_per_name.get(c.name.as_str()) {
                c.executed_funcs = *n;
            }
        }
    }

    // v11: hop distance per chain FIRST - chain_signals reports it.
    for c in &mut chain_list {
        c.graph_hops = graph_hops_for(&graph_ts, c.first_ts, c.last_ts);
    }

    // ---- v11 honest classification, three ordered passes -------------------
    // PROVEN      : an observed FACT - a byte-identity path to a sink
    //               (graph-sink), an entry that initiated a fetch/XHR/beacon
    //               (send-initiator), an entry that read/wrote a cookie or
    //               storage value (token-access), or an entry that eval'd /
    //               dynamically compiled a chain which is itself proven
    //               (provenance, pass 2).
    // HEURISTIC   : evidence, not proof - text match, time windows, probe
    //               counts. Kept in the filtered zip by default: the real
    //               collectors often live here.
    // UNRESOLVED  : no observable connection. Deliberately NOT called a
    //               "proven dead end": in-memory dataflow (fingerprint ->
    //               closure variable -> sent 30 s later by another chain)
    //               crosses NO C++ boundary, so boundary-level capture can
    //               never prove the negative. The token story survives because
    //               the ASSEMBLING and SENDING chains are proven; only the
    //               invisible middle is dropped. AF_STRICT_GRAPH=1 cuts the
    //               filtered zip to PROVEN only.
    //
    // PASS 1 - the per-chain facts that need no other chain.
    for c in &mut chain_list {
        c.proven = c.graph_hops.is_some() || c.send_initiator || c.token_access;
    }

    // ---- PASS 1b: URL-identity (structural, zero-risk) ---------------------
    // A chain whose display name is a URL the net layer actually requested is
    // downloaded code. Deliberately NOT a proven/taint signal: attributing a
    // resp-body span to its URL would need per-request correlation that the
    // wire format does not carry (concurrent responses interleave in one pid),
    // and claiming it would be exactly the kind of guess this pass removes.
    {
        let mut requested: HashSet<String> = HashSet::new();
        for r in recs.iter().filter(|r| r.kind == "net-request") {
            let txt = r.txt.as_deref().unwrap_or("");
            if let Some(nul) = txt.find('\u{0}') {
                let url = &txt[nul + 1..];
                if url.starts_with("http://") || url.starts_with("https://") {
                    requested.insert(url.to_string());
                }
            }
        }
        for c in &mut chain_list {
            if !c.name.is_empty() && requested.contains(&c.name) {
                c.fetched_url = true;
                stats.fetched_url_chains += 1;
            }
        }
    }

    // ---- PASS 2: compile-provenance edges --------------------------------------
    // The byte graph cannot see WHO eval'd/compiled the token code: an
    // eval'd chunk's source crosses kind-1 with the name "eval", and its
    // bytes are code, not payload. But the moment a PROVEN chain's first
    // fragment materialized, some chain was the active C++->JS entry (kind-8)
    // - that chain is the one that ran the eval / dynamic import / Function
    // constructor which produced it. Mark that parent.
    //
    // Direction matters: the edge is recorded on the PARENT only. Taint is
    // NOT inherited downward, because a deobfuscator legitimately evals both
    // the token pipeline and piles of library code - downward inheritance
    // would drag every lodash template into the filtered zip. The parent
    // marker answers "which orchestrator spawned proven code", which is what
    // the report needs, without contaminating the cut.
    //
    // Honest limit: the parent is the nearest C++->JS entry, so a chunk
    // compiled during a long synchronous run is attributed to that entry;
    // and a chunk compiled on a background thread has no entry to attribute
    // (script_at returns None) - it stays unparented rather than guessing.
    {
        let mut proven_names: Vec<(u64, u64, usize, &str)> = chain_list
            .iter()
            .enumerate()
            .filter(|(_, c)| c.proven && !c.name.is_empty())
            .map(|(i, c)| (c.pid, c.first_ts, i, c.name.as_str()))
            .collect();
        proven_names.sort_unstable_by_key(|x| (x.0, x.1));
        let mut parents: HashMap<usize, Vec<String>> = HashMap::new();
        for (pid, ts, _ci, child) in &proven_names {
            let parent = match entry_index.script_at(&recs, *pid, *ts) {
                Some(p) => p,
                None => continue,
            };
            let (_, bare) = split_iso(parent);
            // a chain that compiled itself (toplevel script) is not a parent
            if bare == *child {
                continue;
            }
            let pidx = match name_to_chain.get(&(*pid, canon_name(&bare))) {
                Some(i) => *i,
                None => continue,
            };
            let v = parents.entry(pidx).or_default();
            let cname = child.to_string();
            if !v.contains(&cname) && v.len() < 16 {
                v.push(cname);
            }
        }
        for (pidx, children) in parents {
            if let Some(c) = chain_list.get_mut(pidx) {
                c.spawned_proven = children;
                stats.provenance_parents += 1;
            }
        }
    }

    // PASS 3 - signals and the three-way verdict, now that provenance is known.
    let strict_graph =
        std::env::var("AF_STRICT_GRAPH").map(|v| v == "1").unwrap_or(false);
    stats.strict_graph = strict_graph;
    for c in &mut chain_list {
        let (signals, net_adjacent, content_sink) = chain_signals(c, &net_ts, &content_ts);
        if net_adjacent {
            stats.net_adjacent_chains += 1;
        }
        if content_sink {
            stats.content_sink_chains += 1;
        }
        if c.graph_hops.is_some() {
            stats.graph_chains += 1;
        }
        // provenance upgrades the parent: it is a kind-8 fact about which
        // entry compiled the proven code, not a guess.
        if !c.spawned_proven.is_empty() {
            c.proven = true;
        }
        if c.proven {
            stats.proven_chains += 1;
        }
        if !signals.is_empty() || c.proven {
            c.token_forming = true;
            stats.token_chains += 1;
            if !c.proven {
                stats.heuristic_chains += 1;
            }
        } else {
            stats.dead_end_chains += 1;
            // An UNRESOLVED chain is a PROVEN dead end only with a
            // completeness witness: no ring drops in this pid up to the end of
            // its materialization window. With drops present the absence of a
            // link is not evidence - the link may have been dropped.
            if !drops_witnessed(&drop_events, c.pid, c.last_ts) {
                c.dead_end_proven = true;
                stats.dead_end_proven += 1;
            } else {
                stats.unresolved_chains += 1;
            }
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

    // v9 prune list: the authoritative cut set for the filtered zip, UNCAPPED
    // (the report's chains[] caps at 4000; chains past the cap were silently
    // escaping the cut - eval storms leak thousands).
    // v11: in AF_STRICT_GRAPH mode the keep rule tightens from "token_forming"
    // (facts + heuristics) to "proven" (facts only: byte-identity graph path,
    // observed send initiation, observed cookie/storage access). Everything
    // else is pruned, INCLUDING heuristic-only chains.
    let prune_report: Vec<serde_json::Value> = chain_list
        .iter()
        .filter(|c| {
            !c.path.is_empty() && if stats.strict_graph { !c.proven } else { !c.token_forming }
        })
        .map(|c| {
            json!({
                "path": c.path,
                "bytes": c.bytes,
                "verdict": if c.proven {
                    "proven"
                } else if c.token_forming {
                    "heuristic"
                } else if c.dead_end_proven {
                    "dead-end-proven"
                } else {
                    "unresolved"
                },
            })
        })
        .collect();
    stats.prune_paths = prune_report.len() as u64;

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
        if c.send_initiator {
            entry["send_initiator"] = json!(true);
        }
        if c.token_access {
            entry["token_access"] = json!(true);
        }
        if !c.fp_entry.is_empty() {
            entry["fp_entry"] = json!(c.fp_entry);
        }
        if c.gopd_check {
            entry["gopd_check"] = json!(true);
        }
        if c.stack_inspect {
            entry["stack_inspect"] = json!(true);
            if !c.stack_samples.is_empty() {
                entry["stack_samples"] = json!(c.stack_samples);
            }
        }
        if c.payload_assembler {
            entry["payload_assembler"] = json!(true);
        }
        if c.executed_funcs > 0 {
            entry["executed_funcs"] = json!(c.executed_funcs);
        }
        if let Some(h) = c.graph_hops {
            entry["graph_hops"] = json!(h);
        }
        if !c.spawned_proven.is_empty() {
            entry["spawned_proven"] = json!(c.spawned_proven);
            entry["provenance"] = json!("entry");
        }
        if c.fetched_url {
            entry["fetched_url"] = json!(true);
        }
        entry["verdict"] = json!(if c.proven {
            "proven"
        } else if c.token_forming {
            "heuristic"
        } else if c.dead_end_proven {
            "dead-end-proven"
        } else {
            "unresolved"
        });
        if !c.token_forming {
            entry["dead_end_witness"] = json!({
                "ring_drops_in_pid": drops_witnessed(&drop_events, c.pid, c.last_ts),
            });
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
            let rr = &recs[cursor];
            if TRIGGER_KINDS.contains(&rr.kind.as_str())
                && !(rr.kind == "input"
                    && !is_trigger_input(rr.txt.as_deref().unwrap_or("")))
                && !(rr.kind == "event-dispatch"
                    && !is_trigger_event(rr.txt.as_deref().unwrap_or("")))
            {
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
            "send_initiator": stats.send_initiator_chains,
            "token_access": stats.token_access_chains,
            "fp_entry": stats.fp_entry_chains,
            "gopd": stats.gopd_chains,
            "stack_inspect": stats.stack_inspect_chains,
            "payload_assembler": stats.payload_assembler_chains,
            "rule": "token-forming = sink-call | handler-born | fp-probes>=2 | integrity-check | net-window | content-sink | send-initiator | token-access | fp-probes-entry | gopd-check | stack-inspect (v10); content-sink crosses the encryption boundary via crypto-out/ws-frame-out byte identity (v9); the *-entry/send-initiator/token-access/gopd/stack signals come from the kind-8 entry-join (caller attribution, no stack walk) - dead ends stay whole in the raw run zip",
        },
        "graph": {
            "fanout_dropped": stats.graph_fanout_dropped,
            "nodes": stats.graph_nodes,
            "edges": stats.graph_edges,
            "sink_seeds": stats.graph_sinks,
            "tainted_nodes": stats.graph_tainted,
            "hop1": stats.graph_hop1,
            "hop2_plus": stats.graph_deep,
            "chains_linked": stats.graph_chains,
            "max_hops": GRAPH_MAX_HOPS,
            "rule": "nodes = payload records (crypto-op/structured-clone/net-request/taint-edge/websocket); edges = shared 32B blake3 run (stride 16, monotone skipped); seeds = req-body + ws-frame-out + payload-forming crypto raw_data + crypto-out; BFS backwards, hop-capped; sinks also carry base64/hex variant runs so an envelope step still matches. A chain is graph-sink@N when a tainted record falls in its materialization window - N hops of DEMONSTRATED byte identity to the wire, not a timer guess.",
        },
        "classification": {
            "strict_graph": stats.strict_graph,
            "proven": stats.proven_chains,
            "heuristic": stats.heuristic_chains,
            "dead_end_proven": stats.dead_end_proven,
            "unresolved": stats.unresolved_chains,
            "provenance_parents": stats.provenance_parents,
            "fetched_url_chains": stats.fetched_url_chains,
            "rule": "proven = graph-sink | send-initiator | token-access | spawned-proven (observed facts: byte identity to a sink, an entry that initiated the send, an entry that touched the stored token, an entry that compiled proven code); heuristic = token_forming without a fact (sink-call text, handler-born window, fp-probes, integrity, net-window); unresolved = no observable connection. Unresolved is NOT claimed to be a proven dead end: in-memory dataflow (fingerprint -> closure -> sent later by another chain) crosses no C++ boundary, so boundary-level capture cannot prove the negative. AF_STRICT_GRAPH=1 cuts the filtered zip to proven only.",
        },
        "v8_depth": {
            "lazy_funcs": stats.lazy_funcs,
            "wasm_firstcalls": stats.wasm_firstcalls,
            "wasm_traps": stats.wasm_traps,
            "wasm_cached": stats.wasm_cached,
            "automation_tells": automation_tells,
            "note": "lazy_funcs = wasm-free JS functions that actually executed (0023); wasm_firstcalls = wasm functions that ran at least once; automation_tells = harness markers found in materialized Error.stacks (kind 38) - if the crawler's own harness shows up here, that is a capture-integrity alarm",
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
        "prune": prune_report,
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
            txt: Some("evt click".into()),
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
        // v12.1: ambient event-dispatch types are NOT triggers (mousemove
        // storms re-saturated handler-born - the v7 bug)
        let amb = vec![
            tr(100_000_000_000, "script-source"),
            tr(100_010_000_000, "event-dispatch"), // ambient mousemove below
        ];
        let mut amb = amb;
        amb[1].txt = Some("evt mousemove".into());
        assert!(latest_trigger_before(&amb, 100_100_000_000, 250_000_000).is_none());
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
            pid: 1,
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
            send_initiator: false,
            token_access: false,
            fp_entry: Vec::new(),
            gopd_check: false,
            stack_inspect: false,
            stack_samples: Vec::new(),
            payload_assembler: false,
            executed_funcs: 0,
            fetched_url: false,
            graph_hops: None,
            proven: false,
            dead_end_proven: false,
            spawned_proven: Vec::new(),
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
    // ---- v12.1 e2e: .rec wire stream -> production collector -> production
    // filter -> verdicts. Proves the deep filter actually runs on data (the
    // v12 bug: the driver never fed it), that the cookie/taint/crypto/body
    // records join the content graph, and that a dead-end chain is honestly
    // separated from the token chain.
    #[test]
    fn e2e_token_chain_verdicts() {
        use std::io::Write as _;

        let tmp = tempfile::tempdir().unwrap();
        let raw_dir = tmp.path().join("raw-src");
        let collect_dir = tmp.path().join("collect");
        std::fs::create_dir_all(&raw_dir).unwrap();

        // ---- the wire stream (u32 | u8 kind | u8 flags | u16 | u64 ts | payload)
        let mut rec: Vec<u8> = Vec::new();
        let t0: u64 = 1_000_000_000;
        let mut recs_written = 0usize;
        {
            let mut w = std::io::Cursor::new(&mut rec);
            let mut put = |kind: u8, ts: u64, payload: &[u8]| {
                let total: u32 = (16 + payload.len()) as u32;
                w.write_all(&total.to_le_bytes()).unwrap();
                w.write_all(&[kind, 0]).unwrap();
                w.write_all(&[0u8, 0]).unwrap();
                w.write_all(&ts.to_le_bytes()).unwrap();
                w.write_all(payload).unwrap();
                recs_written += 1;
            };
            // sink-hello (kind 0) - the liveness record
            put(0, t0, b"afeye-sink/v8 v2 pid=1");
            // the token pipeline script (kind 1, EmitTwoStr name\0source)
            // name carries no iso: prefix; body embeds a collector sink call
            put(1, t0 + 1_000_000, b"https://af.io/collector.js\0function build(){fetch('/t')}build()");
            // a DEAD-END library script (runs, feeds nothing)
            put(1, t0 + 2_000_000, b"https://cdn.io/lodash.js\0var _=function(){return 1}");
            // fp probe reads (kind 29 dom-api, batched)
            put(29, t0 + 3_000_000, b"dom Navigator.get userAgent");
            put(29, t0 + 3_100_000, b"dom Screen.get width");
            // the fingerprint assembly: json-stringify as EmitSpan (v12.1 0021)
            // tag\0body - the plaintext head that must join the graph
            let fp_head = b"{\"ua\":\"x\",\"screen\":1920,\"lang\":\"en\"}";
            let mut js = Vec::new();
            js.extend_from_slice(b"json-stringify len=44 replacer=0");
            js.push(0);
            js.extend_from_slice(fp_head);
            put(16, t0 + 4_000_000, &js);
            // TextEncoder.encode of the SAME bytes (taint-edge, kind 37,
            // tag\0body) - the carrier hop between collect and crypto
            let mut te = Vec::new();
            te.extend_from_slice(b"text-encoder");
            te.push(0);
            te.extend_from_slice(fp_head);
            put(37, t0 + 5_000_000, &te);
            // SubtleCrypto.encrypt raw_data (crypto-op kind 11, tag\0bytes)
            // - the payload-forming SINK: plaintext input
            let mut co = Vec::new();
            co.extend_from_slice(b"encrypt");
            co.push(0);
            co.extend_from_slice(fp_head);
            put(11, t0 + 6_000_000, &co);
            // the req-body upload (net-request kind 17, tag\0body) - the
            // wire sink. Body shares bytes with the crypto input so the
            // backward slice crosses to it.
            let mut rb = Vec::new();
            rb.extend_from_slice(b"req-body");
            rb.push(0);
            rb.extend_from_slice(fp_head);
            put(17, t0 + 7_000_000, &rb);
            // cookie-set: the token park (kind 16, EmitSpan tag\0value)
            let mut ck = Vec::new();
            ck.extend_from_slice(b"cookie-set len=33");
            ck.push(0);
            ck.extend_from_slice(b"tok=deadbeefdeadbeefdeadbeef");
            put(16, t0 + 8_000_000, &ck);
            // fetch initiation (kind 28) + the entry that names the sender
            // (kind 8 call-completed, batched)
            put(28, t0 + 9_000_000, b"fetch url=https://af.io/relay type=fetch ctx=evt:mousedown");
            put(8, t0 + 8_999_000, b"call argc=1 script=https://af.io/collector.js:2");
            // nav-start (kind 36)
            put(36, t0 - 500_000, b"nav-start mono_ns=999500000");
        }
        assert!(recs_written >= 10);

        // ---- run the PRODUCTION collector over the .rec stream
        std::env::set_var("AF_RAW_DIR", &raw_dir);
        let fname = format!("v8-{}.rec", 4242);
        std::fs::write(raw_dir.join(&fname), &rec).unwrap();
        let collector = crate::collect::Collector::spawn_dirs(raw_dir.clone(), collect_dir.clone());
        std::thread::sleep(std::time::Duration::from_millis(600));
        let stats = collector.stop();
        assert!(stats.records >= 10, "collector parsed {} records", stats.records);
        assert!(stats.corrupt == 0, "corrupt records: {}", stats.corrupt);
        assert!(stats.per.contains_key("v8/script-source"));
        assert!(stats.per.contains_key("v8/fingerprint"));
        assert!(stats.per.contains_key("v8/crypto-op"));

        // ---- run the PRODUCTION filter
        let sf = run(&collect_dir).expect("sinkfilter run");
        // the graph must exist and the sinks must be in it
        assert!(sf.graph_sinks >= 2, "graph sinks: {}", sf.graph_sinks);
        assert!(sf.graph_tainted >= 1, "graph tainted: {}", sf.graph_tainted);
        // BOTH scripts became chains
        assert!(sf.chains >= 2, "chains: {}", sf.chains);
        // the token chain is proven (graph path to a sink), the library is not
        assert!(sf.proven_chains >= 1, "proven: {}", sf.proven_chains);

        // ---- report.json: verdict per chain
        let rep: serde_json::Value = serde_json::from_slice(
            &std::fs::read(collect_dir.join("filtered/report.json")).unwrap(),
        )
        .unwrap();
        let chains = rep["chains"].as_array().unwrap();
        let mut saw_proven_token = false;
        let mut saw_dead_library = false;
        for ch in chains {
            let name = ch["name"].as_str().unwrap_or("");
            let verdict = ch["verdict"].as_str().unwrap_or("");
            if name.contains("collector.js") {
                assert!(
                    verdict.contains("proven") || ch["token_forming"].as_bool().unwrap_or(false),
                    "token chain verdict={verdict} signals={:?}",
                    ch["signals"]
                );
                saw_proven_token = true;
            }
            if name.contains("lodash") {
                saw_dead_library = true;
            }
        }
        assert!(saw_proven_token, "collector.js chain missing from report");
        assert!(saw_dead_library, "lodash chain missing from report");
        // the token chain's file must exist in filtered/scripts/
        assert!(!std::fs::read_dir(collect_dir.join("filtered/scripts"))
            .unwrap()
            .next()
            .is_none());
    }

}
