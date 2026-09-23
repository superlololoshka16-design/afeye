
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
    pub fp_reads: u64,
    pub fp_chains: u64,
    pub integrity_checks: u64,
    pub integrity_chains: u64,
    pub wasm_instantiated: u64,
    pub token_chains: u64,
    pub dead_end_chains: u64,
    pub net_adjacent_chains: u64,
    pub content_sink_chains: u64,
    pub prune_paths: u64,
    pub send_initiator_chains: u64,
    pub token_access_chains: u64,
    pub fp_entry_chains: u64,
    pub gopd_chains: u64,
    pub stack_inspect_chains: u64,
    pub automation_tells: u64,
    pub wasm_firstcalls: u64,
    pub wasm_mem_grows: u64,
    pub exec_compiles: u64,
    pub exec_jit: u64,
    pub exec_byte: u64,
    pub exec_wasm_code: u64,
    pub wasm_traps: u64,
    pub wasm_cached: u64,
    pub lazy_funcs: u64,
    pub payload_assembler_chains: u64,
    pub graph_nodes: u64,
    pub graph_edges: u64,
    pub graph_sinks: u64,
    pub graph_tainted: u64,
    pub graph_hop1: u64,
    pub graph_deep: u64,
    pub graph_chains: u64,
    pub graph_entry_chains: u64,
    pub provenance_parents: u64,
    pub fetched_url_chains: u64,
    pub proven_chains: u64,
    pub heuristic_chains: u64,
    pub unresolved_chains: u64,
    pub dead_end_proven: u64,
    pub taint_sink_chains: u64,
    pub taint_swept_union: u64,
    pub taint_deadend_union: u64,
    pub graph_distinct_keys: u64,
    pub graph_fanout_dropped: u64,
    pub strict_graph: bool,
}

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
];

const FP_API_NEEDLES: &[&str] = &[
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
    "Screen.get width",
    "Screen.get height",
    "Screen.get colorDepth",
    "Screen.get pixelDepth",
    "Screen.get availLeft",
    "Screen.get availTop",
    "Screen.get availWidth",
    "Screen.get availHeight",
    "Document.get cookie",
    "getParameter",
    "getExtension",
    "getShaderPrecisionFormat",
    "toDataURL",
    "toBlob",
    "getImageData",
    "measureText",
    "getBoundingClientRect",
    "getClientRects",
    "getChannelData",
    "createOffer",
    "createDataChannel",
    "enumerateDevices",
    "getGamepads",
    "getBattery",
];

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

struct FpRead {
    ts: u64,
    needle: &'static str,
}

const FP_GRACE_NS: u64 = 50_000_000;
const NET_FP_WINDOW_NS: u64 = 5_000_000_000;
const WASM_INST_WINDOW_NS: u64 = 5_000_000_000;

const CONTENT_RUN_BYTES: usize = 32;
const CONTENT_RUN_STEP: usize = 16;
const CONTENT_MAX_RUNS: usize = 8192;
const CONTENT_LINK_GRACE_NS: u64 = 200_000_000;
const CONTENT_MAX_RECORDS: usize = 50_000;

const GRAPH_MAX_EDGES: usize = 8_000_000;
const GRAPH_MAX_HOPS: u32 = 6;
const VARIANT_MIN_BYTES: usize = 64;
const VARIANT_MAX_SINKS: usize = 4_096;
const QUERY_SINK_MIN_BYTES: usize = 96;
const HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
];
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
    off: Option<u64>,
    txt: Option<String>,
}

fn read_payload(raw_dir: &Path, r: &Rec) -> Option<Vec<u8>> {
    let b = fs::read(raw_dir.join(&r.path)).ok()?;
    let start = r.off.unwrap_or(0) as usize;
    if start == 0 && b.len() == r.len as usize {
        return Some(b);
    }
    let end = start.checked_add(r.len as usize)?;
    Some(b.get(start..end)?.to_vec())
}


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

fn value_of_prose(payload: &[u8]) -> Option<(String, Vec<u8>)> {
    let t = std::str::from_utf8(payload).ok()?;
    for tag in ["cookie-get", "cookie-set"] {
        if let Some(rest) = t.strip_prefix(tag) {
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
        if let Some(hp) = rest.find(" head=") {
            let v = &rest[hp + 6..];
            if !v.is_empty() {
                return Some(("json-stringify".to_string(), v.as_bytes().to_vec()));
            }
        }
        return None;
    }
    for tag in ["webgl/unmasked-vendor", "webgl/unmasked-renderer", "webgl/param"] {
        if let Some(rest) = t.strip_prefix(tag) {
            if let Some(vp) = rest.find(" val=") {
                let v = &rest[vp + 5..];
                if !v.is_empty() {
                    return Some((tag.to_string(), v.as_bytes().to_vec()));
                }
            }
            return None;
        }
    }
    if let Some(rest) = t.strip_prefix("canvas/measure-r") {
        if let Some(wp) = rest.find(" w=") {
            let v = &rest[wp + 3..];
            if !v.is_empty() {
                return Some(("canvas/measure-r".to_string(), v.as_bytes().to_vec()));
            }
        }
        return None;
    }
    None
}

fn split_iso(name: &str) -> (Option<String>, String) {
    if let Some(rest) = name.strip_prefix("iso:") {
        if let Some(sp) = rest.find(' ') {
            return (Some(rest[..sp].to_string()), rest[sp + 1..].to_string());
        }
    }
    (None, name.to_string())
}

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
    if body.windows(13).any(|w| w == b"afeye-harness") {
        return false;
    }
    if name.contains("afeye-harness") {
        return false;
    }

    if name.starts_with("evt:") || name.starts_with("timer:") {
        return true;
    }
    let head = &body[..body.len().min(1 << 20)];
    let s = String::from_utf8_lossy(head);
    HOT_PATTERNS.iter().any(|p| s.contains(p))
}

fn overlaps_net_window(net_ts: &[u64], first_ts: u64, last_ts: u64) -> bool {
    let lo = first_ts;
    let hi = last_ts
        .saturating_add(FP_GRACE_NS)
        .saturating_add(NET_FP_WINDOW_NS);
    let a = net_ts.partition_point(|t| *t < lo);
    a < net_ts.len() && net_ts[a] <= hi
}

fn overlaps_content_bridge(content_ts: &[u64], first_ts: u64, last_ts: u64) -> bool {
    let lo = first_ts.saturating_sub(CONTENT_LINK_GRACE_NS);
    let hi = last_ts
        .saturating_add(FP_GRACE_NS)
        .saturating_add(CONTENT_LINK_GRACE_NS);
    let a = content_ts.partition_point(|t| *t < lo);
    a < content_ts.len() && content_ts[a] <= hi
}

fn drops_witnessed(drop_events: &[(u64, u64, u64)], _pid: u64, ts: u64) -> bool {
    let horizon = ts.saturating_add(500_000_000);
    drop_events
        .iter()
        .any(|(dts, _dpid, n)| *dts <= horizon && *n > 0)
}

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

fn is_monotone(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(|&x| x == b[0])
}


fn run_keys(body: &[u8]) -> Vec<u64> {
    let key = |b: &[u8]| -> u64 {
        let h = blake3::hash(b).as_bytes()[..8].to_vec();
        u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]])
    };
    let mut out: Vec<u64> = Vec::new();
    if body.len() < 2 * CONTENT_RUN_BYTES {
        if body.is_empty() {
            return out;
        }
        if is_monotone(body) {
            return out;
        }
        for off in 0..body.len() {
            let win = &body[off..];
            if !is_monotone(win) {
                out.push(key(win));
            }
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

fn hex_bytes(b: &[u8]) -> Vec<u8> {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(b.len() * 2);
    for &x in b {
        out.push(H[(x >> 4) as usize]);
        out.push(H[(x & 0xf) as usize]);
    }
    out
}

fn decode_custom_alphabet(body: &[u8], alpha: &[u8]) -> Option<Vec<u8>> {
    if alpha.len() < 64 || body.len() < VARIANT_MIN_BYTES {
        return None;
    }
    let mut tbl = [255u8; 256];
    for (i, &c) in alpha[..64].iter().enumerate() {
        if tbl[c as usize] != 255 {
            return None;
        }
        tbl[c as usize] = i as u8;
    }
    if !body.iter().all(|&b| tbl[b as usize] != 255) {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4 + 8);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in body {
        acc = (acc << 6) | tbl[b as usize] as u32;
        nbits += 6;
        while nbits >= 8 {
            nbits -= 8;
            out.push(((acc >> nbits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn extract_alphabets(script: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let len = script.len();
    let mut i = 0usize;
    while i + 60 <= len {
        let q = match script[i] {
            b'"' | b'\'' | b'`' => script[i],
            _ => {
                i += 1;
                continue;
            }
        };
        let start = i + 1;
        let mut j = start;
        while j < len && (j - start) < 72 {
            let c = script[j];
            if c == q {
                break;
            }
            if !(c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'$' | b'-')) {
                break;
            }
            j += 1;
        }
        let l = j - start;
        if j < len && script[j] == q && (60..=72).contains(&l) {
            let mut seen = [false; 256];
            let mut distinct = 0usize;
            for &c in &script[start..j] {
                if !seen[c as usize] {
                    seen[c as usize] = true;
                    distinct += 1;
                }
            }
            if distinct >= 60 {
                out.push(script[start..j].to_vec());
            }
        }
        i = j + 1;
    }
    out
}

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
    let content_sink = overlaps_content_bridge(content_ts, c.first_ts, c.last_ts);
    if content_sink {
        signals.push("content-sink".into());
    }
    if c.send_initiator {
        signals.push("send-initiator".into());
    }
    if c.token_access {
        signals.push("token-access".into());
    }
    if !c.fp_entry.is_empty() {
        signals.push("fp-probes-entry".into());
    }
    if c.gopd_check {
        signals.push("gopd-check".into());
    }
    if c.stack_inspect {
        signals.push("stack-inspect".into());
    }
    if !c.spawned_proven.is_empty() {
        signals.push("spawned-proven".into());
    }
    if let Some(h) = c.graph_entry {
        signals.push(format!("graph-entry@{h}"));
    }
    if c.taint_sink {
        signals.push("taint-sink".into());
    }
    if let Some(h) = c.graph_hops {
        signals.push(format!("graph-sink@{h}"));
    }
    (signals, net_adjacent, content_sink)
}


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


struct Chain {
    file: Option<std::fs::File>,
    pid: u64,
    name: String,
    frags: u64,
    bytes: u64,
    hot: bool,
    hot_pattern: bool,
    first_ts: u64,
    last_ts: u64,
    path: String,
    trigger: Option<TriggerRef>,
    iso: Option<String>,
    worker: Option<String>,
    fp_reads: Vec<String>,
    integrity: u64,
    integrity_samples: Vec<String>,
    clock_reads: u64,
    token_forming: bool,
    signals: Vec<String>,
    net_adjacent: bool,
    content_sink: bool,
    send_initiator: bool,
    token_access: bool,
    fp_entry: Vec<String>,
    gopd_check: bool,
    stack_inspect: bool,
    stack_samples: Vec<String>,
    payload_assembler: bool,
    executed_funcs: u64,
    graph_hops: Option<u32>,
    graph_entry: Option<u32>,
    taint_sink: bool,
    proven: bool,
    dead_end_proven: bool,
    fetched_url: bool,
    spawned_proven: Vec<String>,
}

#[derive(Debug, Clone)]
struct TriggerRef {
    kind: String,
    ts: u64,
    what: String,
}

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

fn is_trigger_input(txt: &str) -> bool {
    if let Some(rest) = txt.strip_prefix("input/mouse ") {
        let etype = rest.split(' ').next().unwrap_or("");
        return etype != "mousemove";
    }
    if let Some(rest) = txt.strip_prefix("input/raw type=") {
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

fn latest_trigger_before(recs: &[Rec], ts: u64, window_ns: u64) -> Option<TriggerRef> {
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
            break;
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

fn fp_needle_of(txt: &str) -> Option<&'static str> {
    FP_API_NEEDLES.iter().copied().find(|n| txt.contains(n))
}


const ENTRY_JOIN_WINDOW_NS: u64 = 250_000_000;

struct EntryIndex {
    per_pid: HashMap<u64, Vec<usize>>,
}

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
                if !txt.starts_with("lazy-compile") && entry_script_of(txt).is_some() {
                    per_pid.entry(r.pid).or_default().push(i);
                }
            }
        }
    }
    EntryIndex { per_pid }
}

impl EntryIndex {
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

struct InputCadence {
    total: u64,
    per_type: BTreeMap<String, u64>,
    median_delta_us: Option<u64>,
    p90_delta_us: Option<u64>,
    path_px: u64,
    span_ms: u64,
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
            deltas.push((r.ts - prev_ts) / 1000);
        }
        prev_ts = r.ts;
        last_ts = r.ts;
        if let Some((x, y)) = xy {
            if let Some((px, py)) = prev_xy {
                path_px += ((x - px) * (x - px) + (y - py) * (y - py)).sqrt();
            }
            prev_xy = Some((x, y));
        }
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
    let raw_dir = collect_dir.to_path_buf();
    let mut stats = SinkFilterStats {
        keep_cold: std::env::var("AF_SINK_KEEP_COLD").map(|v| v == "1").unwrap_or(false),
        ..Default::default()
    };
    let index = match fs::read_to_string(&index_p) {
        Ok(s) => s,
        Err(_) => return Ok(stats),
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

    let mut fp_reads: Vec<FpRead> = Vec::new();
    let mut fnts: Vec<(u64, String)> = Vec::new();
    let mut clock_ts: Vec<u64> = Vec::new();
    let mut workers: Vec<(u64, String, String)> = Vec::new();
    let mut wasm_inst: Vec<(u64, u64, bool, String)> = Vec::new();
    let mut wasm_firstcalls = 0u64;
    let mut wasm_mem_grows = 0u64;
    let mut exec_compiles = 0u64;
    let mut exec_per_name: HashMap<String, u64> = HashMap::new();
    let mut exec_jit = 0u64;
    let mut exec_byte = 0u64;
    let mut exec_wasm_code = 0u64;
    let mut wasm_traps = 0u64;
    let mut automation_tells: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut taint_swept_union: u64 = 0;
    let mut taint_deadend_union: u64 = 0;
    let mut drop_events: Vec<(u64, u64, u64)> = Vec::new();
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
            "sink-drop" => {
                if let Some(n) = txt.split("dropped=").nth(1) {
                    if let Ok(n) = n.trim().parse::<u64>() {
                        drop_events.push((r.ts, r.pid, n));
                    }
                }
            }
            "fingerprint" if txt.starts_with("taint-swept tag=") => {
                if let Some(h) = txt.split("tag=").nth(1) {
                    if let Ok(v) = u64::from_str_radix(h.trim(), 16) {
                        taint_swept_union |= v;
                    }
                }
            }
            "fingerprint" if txt.starts_with("taint-deadend tag=") => {
                if let Some(h) = txt.split("tag=").nth(1) {
                    if let Ok(v) = u64::from_str_radix(h.trim(), 16) {
                        taint_deadend_union |= v;
                    }
                }
            }
            "isolate" => {
                if txt.starts_with("exec ") {
                    exec_compiles += 1;
                    if txt.starts_with("exec jit ") {
                        exec_jit += 1;
                    } else if txt.starts_with("exec byte ") {
                        exec_byte += 1;
                    } else if txt.starts_with("exec wasm ") {
                        exec_wasm_code += 1;
                    }
                    if let Some(sp) = txt.find(" script=") {
                        let script_part = &txt[sp + 8..];
                        let end = script_part.find(" len=").unwrap_or(script_part.len());
                        let script_name = &script_part[..end];
                        let bare = match script_name.rfind(':') {
                            Some(c) if script_name[c + 1..]
                                .chars()
                                .all(|d| d.is_ascii_digit()) => &script_name[..c],
                            _ => script_name,
                        };
                        let (_, bare) = split_iso(bare);
                        *exec_per_name.entry(bare.to_string()).or_insert(0u64) += 1;
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
                if txt.starts_with("wasm-firstcall ") {
                    wasm_firstcalls += 1;
                } else if txt.starts_with("wasm-trap ") {
                    wasm_traps += 1;
                } else if txt.starts_with("wasm-mem grow ") {
                    wasm_mem_grows += 1;
                }
            }
            "error-stack" => {
                for marker in AUTOMATION_MARKERS {
                    if txt.contains(marker) {
                        *automation_tells.entry(*marker).or_insert(0) += 1;
                    }
                }
            }
            "nav-start" => {
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
    stats.wasm_firstcalls = wasm_firstcalls;
    stats.wasm_mem_grows = wasm_mem_grows;
    stats.exec_compiles = exec_compiles;
    stats.exec_jit = exec_jit;
    stats.exec_byte = exec_byte;
    stats.exec_wasm_code = exec_wasm_code;
    stats.wasm_traps = wasm_traps;
    stats.automation_tells = automation_tells.values().sum();
    stats.taint_swept_union = taint_swept_union;
    stats.taint_deadend_union = taint_deadend_union;

    let mut chains: HashMap<(u64, String, String), usize> = HashMap::new();
    let mut chain_list: Vec<Chain> = Vec::new();
    let mut wasm_index: Vec<serde_json::Value> = Vec::new();
    let mut wasm_seen: HashMap<String, ()> = HashMap::new();

    for r in &recs {
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
                        graph_entry: None,
                        taint_sink: false,
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
                    let mut resolved: Vec<String> = Vec::new();
                    for (ts, pid, header, txt) in wasm_inst.iter() {
                        if *pid != r.pid || *ts <= *hts || *ts > *hts + WASM_INST_WINDOW_NS {
                            continue;
                        }
                        if *header {
                            break;
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

    let payload_kinds = [
        "crypto-op",
        "structured-clone",
        "net-request",
        "taint-edge",
        "websocket",
        "wasm-memory",
        "fingerprint",
    ];
    const VALUE_TAGS: &[&str] = &[
        "cookie-get",
        "cookie-set",
        "storage-get",
        "storage-set",
        "canvas/get-image-data-r",
        "webgl/read-pixels-r",
        "audio/float-frequency",
        "audio/byte-frequency",
        "audio/float-timedomain",
        "audio/byte-timedomain",
        "json-stringify",
        "webgl/unmasked-vendor",
        "webgl/unmasked-renderer",
        "webgl/param",
        "canvas/measure-r",
    ];

    struct GraphNode {
        ts: u64,
        pid: u64,
        sink: bool,
        keys: Vec<u64>,
    }

    let mut alphabets_by_pid: HashMap<u64, Vec<Vec<u8>>> = HashMap::new();
    for r in recs.iter().filter(|r| r.kind == "script-source") {
        if let Some(p) = read_payload(&raw_dir, r) {
            let (_, body) = name_of(&p);
            for alpha in extract_alphabets(&body) {
                alphabets_by_pid
                    .entry(r.pid)
                    .or_default()
                    .push(alpha);
            }
        }
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
        if r.kind == "fingerprint" && tag.is_empty() {
            if let Some((t2, b2)) = value_of_prose(&payload) {
                tag = t2;
                body = b2;
            }
        }
        if body.is_empty() {
            continue;
        }
        if r.kind == "fingerprint" && !VALUE_TAGS.iter().any(|t| tag.starts_with(t)) {
            continue;
        }
        let is_crypto_sink = r.kind == "crypto-op"
            && SINK_CRYPTO_OPS.iter().any(|o| tag.contains(o));
        let is_upload = r.kind == "net-request"
            && (tag == "req-body" || tag == "req-body-stream");
        let query_len = body
            .iter()
            .position(|&c| c == b'?')
            .map(|q| body.len() - q - 1)
            .unwrap_or(0);
        let is_query_sink = r.kind == "net-request"
            && HTTP_METHODS.contains(&tag.as_str())
            && (query_len >= QUERY_SINK_MIN_BYTES
                || af_vendor_of_url(&String::from_utf8_lossy(&body)).is_some());
        let is_ws_sink = r.kind == "websocket" && tag == "ws-frame-out";
        let sink = is_crypto_sink || is_upload || is_ws_sink || is_query_sink;

        if !sink {
            if carriers_seen >= CONTENT_MAX_RECORDS || total_keys >= GRAPH_MAX_EDGES {
                continue;
            }
            carriers_seen += 1;
        } else if total_keys >= GRAPH_MAX_EDGES {
            nodes.push(GraphNode { ts: r.ts, pid: r.pid, sink: true, keys: Vec::new() });
            continue;
        }

        let mut keys = run_keys(&body);
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
                if let Some(alphas) = alphabets_by_pid.get(&r.pid) {
                    for alpha in alphas {
                        if let Some(decoded) = decode_custom_alphabet(&body, alpha) {
                            vk.extend(run_keys(&decoded));
                        }
                    }
                }
                vk.truncate(room.min(vk.len()));
                total_keys += vk.len();
                keys.extend(vk);
            }
        }
        if keys.len() > CONTENT_MAX_RUNS {
            keys.truncate(CONTENT_MAX_RUNS);
        }
        keys.sort_unstable();
        keys.dedup();
        total_keys += keys.len();
        nodes.push(GraphNode { ts: r.ts, pid: r.pid, sink, keys });
    }

    let mut adj_keys: Vec<u64> = Vec::new();
    let mut adj_off: Vec<u32> = Vec::new();
    let mut adj_nodes: Vec<u32> = Vec::new();
    {
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

    const GRAPH_MAX_FANOUT: usize = 4096;

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

    let mut graph_ts: Vec<(u64, u32)> = Vec::new();
    let mut tainted_positions: Vec<(u64, u64, u32)> = Vec::new();
    let mut tainted_nodes = 0usize;
    let mut hop_hist: BTreeMap<u32, u64> = BTreeMap::new();
    for (ni, n) in nodes.iter().enumerate() {
        if dist[ni] != u32::MAX {
            tainted_nodes += 1;
            graph_ts.push((n.ts, dist[ni]));
            tainted_positions.push((n.pid, n.ts, dist[ni]));
            *hop_hist.entry(dist[ni]).or_insert(0) += 1;
        }
    }
    graph_ts.sort_unstable();
    stats.graph_nodes = nodes.len() as u64;
    stats.graph_sinks = seed_count as u64;
    stats.graph_tainted = tainted_nodes as u64;
    stats.graph_hop1 = hop_hist.get(&1).copied().unwrap_or(0);
    stats.graph_deep = hop_hist.iter().filter(|(h, _)| **h >= 2).map(|(_, n)| *n).sum();

    let mut content_ts: Vec<u64> = graph_ts
        .iter()
        .filter(|(_, h)| *h <= 1)
        .map(|(t, _)| *t)
        .collect();
    content_ts.dedup();

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

    let entry_index = build_entry_index(&recs);

    let mut name_to_chain: HashMap<(u64, String), usize> = HashMap::new();
    for (idx, c) in chain_list.iter().enumerate() {
        if !c.name.is_empty() {
            name_to_chain
                .entry((c.pid, canon_name(&c.name)))
                .or_insert(idx);
        }
    }
    let mut graph_entry_hops: HashMap<usize, u32> = HashMap::new();
    for (pid, ts, hop) in &tainted_positions {
        if let Some(script) = entry_index.script_at(&recs, *pid, *ts) {
            let (_, bare) = split_iso(script);
            if let Some(idx) = name_to_chain.get(&(*pid, canon_name(&bare))) {
                let e = graph_entry_hops.entry(*idx).or_insert(*hop);
                if *hop < *e {
                    *e = *hop;
                }
            }
        }
    }

    let mut send_init: HashSet<usize> = HashSet::new();
    let mut tok_access: HashSet<usize> = HashSet::new();
    let mut taint_sink_set: HashSet<usize> = HashSet::new();
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
        let (_, bare) = split_iso(script);
        let idx = match name_to_chain.get(&(r.pid, canon_name(&bare))) {
            Some(i) => *i,
            None => continue,
        };
        let txt = r.txt.as_deref().unwrap_or("");
        match r.kind.as_str() {
            "fetch" => {
                send_init.insert(idx);
            }
            "fingerprint" if txt.starts_with("json-stringify ") => {
                assembler_chains.insert(idx);
            }
            "fingerprint" if txt.starts_with("taint-sink ") => {
                taint_sink_set.insert(idx);
            }
            "fingerprint" => {
                if txt.starts_with("cookie-get")
                    || txt.starts_with("cookie-set")
                    || txt.starts_with("storage-get")
                    || txt.starts_with("storage-set")
                {
                    tok_access.insert(idx);
                }
            }
            "dom-api" => {
                if let Some(needle) = fp_needle_of(txt) {
                    let v = fp_entry.entry(idx).or_default();
                    if !v.contains(&needle) {
                        v.push(needle);
                    }
                }
            }
            "error-stack" => {
                stack_chains.insert(idx);
                let v = stack_samples.entry(idx).or_default();
                if v.len() < 4 {
                    v.push(txt_head(txt, 240));
                }
            }
            _ => {}
        }
        if r.kind == "fingerprint" && txt.starts_with("gopd ") {
            gopd_chains.insert(idx);
        }
    }
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
    for idx in taint_sink_set {
        if let Some(c) = chain_list.get_mut(idx) {
            c.taint_sink = true;
            stats.taint_sink_chains += 1;
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
            if let Some(n) = exec_per_name.get(c.name.as_str()) {
                if *n > c.executed_funcs {
                    c.executed_funcs = *n;
                }
            }
        }
    }

    for c in &mut chain_list {
        c.graph_hops = graph_hops_for(&graph_ts, c.first_ts, c.last_ts);
    }

    for (idx, hop) in graph_entry_hops {
        if let Some(c) = chain_list.get_mut(idx) {
            match c.graph_entry {
                Some(h) if h <= hop => {}
                _ => c.graph_entry = Some(hop),
            }
            stats.graph_entry_chains += 1;
        }
    }

    for c in &mut chain_list {
        c.proven = c.graph_hops.is_some()
            || c.graph_entry.is_some()
            || c.send_initiator
            || c.token_access
            || c.taint_sink;
    }

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
    let keep_big = std::env::var("AF_KEEP_BIG").map(|v| v == "1").unwrap_or(false);
    for c in &mut chain_list {
        let keep = c.hot || c.token_forming || stats.keep_cold || (keep_big && c.bytes as usize >= big_keep);
        if keep {
            hot += 1;
        } else {
            cold += 1;
        }
        if let Some(f) = c.file.as_mut() {
            let _ = f.sync_all();
        }
        stats.chain_bytes += c.bytes;
    }
    stats.chains = chain_list.len() as u64;
    stats.hot_chains = hot as u64;
    stats.cold_chains = cold as u64;

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
        if c.taint_sink {
            entry["taint_sink"] = json!(true);
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
        if let Some(h) = c.graph_entry {
            entry["graph_entry"] = json!(h);
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

    let cadence = build_input_cadence(&recs);

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
            "chains_entry_linked": stats.graph_entry_chains,
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
            "taint_sink_chains": stats.taint_sink_chains,
            "taint_swept_union": stats.taint_swept_union,
            "taint_deadend_union": stats.taint_deadend_union,
            "rule": "proven = graph-sink | graph-entry | send-initiator | token-access | spawned-proven (observed facts: byte identity to a sink within the window, byte identity + entry attribution when the tainted record is outside the window, an entry that initiated the send, an entry that touched the stored token, an entry that compiled proven code); heuristic = token_forming without a fact (sink-call text, handler-born window, fp-probes, integrity, net-window); dead-end-proven = no link AND a completeness witness (zero sink-ring drops in this pid, 0023 kind 39); unresolved = no link and NO witness - capture may have dropped the evidence. In-memory dataflow (fingerprint -> closure -> sent later by another chain) crosses no C++ boundary, so it can never be linked by bytes: such chains stay unresolved or dead-end-proven, never silently dropped as fact. AF_STRICT_GRAPH=1 cuts the filtered zip to proven only.",
        },
        "v8_depth": {
            "lazy_funcs": stats.lazy_funcs,
            "exec_compiles": stats.exec_compiles,
            "exec_jit": stats.exec_jit,
            "exec_byte": stats.exec_byte,
            "exec_wasm_code": stats.exec_wasm_code,
            "wasm_firstcalls": stats.wasm_firstcalls,
            "wasm_traps": stats.wasm_traps,
            "wasm_cached": stats.wasm_cached,
            "wasm_mem_grows": stats.wasm_mem_grows,
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
            None
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
        let mut recs = vec![
            tr(100_000_000_000, "script-source"),
            tr(100_010_000_000, "event-dispatch"),
            tr(100_200_000_000, "script-source"),
        ];
        recs.sort_by_key(|r| r.ts);
        let t = latest_trigger_before(&recs, 100_100_000_000, 250_000_000).unwrap();
        assert_eq!(t.kind, "event-dispatch");
        assert!(latest_trigger_before(&recs, 100_410_000_000, 250_000_000).is_none());
        assert!(latest_trigger_before(&recs, 10, 250_000_000).is_none());
        let amb = vec![
            tr(100_000_000_000, "script-source"),
            tr(100_010_000_000, "event-dispatch"),
        ];
        let mut amb = amb;
        amb[1].txt = Some("evt mousemove".into());
        assert!(latest_trigger_before(&amb, 100_100_000_000, 250_000_000).is_none());
    }

    #[test]
    fn net_window_overlap() {
        let net_ts = vec![100_000_000_000u64];
        assert!(overlaps_net_window(&net_ts, 99_000_000_000, 99_900_000_000));
        assert!(!overlaps_net_window(&net_ts, 89_000_000_000, 89_900_000_000));
        assert!(overlaps_net_window(&net_ts, 10_000_000_000, 98_000_000_000));
        assert!(!overlaps_net_window(&net_ts, 101_000_000_000, 102_000_000_000));
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
            graph_entry: None,
            taint_sink: false,
            proven: false,
            dead_end_proven: false,
            spawned_proven: Vec::new(),
        }
    }

    #[test]
    fn dead_end_classification() {
        let c = chain_with(false, false, 0, 0);
        let (s, net, content) = chain_signals(&c, &[], &[]);
        assert!(s.is_empty());
        assert!(!net);
        assert!(!content);

        let c = chain_with(true, false, 0, 0);
        let (s, _, _) = chain_signals(&c, &[], &[]);
        assert_eq!(s, vec!["sink-call".to_string()]);

        let c = chain_with(false, true, 0, 0);
        let (s, _, _) = chain_signals(&c, &[], &[]);
        assert_eq!(s, vec!["handler-born".to_string()]);

        let c = chain_with(false, false, 2, 0);
        let (s, _, _) = chain_signals(&c, &[], &[]);
        assert_eq!(s, vec!["fp-probes".to_string()]);
        let c = chain_with(false, false, 1, 0);
        let (s, _, _) = chain_signals(&c, &[], &[]);
        assert!(s.is_empty());

        let c = chain_with(false, false, 0, 3);
        let (s, _, _) = chain_signals(&c, &[], &[]);
        assert_eq!(s, vec!["integrity-check".to_string()]);

        let c = chain_with(false, false, 0, 0);
        let net_ts = vec![100_000];
        let (s, net, _) = chain_signals(&c, &net_ts, &[]);
        assert_eq!(s, vec!["net-window".to_string()]);
        assert!(net);
    }
    #[test]
    fn e2e_token_chain_verdicts() {
        use std::io::Write as _;

        let tmp = tempfile::tempdir().unwrap();
        let raw_dir = tmp.path().join("raw-src");
        let collect_dir = tmp.path().join("collect");
        std::fs::create_dir_all(&raw_dir).unwrap();

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
            put(0, t0, b"afeye-sink/v8 v2 pid=1");
            put(1, t0 + 1_000_000, b"https://af.io/collector.js\0function build(){fetch('/t')}build()");
            put(1, t0 + 2_000_000, b"https://cdn.io/lodash.js\0var _=function(){return 1}");
            put(29, t0 + 3_000_000, b"dom Navigator.get userAgent");
            put(29, t0 + 3_100_000, b"dom Screen.get width");
            let fp_head = b"{\"ua\":\"x\",\"screen\":1920,\"lang\":\"en\"}";
            let mut js = Vec::new();
            js.extend_from_slice(b"json-stringify len=44 replacer=0");
            js.push(0);
            js.extend_from_slice(fp_head);
            put(16, t0 + 4_000_000, &js);
            let mut te = Vec::new();
            te.extend_from_slice(b"text-encoder");
            te.push(0);
            te.extend_from_slice(fp_head);
            put(37, t0 + 5_000_000, &te);
            let mut co = Vec::new();
            co.extend_from_slice(b"encrypt");
            co.push(0);
            co.extend_from_slice(fp_head);
            put(11, t0 + 6_000_000, &co);
            let mut rb = Vec::new();
            rb.extend_from_slice(b"req-body");
            rb.push(0);
            rb.extend_from_slice(fp_head);
            put(17, t0 + 7_000_000, &rb);
            let mut ck = Vec::new();
            ck.extend_from_slice(b"cookie-set len=33");
            ck.push(0);
            ck.extend_from_slice(b"tok=deadbeefdeadbeefdeadbeef");
            put(16, t0 + 8_000_000, &ck);
            put(28, t0 + 9_000_000, b"fetch url=https://af.io/relay type=fetch ctx=evt:mousedown");
            put(8, t0 + 8_999_000, b"call argc=1 script=https://af.io/collector.js:2");
            put(36, t0 - 500_000, b"nav-start mono_ns=999500000");
        }
        assert!(recs_written >= 10);

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

        let sf = run(&collect_dir).expect("sinkfilter run");
        assert!(sf.graph_sinks >= 2, "graph sinks: {}", sf.graph_sinks);
        assert!(sf.graph_tainted >= 1, "graph tainted: {}", sf.graph_tainted);
        assert!(sf.chains >= 2, "chains: {}", sf.chains);
        assert!(sf.proven_chains >= 1, "proven: {}", sf.proven_chains);

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
        assert!(!std::fs::read_dir(collect_dir.join("filtered/scripts"))
            .unwrap()
            .next()
            .is_none());
    }

    #[test]
    fn e2e_custom_alphabet_bridge() {
        use std::io::Write as _;

        let tmp = tempfile::tempdir().unwrap();
        let raw_dir = tmp.path().join("raw-src");
        let collect_dir = tmp.path().join("collect");
        std::fs::create_dir_all(&raw_dir).unwrap();

        let alpha: &[u8] =
            b"y1+jUndxLt$pzuJcoK3k7hCqWBi2Ofsl-MQT0wXRaIgPENrVFSbAm6eG5HZvYD498";
        assert_eq!(alpha.len(), 65);
        let a64 = &alpha[..64];

        let mut plain: Vec<u8> = Vec::with_capacity(96);
        let mut x: u32 = 0x12345678;
        for _ in 0..96 {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            plain.push((x >> 24) as u8);
        }
        let mut wire: Vec<u8> = Vec::new();
        let mut acc: u32 = 0;
        let mut nbits: u32 = 0;
        for &b in &plain {
            acc = (acc << 8) | b as u32;
            nbits += 8;
            while nbits >= 6 {
                nbits -= 6;
                wire.push(a64[((acc >> nbits) & 63) as usize]);
            }
        }
        if nbits > 0 {
            wire.push(a64[((acc << (6 - nbits)) & 63) as usize]);
        }
        assert!(wire.len() >= VARIANT_MIN_BYTES);

        let mut rec: Vec<u8> = Vec::new();
        let t0: u64 = 2_000_000_000;
        {
            let mut w = std::io::Cursor::new(&mut rec);
            let mut put = |kind: u8, ts: u64, payload: &[u8]| {
                let total: u32 = (16 + payload.len()) as u32;
                w.write_all(&total.to_le_bytes()).unwrap();
                w.write_all(&[kind, 0]).unwrap();
                w.write_all(&[0u8, 0]).unwrap();
                w.write_all(&ts.to_le_bytes()).unwrap();
                w.write_all(payload).unwrap();
            };
            put(0, t0, b"afeye-sink/v8 v2 pid=7");
            let mut script: Vec<u8> = Vec::new();
            script.extend_from_slice(b"https://cf.io/challenge.js\x00var A=\"");
            script.extend_from_slice(alpha);
            script.extend_from_slice(b"\";var s=1;");
            put(1, t0 + 1_000_000, &script);
            let mut co: Vec<u8> = Vec::new();
            co.extend_from_slice(b"encrypt\x00");
            co.extend_from_slice(&plain);
            put(11, t0 + 2_000_000, &co);
            let mut rb: Vec<u8> = Vec::new();
            rb.extend_from_slice(b"req-body\x00");
            rb.extend_from_slice(&wire);
            put(17, t0 + 3_000_000, &rb);
        }

        std::env::set_var("AF_RAW_DIR", &raw_dir);
        std::fs::write(raw_dir.join("v8-777.rec"), &rec).unwrap();
        let collector = crate::collect::Collector::spawn_dirs(raw_dir.clone(), collect_dir.clone());
        std::thread::sleep(std::time::Duration::from_millis(600));
        let stats = collector.stop();
        assert!(stats.records >= 4, "records: {}", stats.records);

        let sf = run(&collect_dir).expect("sinkfilter run");
        assert!(sf.graph_sinks >= 1, "sinks: {}", sf.graph_sinks);
        assert!(
            sf.graph_tainted >= 1,
            "carrier not tainted: sinks={} tainted={} - alphabet bridge failed",
            sf.graph_sinks,
            sf.graph_tainted
        );
    }

    #[test]
    fn dtt_taint_sink_verdict() {
        use std::io::Write as _;

        let tmp = tempfile::tempdir().unwrap();
        let raw_dir = tmp.path().join("raw-src");
        let collect_dir = tmp.path().join("collect");
        std::fs::create_dir_all(&raw_dir).unwrap();

        let mut rec: Vec<u8> = Vec::new();
        let t0: u64 = 2_000_000_000;
        {
            let mut w = std::io::Cursor::new(&mut rec);
            let mut put = |kind: u8, ts: u64, payload: &[u8]| {
                let total: u32 = (16 + payload.len()) as u32;
                w.write_all(&total.to_le_bytes()).unwrap();
                w.write_all(&[kind, 0]).unwrap();
                w.write_all(&[0u8, 0]).unwrap();
                w.write_all(&ts.to_le_bytes()).unwrap();
                w.write_all(payload).unwrap();
            };
            put(0, t0, b"afeye-sink/v8 v2 pid=1");
            put(36, t0 - 500_000, b"nav-start mono_ns=1999500000");
            put(1, t0 + 1_000_000,
                b"https://af.io/collector.js\0function build(){fetch('/t')}build()");
            put(8, t0 + 2_999_000,
                b"call argc=1 script=https://af.io/collector.js:2");
            put(16, t0 + 3_000_000,
                b"taint-sink socket-write space=0 key=7f3a tag=1");
        }

        std::env::set_var("AF_RAW_DIR", &raw_dir);
        std::fs::write(raw_dir.join("v8-99.rec"), &rec).unwrap();
        let collector =
            crate::collect::Collector::spawn_dirs(raw_dir.clone(), collect_dir.clone());
        std::thread::sleep(std::time::Duration::from_millis(600));
        let cstats = collector.stop();
        assert!(cstats.records >= 5, "records: {}", cstats.records);

        let sf = run(&collect_dir).expect("sinkfilter run");
        assert_eq!(sf.taint_sink_chains, 1, "taint_sink_chains={}", sf.taint_sink_chains);
        assert!(sf.proven_chains >= 1, "proven: {}", sf.proven_chains);

        let rep: serde_json::Value = serde_json::from_slice(
            &std::fs::read(collect_dir.join("filtered/report.json")).unwrap(),
        )
        .unwrap();
        let chains = rep["chains"].as_array().unwrap();
        let mut found = false;
        for ch in chains {
            if ch["name"].as_str().unwrap_or("").contains("collector.js") {
                assert_eq!(ch["verdict"].as_str(), Some("proven"), "chain={:?}", ch);
                assert_eq!(ch["taint_sink"].as_bool(), Some(true));
                let sigs: Vec<String> = ch["signals"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
                assert!(sigs.iter().any(|s| s == "taint-sink"), "signals={:?}", sigs);
                found = true;
            }
        }
        assert!(found, "collector.js chain missing from report");
    }

    #[test]
    fn req_body_stream_is_graph_sink() {
        use std::io::Write as _;
        let tmp = tempfile::tempdir().unwrap();
        let raw_dir = tmp.path().join("raw-src");
        let collect_dir = tmp.path().join("collect");
        std::fs::create_dir_all(&raw_dir).unwrap();
        let mut rec: Vec<u8> = Vec::new();
        let t0: u64 = 3_000_000_000;
        {
            let mut w = std::io::Cursor::new(&mut rec);
            let mut put = |kind: u8, ts: u64, payload: &[u8]| {
                let total: u32 = (16 + payload.len()) as u32;
                w.write_all(&total.to_le_bytes()).unwrap();
                w.write_all(&[kind, 0]).unwrap();
                w.write_all(&[0u8, 0]).unwrap();
                w.write_all(&ts.to_le_bytes()).unwrap();
                w.write_all(payload).unwrap();
            };
            put(0, t0, b"afeye-sink/net v2 pid=1");
            put(36, t0 - 500_000, b"nav-start mono_ns=2999500000");
            put(1, t0 + 1_000_000,
                b"https://af.io/stream.js\0function go(){fetch('/u',{method:'POST',body:b})}go()");
            let wire = b"{\"fp\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"tok\":\"zz\"}";
            let mut te = Vec::new();
            te.extend_from_slice(b"text-encoder");
            te.push(0);
            te.extend_from_slice(wire);
            put(37, t0 + 4_000_000, &te);
            let mut rb = Vec::new();
            rb.extend_from_slice(b"req-body-stream");
            rb.push(0);
            rb.extend_from_slice(wire);
            put(17, t0 + 6_000_000, &rb);
        }
        std::env::set_var("AF_RAW_DIR", &raw_dir);
        std::fs::write(raw_dir.join("net-5.rec"), &rec).unwrap();
        let collector =
            crate::collect::Collector::spawn_dirs(raw_dir.clone(), collect_dir.clone());
        std::thread::sleep(std::time::Duration::from_millis(600));
        let cstats = collector.stop();
        assert!(cstats.records >= 4, "records: {}", cstats.records);

        let sf = run(&collect_dir).expect("sinkfilter run");
        assert!(sf.graph_sinks >= 1, "req-body-stream not a sink: {}", sf.graph_sinks);
        assert!(sf.graph_tainted >= 1, "carrier not tainted by stream sink");
    }

    #[test]
    fn gc_taint_unions_are_runlevel() {
        use std::io::Write as _;
        let tmp = tempfile::tempdir().unwrap();
        let raw_dir = tmp.path().join("raw-src");
        let collect_dir = tmp.path().join("collect");
        std::fs::create_dir_all(&raw_dir).unwrap();
        let mut rec: Vec<u8> = Vec::new();
        let t0: u64 = 4_000_000_000;
        {
            let mut w = std::io::Cursor::new(&mut rec);
            let mut put = |kind: u8, ts: u64, payload: &[u8]| {
                let total: u32 = (16 + payload.len()) as u32;
                w.write_all(&total.to_le_bytes()).unwrap();
                w.write_all(&[kind, 0]).unwrap();
                w.write_all(&[0u8, 0]).unwrap();
                w.write_all(&ts.to_le_bytes()).unwrap();
                w.write_all(payload).unwrap();
            };
            put(0, t0, b"afeye-sink/v8 v2 pid=1");
            put(36, t0 - 500_000, b"nav-start mono_ns=3999500000");
            put(1, t0 + 1_000_000, b"https://af.io/x.js\0var x=1");
            put(16, t0 + 2_000_000, b"taint-swept tag=1");
            put(16, t0 + 3_000_000, b"taint-deadend tag=1");
            put(16, t0 + 4_000_000, b"taint-swept tag=4");
        }
        std::env::set_var("AF_RAW_DIR", &raw_dir);
        std::fs::write(raw_dir.join("v8-9.rec"), &rec).unwrap();
        let collector =
            crate::collect::Collector::spawn_dirs(raw_dir.clone(), collect_dir.clone());
        std::thread::sleep(std::time::Duration::from_millis(600));
        let _ = collector.stop();

        let sf = run(&collect_dir).expect("sinkfilter run");
        assert_eq!(sf.taint_swept_union, 0x5, "swept={:#x}", sf.taint_swept_union);
        assert_eq!(sf.taint_deadend_union, 0x1, "deadend={:#x}", sf.taint_deadend_union);
        let rep: serde_json::Value = serde_json::from_slice(
            &std::fs::read(collect_dir.join("filtered/report.json")).unwrap(),
        )
        .unwrap();
        let cls = &rep["classification"];
        assert_eq!(cls["taint_swept_union"].as_u64(), Some(0x5));
        assert_eq!(cls["taint_deadend_union"].as_u64(), Some(0x1));
    }

}
