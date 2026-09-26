use crate::matcher::AhoCorasick;
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{BufReader, Read, Write};
use std::path::Path;

#[derive(Default, Debug, Clone)]
pub struct SinkFilterStats {
    pub records: u64,
    pub fragments: u64,
    pub chains: u64,
    pub chain_bytes: u64,
    pub keep_cold: bool,
    pub wasm_modules: u64,
    pub wasm_imports: u64,
    pub wasm_exports: u64,
    pub wasm_instantiated: u64,
    pub wasm_cached: u64,
    pub wasm_firstcalls: u64,
    pub wasm_mem_grows: u64,
    pub wasm_traps: u64,
    pub exec_compiles: u64,
    pub exec_jit: u64,
    pub exec_byte: u64,
    pub exec_wasm_code: u64,
    pub lazy_funcs: u64,
    pub proven_chains: u64,
    pub dead_end_proven: u64,
    pub unresolved_chains: u64,
    pub prune_paths: u64,
    pub fetched_url_chains: u64,
    pub send_initiator_chains: u64,
    pub token_access_chains: u64,
    pub gopd_chains: u64,
    pub stack_inspect_chains: u64,
    pub payload_assembler_chains: u64,
    pub value_proven_values: u64,
    pub value_proven_scripts: u64,
    pub causality_edges: u64,
    pub causality_roots: u64,
    pub proven_causality: u64,
    pub proven_value: u64,
    pub unavailable_chains: u64,
    pub incomplete_reasons: BTreeMap<String, u64>,
    pub sid_attributed_records: u64,
    pub sid_zero_records: u64,
    pub valuebook_entries: u64,
    pub ac_matches: u64,
    pub exec_jit_violations: u64,
    pub drop_witnesses: u64,
    pub cap_exhausted: u64,
    pub tid_low16_collisions: u64,
}

const PAYLOAD_KINDS: &[&str] = &[
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
    "canvas/to-data-url-data",
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

const SINK_TAGS: &[&str] = &[
    "ws-frame-out",
    "wt-stream-out",
    "wt-datagram-out",
    "rtc-datachannel-out",
    "webgpu/write-buffer",
    "webgpu/write-texture",
    "req-body",
    "req-body-stream",
    // 0039: the first 4KiB of a real file upload (EmitSpan, NUL-framed).
    // Without this a token sent via multipart/form-data was invisible.
    "req-file-head",
    // 0011: full request headers (EmitTwoStr). Authorization / Cookie /
    // X-*-Token headers are where tokens actually leave the renderer.
    "req-headers",
    "cookie-attach",
];

const VALUEBOOK_MAX_LEN: u32 = 1 << 20;
const OP_ID_NONE: u16 = 0xFFFF;

#[derive(Debug)]
struct Rec {
    ts: u64,
    pid: u64,
    layer: String,
    kind: String,
    sid: u32,
    tid: u16,
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

fn is_sink_tag(kind: &str, tag: &str) -> bool {
    match kind {
        "crypto-op" | "structured-clone" | "taint-edge" | "wasm-memory" => true,
        "websocket" | "net-request" => {
            let tok = tag.split(' ').next().unwrap_or(tag);
            SINK_TAGS.contains(&tok)
        }
        "fingerprint" => VALUE_TAGS.iter().any(|t| tag.starts_with(t)),
        _ => false,
    }
}

fn hex_field(txt: &str, key: &str) -> Option<u64> {
    let p = txt.find(key)? + key.len();
    let rest = &txt[p..];
    let end = rest.find(' ').unwrap_or(rest.len());
    u64::from_str_radix(rest[..end].trim(), 16).ok()
}

fn dec_field(txt: &str, key: &str) -> Option<u64> {
    let p = txt.find(key)? + key.len();
    let rest = &txt[p..];
    let end = rest.find(' ').unwrap_or(rest.len());
    rest[..end].trim().parse::<u64>().ok()
}

fn str_field<'a>(txt: &'a str, key: &str) -> Option<&'a str> {
    let p = txt.find(key)? + key.len();
    let rest = &txt[p..];
    let end = rest.find(' ').unwrap_or(rest.len());
    let v = rest[..end].trim();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn hex_of(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(b.len() * 2);
    for &x in b {
        out.push(H[(x >> 4) as usize] as char);
        out.push(H[(x & 0xf) as usize] as char);
    }
    out
}

struct UnionFind {
    p: HashMap<u64, u64>,
}

impl UnionFind {
    fn new() -> Self {
        UnionFind { p: HashMap::new() }
    }
    fn find(&mut self, x: u64) -> u64 {
        let mut root = x;
        loop {
            match self.p.get(&root) {
                Some(&v) if v != root => root = v,
                _ => break,
            }
        }
        let mut cur = x;
        while cur != root {
            match self.p.get(&cur).copied() {
                Some(v) if v != cur => {
                    self.p.insert(cur, root);
                    cur = v;
                }
                _ => break,
            }
        }
        root
    }
    fn union(&mut self, a: u64, b: u64) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            self.p.insert(rb, ra);
        }
    }
    fn insert_node(&mut self, x: u64) {
        self.p.entry(x).or_insert(x);
    }
}

fn edge_pair(txt: &str) -> Option<(u64, u64)> {
    let p = txt.find("edge=")? + 5;
    let rest = &txt[p..];
    let end = rest.find(' ').unwrap_or(rest.len());
    let (a, b) = rest[..end].split_once("->")?;
    Some((
        u64::from_str_radix(a, 16).ok()?,
        u64::from_str_radix(b, 16).ok()?,
    ))
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
    layer: String,
    name: String,
    frags: u64,
    bytes: u64,
    first_ts: u64,
    last_ts: u64,
    path: String,
    iso: Option<String>,
    worker: Option<String>,
    sids: Vec<u32>,
    tid_records: u64,
    sink_records: u64,
    has_sink_records: bool,
    send_initiator: bool,
    token_access: bool,
    taint_sink: bool,
    gopd_check: bool,
    stack_inspect: bool,
    stack_samples: Vec<String>,
    payload_assembler: bool,
    fp_entry: Vec<String>,
    executed_funcs: u64,
    fetched_url: bool,
    value_hits: u64,
    causality_hits: u64,
    proven_causality: bool,
    proven_value: bool,
    proven: bool,
    in_zip: bool,
    reasons: Vec<String>,
    dead_end_proven: bool,
}

impl Chain {
    fn verdict(&self) -> &'static str {
        if self.proven_causality {
            "proven-causality"
        } else if self.proven_value {
            "proven-value"
        } else if !self.reasons.is_empty() {
            "unavailable"
        } else if self.has_sink_records {
            "evidence-only"
        } else {
            "dead-end-proven"
        }
    }
}

#[derive(Clone, Copy)]
struct VOrigin {
    func_id: u32,
    off: u32,
    op_id: u16,
    src: u8,
}

impl VOrigin {
    fn src_name(&self) -> &'static str {
        match self.src {
            0 => "acc",
            1 => "reg",
            _ => "cp",
        }
    }
}

fn load_exec_funcs(filt: &Path) -> Vec<u32> {
    let b = match fs::read(filt.join("exec_funcs.bin")) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let mut v: Vec<u32> = Vec::with_capacity(b.len() / 4);
    for c in b.chunks_exact(4) {
        v.push(u32::from_le_bytes([c[0], c[1], c[2], c[3]]));
    }
    v
}

fn load_ops(filt: &Path) -> Vec<String> {
    match fs::read_to_string(filt.join("ops.txt")) {
        Ok(s) => s.lines().map(|l| l.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

struct Valuebook {
    ac: AhoCorasick,
    origins: Vec<VOrigin>,
    entries: u64,
}

fn load_valuebook(filt: &Path, exec_funcs: &[u32]) -> Valuebook {
    let mut ac = AhoCorasick::new();
    let mut origins: Vec<VOrigin> = Vec::new();
    let mut entries = 0u64;
    if let Ok(f) = fs::File::open(filt.join("valuebook.bin")) {
        let mut rd = BufReader::with_capacity(1 << 16, f);
        let mut hdr = [0u8; 15];
        let mut scratch: Vec<u8> = Vec::new();
        loop {
            if rd.read_exact(&mut hdr).is_err() {
                break;
            }
            let len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
            let func_id = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
            let off = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
            let op_id = u16::from_le_bytes([hdr[12], hdr[13]]);
            let src = hdr[14];
            if len == 0 {
                continue;
            }
            if len > VALUEBOOK_MAX_LEN {
                let mut take = (&mut rd).take(len as u64);
                if std::io::copy(&mut take, &mut std::io::sink()).is_err() {
                    break;
                }
                continue;
            }
            scratch.resize(len as usize, 0);
            if rd.read_exact(&mut scratch).is_err() {
                break;
            }
            if src == 2 && exec_funcs.binary_search(&func_id).is_err() {
                continue;
            }
            let id = ac.insert(&scratch) as usize;
            if origins.len() <= id {
                origins.resize(
                    id + 1,
                    VOrigin {
                        func_id: 0,
                        off: 0,
                        op_id: OP_ID_NONE,
                        src: 2,
                    },
                );
            }
            origins[id] = VOrigin {
                func_id,
                off,
                op_id,
                src,
            };
            entries += 1;
        }
    }
    ac.build();
    Valuebook {
        ac,
        origins,
        entries,
    }
}

pub fn run(
    collect_dir: &Path,
    func_scripts: &HashMap<u32, String>,
    script_ids: &HashMap<u32, String>,
) -> Result<SinkFilterStats, String> {
    let index_p = collect_dir.join("index.jsonl");
    let raw_dir = collect_dir.to_path_buf();
    let mut stats = SinkFilterStats {
        keep_cold: std::env::var("AF_SINK_KEEP_COLD")
            .map(|v| v == "1")
            .unwrap_or(false),
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
            sid: v.get("sid").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            tid: v.get("tid").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
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

    let mut uf = UnionFind::new();
    let mut low16_index: HashMap<u16, Vec<u64>> = HashMap::new();
    let mut wit = [0u64; 4];
    let mut causality_links = 0u64;
    let mut drops: Vec<(u64, u64, String, u64)> = Vec::new();
    let mut caps: Vec<(u64, String)> = Vec::new();
    let mut workers: Vec<(u64, String, String)> = Vec::new();
    let mut fetched: HashSet<String> = HashSet::new();
    let mut exec_per_name: HashMap<String, u64> = HashMap::new();
    let mut lazy_per_name: HashMap<String, u64> = HashMap::new();
    let mut taint_swept_union: u64 = 0;
    let mut taint_deadend_union: u64 = 0;
    let mut nav_start: Option<u64> = None;

    for r in &recs {
        let txt = r.txt.as_deref().unwrap_or("");
        match r.kind.as_str() {
            "fingerprint" => {
                if let Some(rest) = txt.strip_prefix("causality ") {
                    if rest.starts_with("witness ") {
                        wit[0] = wit[0].max(dec_field(rest, "dropped=").unwrap_or(0));
                        wit[1] = wit[1].max(dec_field(rest, "imbalance=").unwrap_or(0));
                        wit[2] = wit[2].max(dec_field(rest, "misses=").unwrap_or(0));
                        wit[3] = wit[3].max(dec_field(rest, "minted=").unwrap_or(0));
                        continue;
                    }
                    let tid = hex_field(txt, "tid=").unwrap_or(0);
                    let parent = hex_field(txt, "parent=").unwrap_or(0);
                    let (a, b) = match edge_pair(rest) {
                        Some(pair) => pair,
                        None if tid != 0 && parent != 0 => (tid, parent),
                        _ => {
                            if tid != 0 {
                                uf.insert_node(tid);
                                low16_index
                                    .entry((tid & 0xffff) as u16)
                                    .or_default()
                                    .push(tid);
                            }
                            continue;
                        }
                    };
                    uf.insert_node(a);
                    uf.insert_node(b);
                    uf.union(a, b);
                    causality_links += 1;
                    low16_index
                        .entry((a & 0xffff) as u16)
                        .or_default()
                        .push(a);
                    low16_index
                        .entry((b & 0xffff) as u16)
                        .or_default()
                        .push(b);
                } else if let Some(rest) = txt.strip_prefix("taint-swept tag=") {
                    if let Ok(v) = u64::from_str_radix(rest.trim(), 16) {
                        taint_swept_union |= v;
                    }
                } else if let Some(rest) = txt.strip_prefix("taint-deadend tag=") {
                    if let Ok(v) = u64::from_str_radix(rest.trim(), 16) {
                        taint_deadend_union |= v;
                    }
                }
            }
            "sink-drop" => {
                if let Some(rest) = txt.strip_prefix("sink-drop ") {
                    let n = dec_field(rest, "dropped=").unwrap_or(0);
                    if n > 0 {
                        stats.drop_witnesses += 1;
                        let layer = str_field(rest, "layer=").unwrap_or(&r.layer).to_string();
                        drops.push((r.ts, r.pid, layer, n));
                    }
                } else if let Some(rest) = txt.strip_prefix("cap-exhausted ") {
                    stats.cap_exhausted += 1;
                    if let Some(name) = str_field(rest, "name=") {
                        caps.push((r.pid, name.to_string()));
                    }
                }
            }
            "isolate" => {
                if r.layer == "v8" && txt.starts_with("exec ") {
                    stats.exec_compiles += 1;
                    // Resolve the script= field FIRST: a real JS tier-up
                    // carries script=<URL>:<line>; wasm-Liftoff code (which
                    // we deliberately keep alive so WASM antifraud runs) has
                    // NO SharedFunctionInfo/Script, so 0025 emits an EMPTY
                    // script= for it. Only a JS function compiling to native
                    // code (non-empty script) violates the interpreter-only
                    // pin and means the 0033 bytecode trace is incomplete.
                    let script_bare = txt.find(" script=").map(|sp| {
                        let script_part = &txt[sp + 8..];
                        let end =
                            script_part.find(" len=").unwrap_or(script_part.len());
                        let script_name = &script_part[..end];
                        let bare = match script_name.rfind(':') {
                            Some(c)
                                if script_name[c + 1..]
                                    .chars()
                                    .all(|d| d.is_ascii_digit()) =>
                            {
                                &script_name[..c]
                            }
                            _ => script_name,
                        };
                        split_iso(bare).1
                    });
                    if txt.starts_with("exec jit ") {
                        stats.exec_jit += 1;
                        // empty script= -> wasm-Liftoff (intended, not a
                        // JS-interpreter violation); non-empty -> JS tier-up.
                        if script_bare.as_ref().map(|s| !s.is_empty()).unwrap_or(false) {
                            stats.exec_jit_violations += 1;
                        }
                    } else if txt.starts_with("exec byte ") {
                        stats.exec_byte += 1;
                    } else if txt.starts_with("exec wasm ") {
                        stats.exec_wasm_code += 1;
                    }
                    if let Some(bare) = script_bare {
                        if !bare.is_empty() {
                            *exec_per_name.entry(bare).or_insert(0u64) += 1;
                        }
                    }
                }
            }
            "call-completed" => {
                if let Some(rest) = txt.strip_prefix("lazy-compile ") {
                    stats.lazy_funcs += 1;
                    if let Some(sp) = rest.find(" script=") {
                        let script_part = &rest[sp + 8..];
                        let bare = match script_part.rfind(':') {
                            Some(c)
                                if script_part[c + 1..]
                                    .chars()
                                    .all(|d| d.is_ascii_digit()) =>
                            {
                                &script_part[..c]
                            }
                            _ => script_part,
                        };
                        let (_, bare) = split_iso(bare);
                        *lazy_per_name.entry(bare).or_insert(0) += 1;
                    }
                }
            }
            "worker" => {
                if let Some((iso, name)) = worker_of(txt) {
                    workers.push((r.ts, iso, name));
                }
            }
            "wasm-instance" => {
                if txt.starts_with("wasm-instantiate") {
                    stats.wasm_instantiated += 1;
                } else if txt.starts_with("wasm-firstcall ") {
                    stats.wasm_firstcalls += 1;
                } else if txt.starts_with("wasm-trap ") {
                    stats.wasm_traps += 1;
                } else if txt.starts_with("wasm-mem grow ") {
                    stats.wasm_mem_grows += 1;
                }
            }
            "net-request" => {
                if let Some(nul) = txt.find('\u{0}') {
                    let url = &txt[nul + 1..];
                    if url.starts_with("http://") || url.starts_with("https://") {
                        fetched.insert(url.to_string());
                    }
                }
            }
            "nav-start" => {
                let mono = dec_field(txt, "mono_ns=");
                let t = mono.unwrap_or(r.ts);
                if nav_start.map(|old| t < old).unwrap_or(true) {
                    nav_start = Some(t);
                }
            }
            _ => {}
        }
    }
    for v in low16_index.values_mut() {
        v.sort_unstable();
        v.dedup();
    }
    stats.causality_edges = causality_links;
    {
        let mut roots: HashSet<u64> = HashSet::new();
        let nodes: Vec<u64> = uf.p.keys().copied().collect();
        for node in nodes {
            roots.insert(uf.find(node));
        }
        stats.causality_roots = roots.len() as u64;
    }

    // tid travels over the wire as low16 only (2 bytes), but the causality
    // graph is keyed by the full 64-bit tid. On a long crawl (>65536
    // microtask roots) two DISTINCT causality trees can share a low16. If we
    // matched a sink's low16 against every full tid with that low16, a record
    // would inherit a foreign tree's root -> FALSE proven. So a low16 is only
    // trusted for causality when ALL full tids sharing it collapse to ONE
    // root (unambiguous); ambiguous low16s are blacklisted -> honest
    // false-negative, value-provenance (byte-exact SAM) still catches it.
    let mut ambig_low16: HashSet<u16> = HashSet::new();
    for (low, fulls) in low16_index.iter() {
        let mut root: Option<u64> = None;
        let mut conflict = false;
        for f in fulls {
            let r = uf.find(*f);
            match root {
                None => root = Some(r),
                Some(prev) if prev != r => {
                    conflict = true;
                    break;
                }
                Some(_) => {}
            }
        }
        if conflict {
            ambig_low16.insert(*low);
            stats.tid_low16_collisions += 1;
        }
    }

    let graceful = fs::read_to_string(collect_dir.join("shutdown.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("graceful").and_then(|g| g.as_bool()))
        .unwrap_or(false);
    let corrupt = fs::read_to_string(collect_dir.join("stats.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("corrupt").and_then(|c| c.as_u64()))
        .unwrap_or(u64::MAX);
    let allow_jit = std::env::var("AF_ALLOW_JIT")
        .map(|v| v != "0")
        .unwrap_or(false);

    let mut chains: HashMap<(u64, String, String), usize> = HashMap::new();
    let mut chain_list: Vec<Chain> = Vec::new();
    let mut wasm_index: Vec<serde_json::Value> = Vec::new();
    let mut wasm_seen: HashSet<String> = HashSet::new();

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
                    chain_list.push(Chain {
                        file,
                        pid: r.pid,
                        layer: r.layer.clone(),
                        name: display,
                        frags: 0,
                        bytes: 0,
                        first_ts: r.ts,
                        last_ts: r.ts,
                        path: format!("filtered/scripts/{}", fname),
                        iso,
                        worker,
                        sids: Vec::new(),
                        tid_records: 0,
                        sink_records: 0,
                        has_sink_records: false,
                        send_initiator: false,
                        token_access: false,
                        taint_sink: false,
                        gopd_check: false,
                        stack_inspect: false,
                        stack_samples: Vec::new(),
                        payload_assembler: false,
                        fp_entry: Vec::new(),
                        executed_funcs: 0,
                        fetched_url: false,
                        value_hits: 0,
                        causality_hits: 0,
                        proven_causality: false,
                        proven_value: false,
                        proven: false,
                        in_zip: false,
                        reasons: Vec::new(),
                        dead_end_proven: false,
                    });
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
                let _ = writeln!(f, "/* ==== ts={} len={} h={} ==== */", r.ts, r.len, r.h);
                let _ = f.write_all(&body);
                let _ = f.write_all(b"\n");
            }
            c.frags += 1;
            c.bytes += body.len() as u64;
            c.last_ts = r.ts;
        } else if r.kind == "wasm-module" {
            if !wasm_seen.insert(r.h.clone()) {
                continue;
            }
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
                wasm_index.push(json!({
                    "hash": r.h,
                    "bytes": wasm_bytes.len(),
                    "ts": r.ts,
                    "pid": r.pid,
                    "from_cache": from_cache,
                    "imports": im.iter().take(256).cloned().collect::<Vec<_>>(),
                    "exports": ex.iter().take(256).cloned().collect::<Vec<_>>(),
                }));
            }
        }
    }
    for c in &mut chain_list {
        if let Some(f) = c.file.as_mut() {
            let _ = f.sync_all();
        }
        stats.chain_bytes += c.bytes;
    }
    stats.chains = chain_list.len() as u64;

    let mut name_to_chain: HashMap<(u64, String), usize> = HashMap::new();
    let mut chains_by_name: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, c) in chain_list.iter().enumerate() {
        if !c.name.is_empty() {
            name_to_chain
                .entry((c.pid, c.name.clone()))
                .or_insert(idx);
            chains_by_name.entry(c.name.clone()).or_default().push(idx);
        }
    }

    let mut sid_chain: HashMap<u32, Vec<(u64, u32)>> = HashMap::new();
    for (&sid, name) in script_ids {
        if sid == 0 {
            continue;
        }
        if let Some(idxs) = chains_by_name.get(name) {
            let v = sid_chain.entry(sid).or_default();
            for &idx in idxs {
                v.push((chain_list[idx].pid, idx as u32));
            }
        }
    }

    let attr_chain = |r: &Rec| -> Option<usize> {
        if r.sid == 0 {
            return None;
        }
        sid_chain.get(&r.sid).and_then(|v| {
            v.iter()
                .find(|(pid, _)| *pid == r.pid)
                .map(|(_, idx)| *idx as usize)
        })
    };

    let mut tid16_chains: HashMap<u16, Vec<u32>> = HashMap::new();
    let mut root_chains: HashMap<u64, Vec<u32>> = HashMap::new();
    for r in &recs {
        if r.sid == 0 {
            stats.sid_zero_records += 1;
            continue;
        }
        let idx = match attr_chain(r) {
            Some(i) => i,
            None => continue,
        };
        stats.sid_attributed_records += 1;
        let c = &mut chain_list[idx];
        if c.sids.len() < 16 && !c.sids.contains(&r.sid) {
            c.sids.push(r.sid);
        }
        if r.tid != 0 {
            c.tid_records += 1;
            tid16_chains.entry(r.tid).or_default().push(idx as u32);
            if !ambig_low16.contains(&r.tid) {
                if let Some(fulls) = low16_index.get(&r.tid) {
                    for full in fulls {
                        let root = uf.find(*full);
                        root_chains.entry(root).or_default().push(idx as u32);
                    }
                }
            }
        }
        let txt = r.txt.as_deref().unwrap_or("");
        match r.kind.as_str() {
            "fetch" => c.send_initiator = true,
            "fingerprint" => {
                if txt.starts_with("json-stringify") {
                    c.payload_assembler = true;
                } else if txt.starts_with("taint-sink ") {
                    c.taint_sink = true;
                } else if txt.starts_with("gopd ") {
                    c.gopd_check = true;
                } else if txt.starts_with("cookie-get")
                    || txt.starts_with("cookie-set")
                    || txt.starts_with("storage-get")
                    || txt.starts_with("storage-set")
                {
                    c.token_access = true;
                }
            }
            "dom-api" => {
                let head = txt_head(txt, 120);
                if c.fp_entry.len() < 32 && !c.fp_entry.contains(&head) {
                    c.fp_entry.push(head);
                }
            }
            "error-stack" => {
                c.stack_inspect = true;
                if c.stack_samples.len() < 4 {
                    c.stack_samples.push(txt_head(txt, 240));
                }
            }
            _ => {}
        }
    }
    for v in tid16_chains.values_mut() {
        v.sort_unstable();
        v.dedup();
    }

    let exec_funcs = load_exec_funcs(&filt);
    let ops = load_ops(&filt);
    let vb = load_valuebook(&filt, &exec_funcs);
    stats.valuebook_entries = vb.entries;

    let mut value_hits: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    let mut matched_values: HashSet<u32> = HashSet::new();
    let mut sink_tid_cache: HashMap<u16, Vec<u32>> = HashMap::new();
    let mut related: Vec<u32> = Vec::new();
    let mut hits: Vec<(u32, usize)> = Vec::new();
    let mut attributed: Vec<u32> = Vec::new();

    for r in &recs {
        if !PAYLOAD_KINDS.contains(&r.kind.as_str()) {
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
        if body.is_empty() || !is_sink_tag(&r.kind, &tag) {
            continue;
        }

        attributed.clear();
        if let Some(idx) = attr_chain(r) {
            attributed.push(idx as u32);
            let c = &mut chain_list[idx];
            c.sink_records += 1;
            c.has_sink_records = true;
        }
        // ambiguous low16 (two distinct causality trees share it) -> the
        // tid carries no trustworthy causality fact; skip rather than risk a
        // false proven. value-provenance below still catches the token.
        if r.tid != 0 && !ambig_low16.contains(&r.tid) {
            if !sink_tid_cache.contains_key(&r.tid) {
                related.clear();
                if let Some(direct) = tid16_chains.get(&r.tid) {
                    related.extend(direct.iter().copied());
                }
                if let Some(fulls) = low16_index.get(&r.tid) {
                    for full in fulls {
                        let root = uf.find(*full);
                        if let Some(v) = root_chains.get(&root) {
                            related.extend(v.iter().copied());
                        }
                    }
                }
                related.sort_unstable();
                related.dedup();
                let cached = related.clone();
                sink_tid_cache.insert(r.tid, cached);
            }
            let cached = &sink_tid_cache[&r.tid];
            for idx in cached {
                let c = &mut chain_list[*idx as usize];
                c.proven_causality = true;
                c.causality_hits += 1;
                c.has_sink_records = true;
                if !attributed.contains(idx) {
                    attributed.push(*idx);
                }
            }
        }
        if vb.ac.is_empty() {
            continue;
        }
        hits.clear();
        vb.ac.find(&body, |pid, off| hits.push((pid, off)));
        for (pid, off) in hits.drain(..) {
            stats.ac_matches += 1;
            matched_values.insert(pid);
            let origin = vb.origins[pid as usize];
            let val = vb.ac.pattern(pid as usize);
            let script = func_scripts
                .get(&origin.func_id)
                .cloned()
                .unwrap_or_else(|| format!("func:{:08x}", origin.func_id));
            let via_value: Vec<u32> = if attributed.is_empty() {
                chains_by_name
                    .get(&script)
                    .map(|v| v.iter().map(|i| *i as u32).collect())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let mut all = attributed.clone();
            all.extend(via_value.iter().copied());
            all.sort_unstable();
            all.dedup();
            for idx in &all {
                let c = &mut chain_list[*idx as usize];
                c.proven_value = true;
                c.value_hits += 1;
            }
            let list = value_hits.entry(script).or_default();
            if list.len() < 64 {
                let op = if origin.op_id == OP_ID_NONE {
                    if origin.src == 2 {
                        json!("cp")
                    } else {
                        json!(null)
                    }
                } else {
                    json!(ops.get(origin.op_id as usize))
                };
                let head = hex_of(&val[..val.len().min(32)]);
                let mut attrib: Vec<&str> = Vec::new();
                if !attributed.is_empty() {
                    attrib.push("record");
                }
                if !via_value.is_empty() {
                    attrib.push("value");
                }
                list.push(json!({
                    "kind": r.kind,
                    "off_in_payload": off,
                    "val_len": val.len(),
                    "val_head_hex": head,
                    "src": origin.src_name(),
                    "op": op,
                    "bc_off": origin.off,
                    "sink_pid": r.pid,
                    "sink_layer": r.layer,
                    "attributed_by": attrib,
                }));
            }
        }
    }
    stats.value_proven_values = matched_values.len() as u64;
    stats.value_proven_scripts = value_hits.len() as u64;

    let mut taint_sink_chains = 0u64;
    let mut fp_entry_chains = 0u64;
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
            if fetched.contains(c.name.as_str()) {
                c.fetched_url = true;
                stats.fetched_url_chains += 1;
            }
        }
        if c.send_initiator {
            stats.send_initiator_chains += 1;
        }
        if c.token_access {
            stats.token_access_chains += 1;
        }
        if c.taint_sink {
            taint_sink_chains += 1;
        }
        if c.gopd_check {
            stats.gopd_chains += 1;
        }
        if c.stack_inspect {
            stats.stack_inspect_chains += 1;
        }
        if c.payload_assembler {
            stats.payload_assembler_chains += 1;
        }
        if !c.fp_entry.is_empty() {
            fp_entry_chains += 1;
        }
    }

    let drops_by_pid: HashMap<u64, Vec<(u64, String, u64)>> = {
        let mut m: HashMap<u64, Vec<(u64, String, u64)>> = HashMap::new();
        for (ts, pid, layer, n) in drops {
            m.entry(pid).or_default().push((ts, layer, n));
        }
        m
    };
    let caps_by_pid: HashMap<u64, BTreeMap<String, ()>> = {
        let mut m: HashMap<u64, BTreeMap<String, ()>> = HashMap::new();
        for (pid, name) in caps {
            m.entry(pid).or_default().insert(name, ());
        }
        m
    };

    for c in &mut chain_list {
        c.proven = c.proven_causality || c.proven_value;
        if c.proven_causality {
            stats.proven_causality += 1;
        }
        if c.proven_value {
            stats.proven_value += 1;
        }
        if c.proven {
            stats.proven_chains += 1;
        }
        if !c.proven {
            let mut reasons: Vec<String> = Vec::new();
            if !graceful {
                reasons.push("shutdown not graceful".into());
            }
            if corrupt != 0 {
                reasons.push("corrupt records".into());
            }
            if stats.exec_jit_violations > 0 && !allow_jit {
                reasons.push("exec-jit observed".into());
            }
            if let Some(v) = drops_by_pid.get(&c.pid) {
                for (ts, layer, _) in v {
                    if (layer == "v8" || layer == "blink") && *ts <= c.last_ts {
                        let s = format!("drop-witness pid={} layer={}", c.pid, layer);
                        if !reasons.contains(&s) {
                            reasons.push(s);
                        }
                    }
                }
            }
            if let Some(m) = caps_by_pid.get(&c.pid) {
                for name in m.keys() {
                    let s = format!("cap-exhausted name={}", name);
                    if !reasons.contains(&s) {
                        reasons.push(s);
                    }
                }
            }
            if reasons.is_empty() {
                if c.has_sink_records {
                    stats.unresolved_chains += 1;
                } else {
                    c.dead_end_proven = true;
                    stats.dead_end_proven += 1;
                }
            } else {
                c.reasons = reasons;
                stats.unavailable_chains += 1;
                for s in &c.reasons {
                    *stats.incomplete_reasons.entry(s.clone()).or_insert(0) += 1;
                }
            }
        }
        c.in_zip = c.proven || c.has_sink_records || stats.keep_cold;
    }

    let mut chain_report = Vec::new();
    let mut prune_report: Vec<serde_json::Value> = Vec::new();
    for c in &chain_list {
        let verdict = c.verdict();
        let mut evidence = json!({
            "layer": c.layer,
            "frags": c.frags,
            "bytes": c.bytes,
            "ts0": c.first_ts,
            "ts1": c.last_ts,
            "sink_records": c.sink_records,
            "tid_records": c.tid_records,
            "value_hits": c.value_hits,
            "causality_hits": c.causality_hits,
        });
        if !c.sids.is_empty() {
            evidence["sids"] = json!(c.sids);
        }
        if let Some(iso) = &c.iso {
            evidence["isolate"] = json!(iso);
        }
        if let Some(w) = &c.worker {
            evidence["worker"] = json!(w);
        }
        if c.send_initiator {
            evidence["send_initiator"] = json!(true);
        }
        if c.token_access {
            evidence["token_access"] = json!(true);
        }
        if c.taint_sink {
            evidence["taint_sink"] = json!(true);
        }
        if c.gopd_check {
            evidence["gopd_check"] = json!(true);
        }
        if c.stack_inspect {
            evidence["stack_inspect"] = json!(true);
            if !c.stack_samples.is_empty() {
                evidence["stack_samples"] = json!(c.stack_samples);
            }
        }
        if c.payload_assembler {
            evidence["payload_assembler"] = json!(true);
        }
        if !c.fp_entry.is_empty() {
            evidence["fp_entry"] = json!(c.fp_entry);
        }
        if c.executed_funcs > 0 {
            evidence["executed_funcs"] = json!(c.executed_funcs);
        }
        if c.fetched_url {
            evidence["fetched_url"] = json!(true);
        }
        if let Some(t0) = nav_start {
            if c.first_ts >= t0 {
                evidence["ts0_rel_ms"] = json!((c.first_ts - t0) / 1_000_000);
                evidence["ts1_rel_ms"] = json!((c.last_ts - t0) / 1_000_000);
            }
        }
        chain_report.push(json!({
            "name": printable(&c.name, 200),
            "pid": c.pid,
            "verdict": verdict,
            "reasons": c.reasons,
            "in_zip": c.in_zip,
            "evidence": evidence,
            "path": c.path,
        }));
        if !c.in_zip && !c.path.is_empty() {
            prune_report.push(json!({
                "path": c.path,
                "bytes": c.bytes,
                "verdict": verdict,
            }));
        }
    }
    stats.prune_paths = prune_report.len() as u64;

    let mut per_kind: BTreeMap<String, u64> = BTreeMap::new();
    for r in &recs {
        *per_kind
            .entry(format!("{}/{}", r.layer, r.kind))
            .or_insert(0) += 1;
    }

    let report = json!({
        "stats": {
            "records": stats.records,
            "records_indexed": recs.len(),
            "fragments": stats.fragments,
            "chains": stats.chains,
            "chain_bytes": stats.chain_bytes,
            "keep_cold": stats.keep_cold,
            "proven": stats.proven_chains,
            "proven_causality": stats.proven_causality,
            "proven_value": stats.proven_value,
            "dead_end_proven": stats.dead_end_proven,
            "evidence_only": stats.unresolved_chains,
            "unavailable": stats.unavailable_chains,
            "prune_paths": stats.prune_paths,
            "sid_attributed_records": stats.sid_attributed_records,
            "sid_zero_records": stats.sid_zero_records,
            "incomplete_reasons": stats.incomplete_reasons,
        },
        "nav_start_ts": nav_start,
        "per_kind": per_kind,
        "causality": {
            "edges": stats.causality_edges,
            "roots": stats.causality_roots,
            "tid_low16_collisions": stats.tid_low16_collisions,
            "witness": {
                "dropped": wit[0],
                "imbalance": wit[1],
                "misses": wit[2],
                "minted": wit[3],
            },
            "rule": "nodes/edges = tid<->parent pairs parsed from kind-16 'causality link edge=A->B' and 'causality ... tid=X parent=Y' records (0031 ambient async trace id, full 64-bit in payload text; wire headers carry only low16). Built once into a union-find over tid components. A chain is proven-causality when a sink record's ambient tid lies in the SAME component (shares the root of the chain's tid-tree, reachable from sink-tid) as an ambient tid carried by a record sid-attributed to the chain. tid_low16_collisions counts low16 values whose full tids span MORE THAN ONE root (long crawl, >65536 microtask roots): those low16 are ambiguous, so NO causality link is asserted for them (honest false-negative; value-provenance still catches the token). net-layer records carry tid=0 (separate process, no v8 isolate) and never enter the graph. Witness counters are completeness evidence, never a verdict. No time is consulted.",
        },
        "completeness": {
            "graceful": graceful,
            "drop_witnesses": stats.drop_witnesses,
            "cap_exhausted": stats.cap_exhausted,
            "corrupt": if corrupt == u64::MAX { json!(null) } else { json!(corrupt) },
            "exec_jit": stats.exec_jit_violations,
            "allow_jit": allow_jit,
            "rule": "dead-end-proven requires ALL of: shutdown.json graceful=true; zero kind-39 sink-drop witnesses with dropped>0 in the chain's pid and a renderer layer (v8|blink) at or before the chain's last_ts; zero kind-39 cap-exhausted in the chain's pid; collect stats corrupt==0; zero kind-34 'exec jit' records unless AF_ALLOW_JIT is set. Any failure marks the chain unavailable with the exact reasons; net-layer drops never gate a renderer chain.",
        },
        "value_provenance": {
            "distinct_values_matched": stats.value_proven_values,
            "scripts_with_proven_values": stats.value_proven_scripts,
            "valuebook_entries": stats.valuebook_entries,
            "ac_matches": stats.ac_matches,
            "by_script": value_hits,
            "rule": "patterns = byte sequences executed Ignition instructions actually carried (acc/reg values from the 0033 trace; cp literals only when their func_id is in exec_funcs.bin, i.e. the function really executed). text = every sink payload (crypto-op, structured-clone, taint-edge, wasm-memory, req-body/req-body-stream/cookie-attach, ws/wt/rtc/webgpu egress tags, VALUE_TAGS fingerprint records). One Aho-Corasick pass per payload; a hit = that exact executed value occurs byte-for-byte at offset N of a boundary-crossing record. Chain attribution: renderer sinks via the record's own sid/tid; net sinks (sid=0, separate process) via value origin func_id -> script -> chain, with no pid-equality requirement. No time window, no hash window, no stride.",
        },
        "verdicts": {
            "proven": stats.proven_chains,
            "proven_causality": stats.proven_causality,
            "proven_value": stats.proven_value,
            "dead_end_proven": stats.dead_end_proven,
            "evidence_only": stats.unresolved_chains,
            "unavailable": stats.unavailable_chains,
            "rule": "proven = causality-proven OR value-proven, both facts (tid/parent edges from 0031; byte-identical executed values from the bctrace valuebook). unavailable = not proven and the completeness gate fails, with reasons[]. dead-end-proven = not proven, no sink record attributed, gate passed - the capture is complete, so the absence of any boundary crossing is itself a fact. evidence-only = sink records attributed by sid/tid but neither causality nor value proof connects them. No substring oracle, no time window, no blake3 content fuzzing participates in any verdict.",
        },
        "evidence": {
            "taint_swept_union": taint_swept_union,
            "taint_deadend_union": taint_deadend_union,
            "send_initiator": stats.send_initiator_chains,
            "token_access": stats.token_access_chains,
            "taint_sink": taint_sink_chains,
            "gopd": stats.gopd_chains,
            "stack_inspect": stats.stack_inspect_chains,
            "payload_assembler": stats.payload_assembler_chains,
            "fp_entry": fp_entry_chains,
            "fetched_url_chains": stats.fetched_url_chains,
            "rule": "per-chain booleans attributed strictly by sid (script_id on the C++ stack at the boundary crossing). They record what a chain did; they never enter proven.",
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
    });
    let _ = fs::write(
        filt.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap_or_default(),
    );

    Ok(stats)
}

fn worker_name_for(
    workers: &[(u64, String, String)],
    ts: u64,
    iso: &Option<String>,
) -> Option<String> {
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
