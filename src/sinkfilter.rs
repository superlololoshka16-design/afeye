//! afeye sink deep-filter (v4).
//!
//! Post-run pass over `collect/index.jsonl` + `collect/raw/*.bin` (what the
//! patched C++ sinks streamed). The raw collector materializes EVERY record
//! as its own file - correct for capture, unusable for humans (a self
//! unpacking loader easily produces 10k one-kilo fragments). This module
//! turns that into analysis-ready output without losing the wire:
//!
//!  1. script chains - all script-source fragments of the same origin
//!     (same pid + same script name) merge into ONE file. An antifraud
//!     unpacker eval-ing itself in thousands of micro-chunks lands as one
//!     reconstructable stream with `/* ==== [ts] name ==== */` separators.
//!  2. wasm modules - dumped as real `.wasm` files plus an offline walk of
//!     their import/export sections (`wasm-index.json`), so what the module
//!     reaches for is visible without executing anything.
//!  3. backward slicing (taint) - a chain is HOT when its code carries a
//!     network/collector sink call (fetch/XHR/beacon/WebSocket/canvas/audio/
//!     webrtc probes) or when it compiled inside an event handler / timer
//!     (ambient `evt:` / `timer:` provenance baked in by the C++ side).
//!     Cold chains are counted and dropped - dead branches that never reach
//!     the token do not waste disk.
//!  4. timing chains - for every network request the closest preceding
//!     input/event/timer/dom record links into `chains.jsonl`: the
//!     T0 (input) -> T1 (dispatch) -> T2 (network send) timeline.
//!
//! On success `collect/raw/` is pruned by the caller (the 10k-file problem);
//! `index.jsonl` keeps every hash and ts, so nothing is untraceable.

use serde_json::json;
use std::collections::{BTreeMap, HashMap};
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

#[derive(Debug)]
struct Rec {
    ts: u64,
    pid: u64,
    layer: String,
    kind: String,
    len: u64,
    h: String,
    path: String,
    txt: Option<String>,
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

fn is_hot(name: &str, body: &[u8]) -> bool {
    // compiled inside an antifraud handler/timer: provenance says so
    if name.starts_with("evt:") || name.starts_with("timer:") {
        return true;
    }
    let head = &body[..body.len().min(1 << 20)];
    let s = String::from_utf8_lossy(head);
    HOT_PATTERNS.iter().any(|p| s.contains(p))
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
    name: String,
    frags: u64,
    bytes: u64,
    hot: bool,
    first_ts: u64,
    last_ts: u64,
    path: String,
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
            txt: v.get("txt").and_then(|x| x.as_str()).map(|s| s.to_string()),
        });
    }

    let filt = collect_dir.join("filtered");
    let scripts_dir = filt.join("scripts");
    let wasm_dir = filt.join("wasm");
    let _ = fs::create_dir_all(&scripts_dir);
    let _ = fs::create_dir_all(&wasm_dir);

    recs.sort_by_key(|r| r.ts);

    // ---- 1+2+3: chains + wasm + taint ------------------------------------
    let mut chains: HashMap<(u64, String, String), usize> = HashMap::new();
    let mut chain_list: Vec<Chain> = Vec::new();
    let mut wasm_index: Vec<serde_json::Value> = Vec::new();
    let mut wasm_seen: HashMap<String, ()> = HashMap::new();

    for r in &recs {
        let payload = match fs::read(raw_dir.join(&r.path)) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if r.kind == "script-source" {
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
                    let c = Chain {
                        file,
                        name: name.clone(),
                        frags: 0,
                        bytes: 0,
                        hot: false,
                        first_ts: r.ts,
                        last_ts: r.ts,
                        path: format!("filtered/scripts/{}", fname),
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
            }
        } else if r.kind == "wasm-module" {
            if wasm_seen.contains_key(&r.h) {
                continue;
            }
            wasm_seen.insert(r.h.clone(), ());
            let wp = wasm_dir.join(format!("{}.wasm", &r.h[..16.min(r.h.len())]));
            if fs::write(&wp, &payload).is_ok() {
                let (im, ex) = wasm_imports_exports(&payload);
                stats.wasm_modules += 1;
                stats.wasm_imports += im.len() as u64;
                stats.wasm_exports += ex.len() as u64;
                wasm_index.push(json!({
                    "hash": r.h,
                    "bytes": payload.len(),
                    "ts": r.ts,
                    "pid": r.pid,
                    "imports": im.iter().take(256).cloned().collect::<Vec<_>>(),
                    "exports": ex.iter().take(256).cloned().collect::<Vec<_>>(),
                }));
            }
        }
    }

    // drop cold chains from disk (they stay counted in the report)
    let mut hot = 0usize;
    let mut cold = 0usize;
    let mut chain_report = Vec::new();
    let big_keep = 96 * 1024usize;
    for c in &mut chain_list {
        let keep = c.hot || stats.keep_cold || c.bytes as usize >= big_keep;
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
        chain_report.push(json!({
            "name": printable(&c.name, 200),
            "frags": c.frags,
            "bytes": c.bytes,
            "hot": c.hot,
            "ts0": c.first_ts,
            "ts1": c.last_ts,
            "path": c.path,
        }));
    }

    // ---- 4: timing chains: trigger -> network ------------------------------
    // recs are ts-sorted; a moving cursor finds, for every network request,
    // the latest trigger (input/event/timer/dom/fingerprint) before it.
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
        let entry = match best.map(|i| &recs[i]) {
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
        "per_kind": per_kind,
        "scripts": {
            "fragments": stats.fragments,
            "chains": stats.chains,
            "hot": stats.hot_chains,
            "cold_dropped": stats.cold_chains,
            "keep_cold": stats.keep_cold,
            "chain_bytes": stats.chain_bytes,
        },
        "wasm": {
            "modules": stats.wasm_modules,
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
}
