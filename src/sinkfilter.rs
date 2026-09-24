use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write;
use std::path::Path;

// sinkfilter v2: МЕХАНИЧЕСКИЙ ЭКСТРАКТОР. Только факты из записей:
// цепи script-source (группировка фрагментов), дампы wasm-модулей,
// список net-запросов с vendor-матчингом по URL, ценз kind'ов, счётчики
// компиляций (exec jit/byte/wasm из JitLogger-записей), маркеры
// автоматизации из error-stack, input cadence, drop-свидетели.
//
// ВЫРЕЗАНО (было угадыванием, стало ненужным с 0033):
// - content-graph на blake3-окнах + BFS + CSR (связность по совпадению
//   байт в тайм-окнах) — поток данных теперь виден напрямую в
//   bctrace sem/*.jsonl: операнды/регистры/аккумулятор каждой
//   инструкции с engine-decoded значениями.
// - вердикты proven/heuristic/dead-end-proven/unresolved — живость
//   кода определяется по ФАКТУ исполнения: bctrace dead_blocks
//   (offset не встретился в потоке) и executed_scripts (скрипт не
//   исполнил ни одной инструкции).
// - тайм-окна (50ms/250ms/5s), trigger-корреляции, EntryIndex-джойны,
//   is_hot-оракул на подстроках, custom-alphabet мост, taint-union'ы,
//   net-window/content-bridge атрибyция — всё это были предположения.

#[derive(Default, Debug, Clone, Copy)]
pub struct SinkFilterStats {
    pub records: u64,
    pub fragments: u64,
    pub chains: u64,
    pub chain_bytes: u64,
    pub wasm_modules: u64,
    pub wasm_imports: u64,
    pub wasm_exports: u64,
    pub wasm_cached: u64,
    pub wasm_instantiated: u64,
    pub wasm_firstcalls: u64,
    pub wasm_traps: u64,
    pub wasm_mem_grows: u64,
    pub net_requests: u64,
    pub net_vendor_requests: u64,
    pub exec_compiles: u64,
    pub exec_jit: u64,
    pub exec_byte: u64,
    pub exec_wasm_code: u64,
    pub lazy_funcs: u64,
    pub automation_tells: u64,
    pub input_total: u64,
    pub drop_total: u64,
}

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
        let sec_id = match r.u8() {
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
        if sec_id == 2 {
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
        } else if sec_id == 7 {
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
    name: String,
    frags: u64,
    bytes: u64,
    first_ts: u64,
    last_ts: u64,
    path: String,
    iso: Option<String>,
    worker: Option<String>,
}

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

fn median_of(mut v: Vec<u64>) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    Some(v[v.len() / 2])
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
        if out.len() >= 120 {
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

pub fn run(collect_dir: &Path) -> Result<SinkFilterStats, String> {
    let mut stats = SinkFilterStats::default();
    let index_p = collect_dir.join("index.jsonl");
    let raw_dir = collect_dir.to_path_buf();
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
        let kind = v.get("k").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if kind == "sink-hello" {
            continue;
        }
        stats.records += 1;
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

    // ---- pass 1: event census (facts only) ----
    let mut workers: Vec<(u64, String, String)> = Vec::new();
    let mut wasm_inst: Vec<(u64, u64, bool, String)> = Vec::new();
    let mut automation_tells: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut drop_total: u64 = 0;
    let mut nav_start: Option<u64> = None;
    let mut exec_per_name: HashMap<String, u64> = HashMap::new();
    let mut input_deltas: Vec<u64> = Vec::new();
    let mut input_per_type: BTreeMap<String, u64> = BTreeMap::new();
    let mut input_path_px = 0.0f64;
    let mut input_prev_xy: Option<(f64, f64)> = None;
    let mut input_prev_ts = 0u64;
    let mut input_first_ts = 0u64;
    let mut input_last_ts = 0u64;

    for r in &recs {
        let txt = r.txt.as_deref().unwrap_or("");
        match r.kind.as_str() {
            "worker" => {
                if let Some((iso, name)) = worker_of(txt) {
                    workers.push((r.ts, iso, name));
                }
            }
            "wasm-instance" => {
                let header = txt.starts_with("wasm-instantiate");
                wasm_inst.push((r.ts, r.pid, header, txt.to_string()));
                if txt.starts_with("wasm-firstcall ") {
                    stats.wasm_firstcalls += 1;
                } else if txt.starts_with("wasm-trap ") {
                    stats.wasm_traps += 1;
                } else if txt.starts_with("wasm-mem grow ") {
                    stats.wasm_mem_grows += 1;
                }
            }
            "error-stack" => {
                for marker in AUTOMATION_MARKERS {
                    if txt.contains(marker) {
                        *automation_tells.entry(*marker).or_insert(0) += 1;
                    }
                }
            }
            "sink-drop" => {
                if let Some(n) = txt.split("dropped=").nth(1) {
                    if let Ok(n) = n.trim().parse::<u64>() {
                        drop_total = drop_total.max(n);
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
            "isolate" => {
                if txt.starts_with("exec ") {
                    stats.exec_compiles += 1;
                    if txt.starts_with("exec jit ") {
                        stats.exec_jit += 1;
                    } else if txt.starts_with("exec byte ") {
                        stats.exec_byte += 1;
                    } else if txt.starts_with("exec wasm ") {
                        stats.exec_wasm_code += 1;
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
            "call-completed" => {
                if let Some(rest) = txt.strip_prefix("lazy-compile ") {
                    stats.lazy_funcs += 1;
                    let _ = rest;
                }
            }
            "input" => {
                if let Some((etype, xy)) = parse_input_rec(txt) {
                    stats.input_total += 1;
                    *input_per_type.entry(etype.to_string()).or_insert(0) += 1;
                    if input_first_ts == 0 {
                        input_first_ts = r.ts;
                    }
                    if input_prev_ts != 0 && r.ts > input_prev_ts {
                        input_deltas.push((r.ts - input_prev_ts) / 1000);
                    }
                    input_prev_ts = r.ts;
                    input_last_ts = r.ts;
                    if let Some((x, y)) = xy {
                        if let Some((px, py)) = input_prev_xy {
                            input_path_px += ((x - px) * (x - px) + (y - py) * (y - py)).sqrt();
                        }
                        input_prev_xy = Some((x, y));
                    }
                }
            }
            _ => {}
        }
    }
    stats.automation_tells = automation_tells.values().sum();
    stats.drop_total = drop_total;

    // ---- pass 2: script-source chains + wasm modules ----
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
                    chain_list.push(Chain {
                        file,
                        name: display,
                        frags: 0,
                        bytes: 0,
                        first_ts: r.ts,
                        last_ts: r.ts,
                        path: format!("filtered/scripts/{}", fname),
                        iso,
                        worker,
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
                let hdr = wasm_inst.iter().find(|(ts, pid, header, _)| {
                    *header && *pid == r.pid && *ts >= r.ts && *ts <= r.ts + 5_000_000_000
                });
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
                        if *pid != r.pid || *ts <= *hts || *ts > *hts + 5_000_000_000 {
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

    for c in &mut chain_list {
        if let Some(f) = c.file.as_mut() {
            let _ = f.sync_all();
        }
        stats.chain_bytes += c.bytes;
    }
    stats.chains = chain_list.len() as u64;

    // executed_funcs per chain name (lazy-compile/exec counts are facts
    // from JitLogger records, joined by exact script name)
    let mut exec_by_name: HashMap<String, u64> = HashMap::new();
    for (name, n) in &exec_per_name {
        exec_by_name.insert(name.clone(), *n);
    }

    // ---- pass 3: net-request census with vendor match ----
    let mut net_index: Vec<serde_json::Value> = Vec::new();
    let mut net_vendor_counts: BTreeMap<String, u64> = BTreeMap::new();
    for r in recs.iter().filter(|r| r.kind == "net-request") {
        let txt = r.txt.as_deref().unwrap_or("");
        let (method, url) = match txt.find('\u{0}') {
            Some(i) => (&txt[..i], &txt[i + 1..]),
            None => ("", txt),
        };
        stats.net_requests += 1;
        let vendor = af_vendor_of_url(url);
        if let Some(v) = vendor {
            stats.net_vendor_requests += 1;
            *net_vendor_counts.entry(v.to_string()).or_insert(0) += 1;
        }
        if net_index.len() < 8192 {
            let mut entry = json!({
                "ts": r.ts,
                "method": method,
                "url": txt_head(url, 240),
            });
            if let Some(v) = vendor {
                entry["vendor"] = json!(v);
            }
            if let Some(t0) = nav_start {
                if r.ts >= t0 {
                    entry["t_rel_ms"] = json!((r.ts - t0) / 1_000_000);
                }
            }
            net_index.push(entry);
        }
    }

    // ---- report ----
    let chain_report: Vec<serde_json::Value> = chain_list
        .iter()
        .map(|c| {
            let mut entry = json!({
                "name": printable(&c.name, 200),
                "frags": c.frags,
                "bytes": c.bytes,
                "ts0": c.first_ts,
                "ts1": c.last_ts,
                "path": c.path,
            });
            if let Some(iso) = &c.iso {
                entry["isolate"] = json!(iso);
            }
            if let Some(w) = &c.worker {
                entry["worker"] = json!(w);
            }
            if let Some(n) = exec_by_name.get(&c.name) {
                entry["exec_records"] = json!(n);
            }
            if let Some(t0) = nav_start {
                if c.first_ts >= t0 {
                    entry["ts0_rel_ms"] = json!((c.first_ts - t0) / 1_000_000);
                    entry["ts1_rel_ms"] = json!((c.last_ts - t0) / 1_000_000);
                }
            }
            entry
        })
        .collect();

    let mut per_kind: BTreeMap<String, u64> = BTreeMap::new();
    for r in &recs {
        *per_kind.entry(format!("{}/{}", r.layer, r.kind)).or_insert(0) += 1;
    }

    let n = input_deltas.len();
    let report = json!({
        "records": stats.records,
        "nav_start_ts": nav_start,
        "per_kind": per_kind,
        "scripts": {
            "fragments": stats.fragments,
            "chains": stats.chains,
            "chain_bytes": stats.chain_bytes,
        },
        "wasm": {
            "modules": stats.wasm_modules,
            "instantiated": stats.wasm_instantiated,
            "cached": stats.wasm_cached,
            "firstcalls": stats.wasm_firstcalls,
            "traps": stats.wasm_traps,
            "mem_grows": stats.wasm_mem_grows,
            "imports": stats.wasm_imports,
            "exports": stats.wasm_exports,
            "index": wasm_index,
        },
        "net": {
            "requests": stats.net_requests,
            "vendor_requests": stats.net_vendor_requests,
            "vendor_counts": net_vendor_counts,
            "index": net_index,
        },
        "exec": {
            "compiles": stats.exec_compiles,
            "jit": stats.exec_jit,
            "byte": stats.exec_byte,
            "wasm_code": stats.exec_wasm_code,
            "lazy_funcs": stats.lazy_funcs,
        },
        "input": {
            "total": stats.input_total,
            "per_type": input_per_type,
            "median_delta_us": median_of(input_deltas.clone()),
            "p90_delta_us": if n > 0 {
                let mut d = input_deltas;
                d.sort_unstable();
                Some(d[((n as f64) * 0.9) as usize])
            } else {
                None
            },
            "path_px": input_path_px as u64,
            "span_ms": if input_first_ts != 0 && input_last_ts >= input_first_ts {
                (input_last_ts - input_first_ts) / 1_000_000
            } else {
                0
            },
        },
        "automation_tells": automation_tells,
        "drop_total": drop_total,
        "chains": chain_report,
        "rule": "v2: facts only - chains/wasm/net/exec/input/drops are direct record censuses. Liveness and dataflow come from bctrace (0033 bytecode trace): dead blocks = decoded offsets absent from the executed stream; executed_scripts lists scripts with >=1 instruction. No time windows, no content hashing, no verdicts.",
    });
    let _ = fs::write(
        filt.join("report.json"),
        serde_json::to_vec_pretty(&report).unwrap_or_default(),
    );

    Ok(stats)
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
    fn name_split_and_iso() {
        let payload = b"iso:0x7f script.js\x00console.log(1)".to_vec();
        let (name, body) = name_of(&payload);
        let (iso, display) = split_iso(&name);
        assert_eq!(iso.as_deref(), Some("0x7f"));
        assert_eq!(display, "script.js");
        assert_eq!(body, b"console.log(1)".to_vec());
    }

    #[test]
    fn vendor_match_by_host_suffix() {
        assert_eq!(
            af_vendor_of_url("https://geo.px-client.net/api/v2/x"),
            Some("human")
        );
        assert_eq!(
            af_vendor_of_url("https://example.com/cdn-cgi/challenge"),
            Some("cloudflare")
        );
        assert_eq!(af_vendor_of_url("https://example.com/x"), None);
        // suffix must be dot-boundaried
        assert_eq!(af_vendor_of_url("https://notkasada.io/x"), None);
    }

    #[test]
    fn batched_payload_slice() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("part.bin"), b"AAAABBBBCCCC").unwrap();
        let r = Rec {
            ts: 1,
            pid: 1,
            layer: "blink".into(),
            kind: "dom-api".into(),
            len: 4,
            h: "x".into(),
            path: "part.bin".into(),
            off: Some(4),
            txt: None,
        };
        assert_eq!(read_payload(dir.path(), &r).unwrap(), b"BBBB".to_vec());
    }

    #[test]
    fn run_produces_fact_report() {
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("collect");
        let raw = cd.join("raw");
        fs::create_dir_all(&raw).unwrap();
        fs::write(raw.join("a.bin"), b"\x00console.log(1)").unwrap();
        // script-source record: payload = "\x00" name separator + body
        let mut idx = String::new();
        idx.push_str(&format!(
            "{{\"ts\":100,\"l\":\"v8\",\"pid\":7,\"k\":\"script-source\",\"len\":15,\"h\":\"abcd1234ef\",\"p\":\"raw/a.bin\"}}\n"
        ));
        idx.push_str(&format!(
            "{{\"ts\":200,\"l\":\"net\",\"pid\":7,\"k\":\"net-request\",\"len\":40,\"h\":\"ff\",\"p\":\"raw/a.bin\",\"txt\":\"POST\\u0000https://geo.px-client.net/init\"}}\n"
        ));
        idx.push_str(&format!(
            "{{\"ts\":300,\"l\":\"v8\",\"pid\":7,\"k\":\"sink-drop\",\"len\":20,\"h\":\"ee\",\"p\":\"raw/a.bin\",\"txt\":\"sink-drop layer=v8 dropped=3\"}}\n"
        ));
        idx.push_str(&format!(
            "{{\"ts\":50,\"l\":\"v8\",\"pid\":7,\"k\":\"sink-hello\",\"len\":5,\"h\":\"dd\",\"p\":\"raw/a.bin\"}}\n"
        ));
        fs::write(cd.join("index.jsonl"), &idx).unwrap();

        let st = run(&cd).unwrap();
        assert_eq!(st.records, 3, "sink-hello not counted");
        assert_eq!(st.chains, 1);
        assert_eq!(st.fragments, 1);
        assert_eq!(st.net_requests, 1);
        assert_eq!(st.net_vendor_requests, 1);
        assert_eq!(st.drop_total, 3);

        let rep: serde_json::Value =
            serde_json::from_slice(&fs::read(cd.join("filtered/report.json")).unwrap()).unwrap();
        assert_eq!(rep["net"]["vendor_counts"]["human"], 1);
        assert_eq!(rep["scripts"]["chains"], 1);
        // no verdicts in the report - facts only
        assert!(rep.get("classification").is_none());
        assert!(rep.get("graph").is_none());
        assert!(rep["chains"][0].get("verdict").is_none());
        assert!(rep["chains"][0].get("token_forming").is_none());
    }
}
