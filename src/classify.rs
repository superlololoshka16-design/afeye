use crate::ctx::{endpoint_of, host_of, vendor_of_url};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct ClsOut {
    pub af: u64,
    pub garbage: u64,
    pub neutral: u64,
    pub scripts: u64,
    pub kept: u64,
    pub dup: u64,
    pub art_rm: u64,
    pub bytes_rm: u64,
}

const STRONG: &[&str] = &[
    "toDataURL",
    "toBlob",
    "getImageData",
    "getParameter",
    "getExtension",
    "getSupportedExtensions",
    "getShaderPrecisionFormat",
    "getFloatFrequencyData",
    "startRendering",
    "convertToBlob",
    "new:OffscreenCanvas",
    "new:OfflineAudioContext",
    "sab",
    "wmem:new",
    "call:eval",
    "new:Function",
    "shaderSource",
];

const WEAK: &[&str] = &[
    "g:plugins",
    "g:mimeTypes",
    "g:hardwareConcurrency",
    "g:deviceMemory",
    "g:platform",
    "g:languages",
    "g:userAgent",
    "g:width",
    "g:height",
    "g:colorDepth",
    "Math.random",
    "new:AudioContext",
    "po:new",
    "wasm:instantiate",
    "getContext",
];

const BLACKLIST: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "googleadservices.com",
    "adservice.google.com",
    "hotjar.com",
    "sentry.io",
    "ingest.sentry.io",
    "amplitude.com",
    "mixpanel.com",
    "segment.io",
    "segment.com",
    "clarity.ms",
    "mc.yandex.ru",
    "an.yandex.ru",
    "scorecardresearch.com",
    "quantserve.com",
    "quantcount.com",
    "casalemedia.com",
    "rubiconproject.com",
    "pubmatic.com",
    "criteo.com",
    "criteo.net",
    "adnxs.com",
    "adsrvr.org",
    "taboola.com",
    "outbrain.com",
    "demdex.net",
    "everesttech.net",
    "omtrdc.net",
    "2o7.net",
    "pixel.facebook.com",
    "analytics.tiktok.com",
    "bat.bing.com",
    "alb.reddit.com",
    "pixel.reddit.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "cloudflareinsights.com",
    "rum.aliyuncs.com",
    "log.aliyuncs.com",
    "play.google.com",
    "pixel-config.reddit.com",
    "ads-twitter.com",
    "analytics.twitter.com",
    "app-measurement.com",
    "analytics.google.com",
    "youtube.com",
    "youtube-nocookie.com",
    "ytimg.com",
    "video.google.com",
];

const COOKIE_SIGS: &[&str] = &[
    "datadome",
    "_dd_s",
    "_abck",
    "bm_sz",
    "ak_bmsc",
    "cf_clearance",
    "__cf_bm",
    "_cfuvid",
    "pxhd",
    "pxcd",
    "kasada",
];

const BLACKLIST_PATH: &[(&str, &str)] = &[
    ("www.google.com", "/g/collect"),
    ("www.google.com", "/measurement"),
    ("www.google.com", "/ccm/"),
    ("www.google.com", "/pagead/"),
    ("www.google.com", "/log?"),
];

const RES_TYPES: &[&str] = &["Image", "Font", "Stylesheet", "Media", "Manifest", "Favicon"];

#[derive(PartialEq, Clone, Copy)]
pub enum Mode {
    Main,
    Strict,
}

fn res_family(ty: &str) -> u8 {
    match ty {
        "Image" | "Favicon" => 1,
        "Media" => 2,
        "Font" => 3,
        "Stylesheet" | "Manifest" => 4,
        _ => 0,
    }
}

fn binary_magic(b: &[u8]) -> u8 {
    if b.starts_with(&[0x89, b'P', b'N', b'G'])
        || b.starts_with(&[0xFF, 0xD8, 0xFF])
        || b.starts_with(b"GIF8")
        || b.starts_with(b"BM")
        || (b.len() > 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP")
        || (b.len() >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 1 && b[3] == 0)
    {
        return 1;
    }
    if b.starts_with(b"ID3")
        || (b.len() > 2 && b[0] == 0xFF && (b[1] & 0xE0) == 0xE0)
        || b.starts_with(b"OggS")
        || b.starts_with(b"fLaC")
        || (b.len() > 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WAVE")
        || (b.len() > 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"AVI ")
        || (b.len() > 12 && &b[4..8] == b"ftyp")
    {
        return 2;
    }
    if b.starts_with(b"wOFF") || b.starts_with(b"wOF2") || b.starts_with(b"OTTO") || (b.len() >= 4 && b[0] == 0 && b[1] == 1 && b[2] == 0 && b[3] == 0) {
        return 3;
    }
    0
}

fn textish(b: &[u8]) -> bool {
    let n = b.len().min(4096);
    if n == 0 {
        return false;
    }
    let mut ok = 0usize;
    for &c in &b[..n] {
        if (32..127).contains(&c) || c == b'\n' || c == b'\r' || c == b'\t' || c >= 0x80 {
            ok += 1;
        }
    }
    ok * 100 / n >= 90
}

fn js_like(b: &[u8]) -> bool {
    let n = b.len().min(4096);
    let s = String::from_utf8_lossy(&b[..n]).to_ascii_lowercase();
    for pat in [
        "function",
        "=>",
        "eval(",
        "document.",
        "window.",
        "atob(",
        "fromcharcode",
        "new function",
    ] {
        if s.contains(pat) {
            return true;
        }
    }
    false
}

fn res_sniff_ok(b: &[u8], fam: u8) -> bool {
    if b.is_empty() {
        return true;
    }
    match fam {
        1..=3 => binary_magic(b) == fam,
        4 => textish(b) && !js_like(b),
        _ => true,
    }
}

fn read_head(p: &std::path::Path, n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buf = vec![0u8; n];
    match std::fs::File::open(p).and_then(|mut f| f.read(&mut buf)) {
        Ok(k) => {
            buf.truncate(k);
            buf
        }
        Err(_) => Vec::new(),
    }
}

const KEEP_PREFIXES: &[&str] = &[
    "stk:", "src:", "wasm", "wmem:", "sab", "po:", "_boot", "_th", "_c", "_m", "_dr", "new:",
    "call:", "listen", "setattr:", "slow:", "mq:", "worker:src", "gl:shader",
];

fn is_del(c: u8) -> bool {
    matches!(
        c,
        b'"' | b'\'' | b',' | b':' | b';' | b'=' | b'&' | b'{' | b'}' | b'[' | b']' | b'(' | b')' | b'<' | b'>'
            | b'?' | b'/' | b'\\' | b'+' | b'|' | b'*' | b'#' | b'%'
    )
}

pub fn fnv32(b: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &c in b {
        h ^= c as u32;
        h = h.wrapping_mul(16_777_619);
    }
    h
}

#[cfg(test)]
fn fnv32_units(s: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for c in s.chars() {
        let u = c as u32;
        h ^= u & 0xffff;
        h = h.wrapping_mul(16_777_619);
        if u > 0xffff {
            h ^= u >> 16;
            h = h.wrapping_mul(16_777_619);
        }
    }
    h
}

#[cfg(test)]
fn ascii_units_parity(s: &str) -> bool {
    fnv32(s.as_bytes()) == fnv32_units(s)
}

fn body_taint_hits(b: &[u8], taint: &HashSet<u32>) -> usize {
    let lim = b.len().min(4096);
    let mut n = 0;
    let mut run = 0usize;
    let mut h: u32 = 0x811c_9dc5;
    for &c in b.iter().take(lim).chain(std::iter::once(&b' ')) {
        if c > 32 && c < 127 && !is_del(c) {
            h ^= c as u32;
            h = h.wrapping_mul(16_777_619);
            run += 1;
        } else {
            if run >= 3 && taint.contains(&h) {
                n += 1;
            }
            h = 0x811c_9dc5;
            run = 0;
        }
    }
    n
}

pub fn entropy(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    let mut h = [0u64; 256];
    for &c in b {
        h[c as usize] += 1;
    }
    let n = b.len() as f64;
    let mut e = 0.0;
    for &x in &h {
        if x > 0 {
            let p = x as f64 / n;
            e -= p * p.log2();
        }
    }
    e
}

fn strip_ln(mut u: &str) -> &str {
    for _ in 0..2 {
        if let Some(p) = u.rfind(':') {
            if !u[p + 1..].is_empty() && u[p + 1..].chars().all(|c| c.is_ascii_digit()) {
                u = &u[..p];
                continue;
            }
        }
        break;
    }
    u
}

pub fn first_stack_url(s: &str) -> Option<&str> {
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < s.len() {
        let p = i + s[i..].find("http")?;
        let mut e = p;
        while e < b.len() && !matches!(b[e], b')' | b' ' | b'\n' | b'"' | b';' | b',' | b'\'' | b'}' | b'\\') {
            e += 1;
        }
        let u = strip_ln(&s[p..e]);
        if u.len() > 10 {
            return Some(u);
        }
        i = e.max(p + 4);
    }
    None
}

// CDP stack frames arrive as "fn@https://host/path.js:line[:col];..." -
// one frame per ';' part, url after the LAST '@', :line[:col] stripped.
fn parse_cdp_stack(s: &str) -> Vec<String> {
    let mut stk = Vec::new();
    for part in s.split(';') {
        if let Some(at) = part.rfind('@') {
            let u = strip_ln(&part[at + 1..]);
            if u.len() > 10 {
                stk.push(u.to_owned());
            }
        }
    }
    stk
}

fn blacklisted(host: &str) -> bool {
    BLACKLIST.iter().any(|s| host == *s || (host.len() > s.len() && host.ends_with(s) && host.as_bytes()[host.len() - s.len() - 1] == b'.'))
}

fn blacklisted_path(url: &str) -> bool {
    let p = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => return false,
    };
    let (h, rest) = match p.find('/') {
        Some(i) => (&p[..i], &p[i..]),
        None => return false,
    };
    BLACKLIST_PATH.iter().any(|(bh, bp)| h == *bh && rest.starts_with(bp))
}

#[derive(Clone)]
struct ReqInfo {
    url: String,
    method: String,
    ty: Option<String>,
    stk: Vec<String>,
    post_hash: Option<String>,
    setcookie: Option<String>,
}

#[derive(Clone)]
struct Ep {
    n: u64,
    dup: u64,
    method: String,
    vendor: Option<String>,
    af: Vec<String>,
    garbage: Vec<String>,
}

impl Ep {
    fn new(method: &str) -> Ep {
        Ep {
            n: 0,
            dup: 0,
            method: method.to_owned(),
            vendor: None,
            af: Vec::new(),
            garbage: Vec::new(),
        }
    }
    fn verdict(&self) -> u8 {
        if !self.af.is_empty() {
            1
        } else if !self.garbage.is_empty() {
            2
        } else {
            0
        }
    }
}

struct SiteState {
    taint: HashSet<u32>,
    script_tags: HashMap<String, HashSet<String>>,
    req: HashMap<String, ReqInfo>,
    ep: HashMap<String, Ep>,
    tn_sum: HashMap<String, u64>,
    ws_url: HashMap<String, String>,
    art_bodies: HashMap<String, String>,
    art_src: HashMap<String, String>,
}

impl SiteState {
    fn new() -> SiteState {
        SiteState {
            taint: HashSet::new(),
            script_tags: HashMap::new(),
            req: HashMap::new(),
            ep: HashMap::new(),
            tn_sum: HashMap::new(),
            ws_url: HashMap::new(),
            art_bodies: HashMap::new(),
            art_src: HashMap::new(),
        }
    }

    fn ep_of(&mut self, url: &str, method: &str) -> &mut Ep {
        let ep = endpoint_of(url);
        let key = if ep.is_empty() { url } else { ep };
        self.ep.entry(key.to_owned()).or_insert_with(|| Ep::new(method))
    }

    fn ep_key(&self, url: &str) -> String {
        let ep = endpoint_of(url);
        if ep.is_empty() { url } else { ep }.to_owned()
    }
}

fn collect_site(state: &mut SiteState, tl: &std::path::Path) {
    let f = match File::open(tl) {
        Ok(f) => f,
        Err(_) => return,
    };
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        let v: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(kk) = v.get("kk").and_then(|x| x.as_str()) {
            let val = v.get("v");
            if let Some(arr) = val.and_then(|x| x.as_array()) {
                if kk == "_th" {
                    for h in arr {
                        if let Some(n) = h.as_u64() {
                            state.taint.insert(n as u32);
                        }
                    }
                } else if kk == "net:send" {
                    let u = arr.first().and_then(|x| x.as_str()).unwrap_or("");
                    let m = arr.get(1).and_then(|x| x.as_str()).unwrap_or("GET");
                    let tn = arr.get(4).and_then(|x| x.as_u64()).unwrap_or(0);
                    if !u.is_empty() {
                        let k = state.ep_key(u);
                        state.tn_sum.entry(k).and_modify(|x| *x += tn).or_insert(tn);
                        {
                            let e = state.ep_of(u, m);
                            e.n += 1;
                        }
                    }
                } else if let Some(st) = kk.strip_prefix("stk:") {
                    if let Some(stack) = arr.first().and_then(|x| x.as_str()) {
                        if let Some(u) = first_stack_url(stack) {
                            state.script_tags.entry(u.to_owned()).or_default().insert(st.to_owned());
                        }
                    }
                }
            }
            continue;
        }
        let k = match v.get("k").and_then(|x| x.as_u64()) {
            Some(k) => k,
            None => continue,
        };
        let d = match v.get("d") {
            Some(d) => d,
            None => continue,
        };
        match k {
            1 => {
                let rid = d.get("rid").and_then(|x| x.as_str()).unwrap_or("").to_owned();
                let url = d.get("u").and_then(|x| x.as_str()).unwrap_or("").to_owned();
                let method = d.get("m").and_then(|x| x.as_str()).unwrap_or("GET").to_owned();
                let ty = d.get("ty").and_then(|x| x.as_str()).map(|s| s.to_owned());
                let mut stk = Vec::new();
                if let Some(s) = d.get("stk").and_then(|x| x.as_str()) {
                    stk = parse_cdp_stack(s);
                }
                if let Some(iu) = d.get("iniu").and_then(|x| x.as_str()) {
                    if iu.len() > 10 {
                        stk.push(strip_ln(iu).to_owned());
                    }
                }
                if let Some(r) = state.req.get_mut(&rid) {
                    if r.url.is_empty() && !url.is_empty() {
                        r.url = url.clone();
                        r.method = method.clone();
                    }
                    continue;
                }
                if !rid.is_empty() {
                    state.req.insert(rid, ReqInfo { url, method, ty, stk, post_hash: None, setcookie: None });
                }
            }
            2 => {
                let rid = d.get("rid").and_then(|x| x.as_str()).unwrap_or("").to_owned();
                if let Some(r) = state.req.get_mut(&rid) {
                    if let Some(h) = d.get("h").and_then(|x| x.as_object()) {
                        for (hk, hv) in h {
                            if hk.eq_ignore_ascii_case("set-cookie") {
                                if let Some(s) = hv.as_str() {
                                    r.setcookie = Some(s.to_owned());
                                }
                            }
                        }
                    }
                }
            }
            3 => {
                let rid = d.get("rid").and_then(|x| x.as_str()).unwrap_or("").to_owned();
                let a = d.get("a").and_then(|x| x.as_str()).unwrap_or("").to_owned();
                let x = d.get("x").and_then(|x| x.as_str()).unwrap_or("").to_owned();
                if !a.is_empty() {
                    state.art_bodies.insert(a.clone(), rid.clone());
                }
                if let Some(r) = state.req.get_mut(&rid) {
                    if x == "post" {
                        r.post_hash = Some(a);
                    }
                }
            }
            6 => {
                let rid = d.get("rid").and_then(|x| x.as_str()).unwrap_or("").to_owned();
                if d.get("f").and_then(|x| x.as_str()) == Some("created") {
                    if let Some(u) = d.get("u").and_then(|x| x.as_str()) {
                        if u.starts_with("ws") || u.starts_with("http") {
                            state.ws_url.insert(rid, u.to_owned());
                        }
                    }
                }
            }
            7 => {
                if let Some(u) = d.get("u").and_then(|x| x.as_str()) {
                    if u.starts_with("http") {
                    }
                }
            }
            8 => {
                let a = d.get("a").and_then(|x| x.as_str()).unwrap_or("").to_owned();
                let u = d.get("u").and_then(|x| x.as_str()).unwrap_or("").to_owned();
                if !a.is_empty() && u.starts_with("http") {
                    state.art_src.insert(a, u);
                }
            }
            _ => {}
        }
    }
}

fn tag_class(t: &str) -> u8 {
    if STRONG.contains(&t) {
        2
    } else if t.starts_with("g:") || WEAK.contains(&t) {
        1
    } else {
        0
    }
}

fn tainted_scripts(state: &SiteState) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for (u, tags) in &state.script_tags {
        let mut s = 0usize;
        let mut w = 0usize;
        for t in tags {
            match tag_class(t) {
                2 => s += 1,
                1 => w += 1,
                _ => {}
            }
        }
        if s >= 2 || (s >= 1 && w >= 5) {
            let mut sorted: Vec<String> = tags.iter().cloned().collect();
            sorted.sort();
            out.push((u.clone(), sorted));
        }
    }
    out.sort();
    out
}

// Engine-fact bridge: the inject.rs JS harness that used to emit _th/stk:
// tags is gone, so script_tags/body-taint can no longer be sourced from
// CDP heuristics. The authoritative fact is the sinkfilter verdict: a
// script whose chain is proven-causality / proven-value crossed a
// boundary with antifraud data BY FACT (causality trace id or byte-exact
// executed value). Load those script names from collect/filtered/report.json
// and seed the taint set with them.
fn proven_scripts(stage: &std::path::Path) -> HashSet<String> {
    let mut out: HashSet<String> = HashSet::new();
    let p = stage.join("collect").join("filtered").join("report.json");
    let data = match std::fs::read(&p) {
        Ok(d) => d,
        Err(_) => return out,
    };
    let v: Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(_) => return out,
    };
    let chains = match v.get("chains").and_then(|c| c.as_array()) {
        Some(c) => c,
        None => return out,
    };
    for ch in chains {
        let verdict = ch.get("verdict").and_then(|x| x.as_str()).unwrap_or("");
        if verdict != "proven-causality" && verdict != "proven-value" {
            continue;
        }
        if let Some(name) = ch.get("name").and_then(|x| x.as_str()) {
            if name.len() > 10 {
                out.insert(strip_iso_prefix(name).to_owned());
            }
        }
    }
    out
}

fn strip_iso_prefix(name: &str) -> &str {
    match name.strip_prefix("iso:") {
        Some(rest) => match rest.find(' ') {
            Some(sp) => &rest[sp + 1..],
            None => rest,
        },
        None => name,
    }
}

fn first_party(host: &str, site_host: &str) -> bool {
    host == site_host || (host.len() > site_host.len() && host.ends_with(site_host) && host.as_bytes()[host.len() - site_host.len() - 1] == b'.')
}

fn push_once(ep: &mut HashMap<String, Ep>, k: &str, why: &str) {
    if let Some(e) = ep.get_mut(k) {
        if !e.af.iter().any(|x| x == why) {
            e.af.push(why.to_owned());
        }
    }
}

fn verdict_site(state: &mut SiteState, stage: &std::path::Path, arts: &HashMap<String, std::path::PathBuf>, site_host: &str) {
    let mut tainted: HashSet<String> =
        tainted_scripts(state).into_iter().map(|(u, _)| u).collect();
    // engine-fact bridge: proven-causality/proven-value scripts from the
    // sinkfilter report are antifraud BY FACT, not by kk-heuristic guess.
    tainted.extend(proven_scripts(stage));
    let mut rid_art: HashMap<String, String> = HashMap::new();
    for (a, rid) in &state.art_bodies {
        rid_art.entry(rid.clone()).or_insert_with(|| a.clone());
    }
    let reqs: Vec<(String, ReqInfo)> = state.req.iter().map(|(rid, r)| (rid.clone(), r.clone())).collect();
    for (rid, r) in reqs {
        if r.url.is_empty() {
            continue;
        }
        {
            let e = state.ep_of(&r.url, &r.method);
            e.n += 1;
        }
        let k = state.ep_key(&r.url);
        let host = host_of(&r.url);
        if blacklisted(host) || blacklisted_path(&r.url) {
            state.ep.get_mut(&k).unwrap().garbage.push("blacklist".into());
            continue;
        }
        if let Some(v) = vendor_of_url(&r.url) {
            if !first_party(host_of(&r.url), site_host) {
                let e = state.ep.get_mut(&k).unwrap();
                e.vendor = Some(v.to_owned());
                e.af.push(format!("vendor:{v}"));
            }
        }
        let is_doc = r.ty.as_deref() == Some("Document");
        if !is_doc && r.stk.iter().any(|u| tainted.contains(u)) {
            state.ep.get_mut(&k).unwrap().af.push("taint-script".into());
        }
        if let Some(ty) = &r.ty {
            if RES_TYPES.contains(&ty.as_str()) {
                let fam = res_family(ty);
                let masked = match rid_art.get(&rid) {
                    None => false,
                    Some(h) => match arts.get(h) {
                        Some(p) => {
                            let head = read_head(p, 4096);
                            !head.is_empty() && !res_sniff_ok(&head, fam)
                        }
                        None => false,
                    },
                };
                if masked {
                    state.ep.get_mut(&k).unwrap().af.push(format!("masked:{ty}"));
                } else {
                    state.ep.get_mut(&k).unwrap().garbage.push(format!("res:{ty}"));
                }
            }
        }
        if let Some(sc) = &r.setcookie {
            let low = sc.to_ascii_lowercase();
            for sig in COOKIE_SIGS {
                if low.contains(sig) {
                    push_once(&mut state.ep, &k, &format!("cookie:{sig}"));
                }
            }
        }
        if let Some(h) = &r.post_hash {
            let p = stage.join("artifacts").join(format!("{h}.post"));
            if let Ok(b) = std::fs::read(&p) {
                if b.len() >= 64 && b.len() <= 512 * 1024 {
                    let hits = body_taint_hits(&b, &state.taint);
                    if hits > 0 {
                        state.ep.get_mut(&k).unwrap().af.push(format!("taint-body:{hits}"));
                    }
                    let en = entropy(&b);
                    if en > 6.5 {
                        state.ep.get_mut(&k).unwrap().af.push(format!("entropy:{en:.2}"));
                    }
                }
            }
        }
    }
    for (k, tn) in state.tn_sum.iter() {
        if *tn > 0 {
            if let Some(e) = state.ep.get_mut(k) {
                if e.garbage.is_empty() || !e.garbage.iter().any(|g| g == "blacklist") {
                    e.af.push(format!("tn:{tn}"));
                }
            }
        }
    }
    let eps: Vec<String> = state.ep.keys().cloned().collect();
    for k in eps {
        if let Some(e) = state.ep.get_mut(&k) {
            if !e.af.is_empty() && !e.garbage.iter().any(|g| g == "blacklist") {
                e.garbage.clear();
            }
        }
    }
}

fn filter_file(
    state: &mut SiteState,
    tainted: &HashSet<String>,
    tl: &std::path::Path,
    keep_hashes: &mut HashSet<String>,
    mode: Mode,
) -> (u64, u64) {
    let rid_ep: HashMap<String, u8> = state
        .req
        .iter()
        .map(|(rid, r)| {
            let k = state.ep_key(&r.url);
            let v = state.ep.get(&k).map(|e| e.verdict()).unwrap_or(0);
            (rid.clone(), v)
        })
        .collect();
    let f = match File::open(tl) {
        Ok(f) => f,
        Err(_) => return (0, 0),
    };
    let tmp = tl.with_extension("jsonl.tmp");
    let mut w = match OpenOptions::new().create(true).write(true).truncate(true).open(&tmp) {
        Ok(w) => w,
        Err(_) => return (0, 0),
    };
    let mut kept = 0u64;
    let mut dup = 0u64;
    let mut seen_send: HashSet<(String, (u32, u32))> = HashSet::new();
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        let v: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !line_keep(&v, state, tainted, &rid_ep, mode) {
            continue;
        };
        if v.get("kk").and_then(|x| x.as_str()) == Some("net:send") {
            if let Some(arr) = v.get("v").and_then(|x| x.as_array()) {
                let u = arr.first().and_then(|x| x.as_str()).unwrap_or("");
                let m = arr.get(1).and_then(|x| x.as_str()).unwrap_or("GET");
                let bh = match arr.get(2) {
                    Some(Value::String(s)) => fnv32(s.as_bytes()),
                    Some(other) => fnv32(other.to_string().as_bytes()),
                    None => 0,
                };
                let key = (state.ep_key(u), (fnv32(m.as_bytes()), bh));
                if !seen_send.insert(key) {
                    dup += 1;
                    let k = state.ep_key(u);
                    if let Some(e) = state.ep.get_mut(&k) {
                        e.dup += 1;
                    }
                    continue;
                }
            }
        }
        if let Some(d) = v.get("d") {
            if let Some(a) = d.get("a").and_then(|x| x.as_str()) {
                if !a.is_empty() {
                    keep_hashes.insert(a.to_owned());
                }
            }
        }
        let _ = w.write_all(line.as_bytes());
        let _ = w.write_all(b"\n");
        kept += 1;
    }
    drop(w);
    if std::fs::rename(&tmp, tl).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    (kept, dup)
}

fn line_keep(v: &Value, state: &SiteState, tainted: &HashSet<String>, rid_ep: &HashMap<String, u8>, mode: Mode) -> bool {
    if let Some(kk) = v.get("kk").and_then(|x| x.as_str()) {
        if KEEP_PREFIXES.iter().any(|p| kk.starts_with(p)) {
            return true;
        }
        if kk == "net:send" {
            if let Some(arr) = v.get("v").and_then(|x| x.as_array()) {
                let u = arr.first().and_then(|x| x.as_str()).unwrap_or("");
                if !u.is_empty() {
                    let k = state.ep_key(u);
                    let vd = state.ep.get(&k).map(|e| e.verdict()).unwrap_or(0);
                    if mode == Mode::Strict {
                        return vd == 1;
                    }
                    return vd != 2;
                }
            }
        }
        return false;
    }
    let k = v.get("k").and_then(|x| x.as_u64()).unwrap_or(0);
    let d = match v.get("d") {
        Some(d) => d,
        None => return false,
    };
    match k {
        1..=5 => {
            let rid = d.get("rid").and_then(|x| x.as_str()).unwrap_or("");
            let vd = rid_ep.get(rid).copied().unwrap_or(0);
            if mode == Mode::Strict {
                vd == 1
            } else {
                vd != 2
            }
        }
        6 => {
            let rid = d.get("rid").and_then(|x| x.as_str()).unwrap_or("");
            match state.ws_url.get(rid) {
                None => true,
                Some(u) => {
                    if mode == Mode::Strict {
                        !blacklisted(host_of(u)) && vendor_of_url(u).is_none() || verdict_of_url(state, u) != 2
                    } else {
                        !blacklisted(host_of(u))
                    }
                }
            }
        }
        7 | 8 => {
            let u = d.get("u").and_then(|x| x.as_str()).unwrap_or("");
            if mode == Mode::Strict {
                tainted.contains(u) || vendor_of_url(u).is_some()
            } else {
                !blacklisted(host_of(u))
            }
        }
        12 => {
            let u = d.get("u").and_then(|x| x.as_str()).unwrap_or("");
            if mode == Mode::Strict {
                tainted.contains(u)
            } else {
                !blacklisted(host_of(u))
            }
        }
        10 | 11 | 13 | 14 | 15 => mode == Mode::Main,
        _ => false,
    }
}

fn verdict_of_url(state: &SiteState, url: &str) -> u8 {
    let k = state.ep_key(url);
    state.ep.get(&k).map(|e| e.verdict()).unwrap_or(0)
}

fn esc(s: &str) -> String {
    let mut b = String::with_capacity(s.len() + 2);
    b.push('"');
    for c in s.chars() {
        match c {
            '"' => b.push_str("\\\""),
            '\\' => b.push_str("\\\\"),
            '\n' => b.push_str("\\n"),
            '\r' => b.push_str("\\r"),
            '\t' => b.push_str("\\t"),
            c if (c as u32) < 0x20 => b.push_str(&format!("\\u{:04x}", c as u32)),
            c => b.push(c),
        }
    }
    b.push('"');
    b
}

struct SiteOut {
    name: String,
    inner: String,
    af: u64,
    garbage: u64,
    neutral: u64,
    scripts: u64,
    kept: u64,
    dup: u64,
    art: Vec<(String, String)>,
    art_v: Vec<(String, u8, bool, u8)>,
}

fn process_site(site: &std::path::Path, stage: &std::path::Path, arts: &HashMap<String, std::path::PathBuf>, mode: Mode, keep_hashes: &mut HashSet<String>) -> SiteOut {
    let site_name = site.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
    let mut state = SiteState::new();
    let mut tls: Vec<std::path::PathBuf> = Vec::new();
    let tdir = site.join("tunnels");
    collect_ttls(&tdir, &mut tls);
    if tls.is_empty() {
        let merged = site.join("timeline.jsonl");
        if merged.is_file() {
            tls.push(merged);
        }
    }
    tls.sort();
    for tl in &tls {
        collect_site(&mut state, tl);
    }
    verdict_site(&mut state, stage, arts, &site_name);
    let tainted_list = tainted_scripts(&state);
    let tainted: HashSet<String> = tainted_list.iter().map(|(u, _)| u.clone()).collect();
    let mut af_n = 0u64;
    let mut gb_n = 0u64;
    let mut nt_n = 0u64;
    let mut dup_n = 0u64;
    let scripts_n = tainted_list.len() as u64;
    let mut kept = 0u64;
    for tl in &tls {
        let (k, d) = filter_file(&mut state, &tainted, tl, keep_hashes, mode);
        kept += k;
        dup_n += d;
    }
    let mut eps: Vec<(&String, &Ep)> = state.ep.iter().collect();
    eps.sort_by(|a, b| b.1.n.cmp(&a.1.n).then(a.0.cmp(b.0)));
    let mut ep_doc = String::new();
    let mut gb_doc = String::new();
    for (i, (u, e)) in eps.iter().enumerate() {
        if i >= 300 {
            break;
        }
        let seg = format!(
            "{{\"u\":{},\"n\":{},\"dup\":{},\"m\":{},\"v\":\"{}\",\"why\":[{}],\"vendor\":{}}}",
            esc(u),
            e.n,
            e.dup,
            esc(&e.method),
            match e.verdict() { 1 => "antifraud", 2 => "garbage", _ => "neutral" },
            e.af.iter().chain(e.garbage.iter()).map(|x| esc(x)).collect::<Vec<_>>().join(","),
            e.vendor.as_deref().map(esc).unwrap_or_else(|| "null".into())
        );
        match e.verdict() {
            1 => {
                af_n += 1;
                if !ep_doc.is_empty() {
                    ep_doc.push(',');
                }
                ep_doc.push_str(&seg);
            }
            2 => {
                gb_n += 1;
                if !gb_doc.is_empty() {
                    gb_doc.push(',');
                }
                gb_doc.push_str(&seg);
            }
            _ => nt_n += 1,
        }
    }
    let af_dir = site.join("antifraud");
    if af_dir.exists() {
        if let Ok(rd) = std::fs::read_dir(&af_dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    if let Ok(rd2) = std::fs::read_dir(&p) {
                        for f in rd2.flatten() {
                            if f.file_name() == "timeline.jsonl" {
                                let _ = std::fs::remove_file(f.path());
                            }
                        }
                    }
                }
            }
        }
    }
    let sc_doc = tainted_list
        .iter()
        .take(200)
        .map(|(u, t)| format!("{{\"u\":{},\"tags\":[{}]}}", esc(u), t.iter().map(|x| esc(x)).collect::<Vec<_>>().join(",")))
        .collect::<Vec<_>>()
        .join(",");
    let inner = format!(
        "\"endpoints\":[{}],\"garbage\":[{}],\"tainted_scripts\":[{}],\"totals\":{{\"endpoints\":{},\"antifraud\":{},\"garbage\":{},\"neutral\":{},\"taint_pool\":{},\"kept_lines\":{},\"dup_lines\":{}}}",
        ep_doc,
        gb_doc,
        sc_doc,
        state.ep.len(),
        af_n,
        gb_n,
        nt_n,
        state.taint.len(),
        kept,
        dup_n
    );
    let so = SiteOut {
        name: site_name,
        inner,
        af: af_n,
        garbage: gb_n,
        neutral: nt_n,
        scripts: scripts_n,
        kept,
        dup: dup_n,
        art: Vec::new(),
        art_v: Vec::new(),
    };
    let mut art: Vec<(String, String)> = Vec::new();
    let mut art_v: Vec<(String, u8, bool, u8)> = Vec::new();
    for (a, rid) in &state.art_bodies {
        let url = state.req.get(rid).map(|r| r.url.as_str()).unwrap_or("");
        if url.is_empty() {
            continue;
        }
        let k = state.ep_key(url);
        let ep = state.ep.get(&k);
        let vd = ep.map(|e| e.verdict()).unwrap_or(0);
        let bl = ep.map(|e| e.garbage.iter().any(|g| g == "blacklist")).unwrap_or(false);
        let ty = state.req.get(rid).and_then(|r| r.ty.clone()).unwrap_or_default();
        let fam = res_family(&ty);
        art_v.push((a.clone(), vd, bl, fam));
        let v = vendor_of_url(url)
            .map(|s| s.to_owned())
            .or_else(|| ep.and_then(|e| e.vendor.clone()))
            .unwrap_or_else(|| "first-party".into());
        art.push((a.clone(), v));
    }
    for (a, u) in &state.art_src {
        let bl = blacklisted(host_of(u));
        let vd = if bl {
            2
        } else if tainted.contains(u) || vendor_of_url(u).is_some() {
            1
        } else {
            0
        };
        art_v.push((a.clone(), vd, bl, 0));
        let v = vendor_of_url(u).map(|s| s.to_owned()).unwrap_or_else(|| "unknown".into());
        art.push((a.clone(), v));
    }
    art.sort();
    art_v.sort();
    let mut lines: Vec<(u64, String)> = Vec::new();
    for tl in &tls {
        if let Ok(f) = File::open(tl) {
            for line in BufReader::new(f).lines().map_while(Result::ok) {
                lines.push((line_t(&line), line));
            }
        }
    }
    lines.sort_by_key(|x| x.0);
    if !lines.is_empty() {
        if let Ok(mut w) = File::create(site.join("timeline.jsonl")) {
            for (_, l) in &lines {
                let _ = writeln!(w, "{l}");
            }
        }
    }
    lift_site_tabs(site);
    SiteOut { art, art_v, ..so }
}

fn line_t(s: &str) -> u64 {
    let p = match s.find("\"t\":") {
        Some(p) => p + 4,
        None => return 0,
    };
    let rest = &s[p..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().unwrap_or(0)
}

fn safe_seg(s: &str) -> String {
    s.chars()
        .map(|c| if c == '/' || c == '\\' || c == ':' { '_' } else { c })
        .collect()
}

fn lift_site_tabs(site: &std::path::Path) {
    let tdir = site.join("tunnels");
    if let Ok(rd) = std::fs::read_dir(&tdir) {
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_dir() {
                continue;
            }
            let tun = safe_seg(&e.file_name().to_string_lossy());
            let tabs_old = p.join("tabs");
            if tabs_old.is_dir() {
                let tabs_new = site.join("tabs").join(&tun);
                if std::fs::create_dir_all(&tabs_new).is_ok() {
                    if let Ok(rd2) = std::fs::read_dir(&tabs_old) {
                        for f in rd2.flatten() {
                            let _ = std::fs::rename(f.path(), tabs_new.join(f.file_name()));
                        }
                    }
                }
            }
            let ck = p.join("cookies.json");
            if ck.is_file() {
                let cd = site.join("cookies");
                if std::fs::create_dir_all(&cd).is_ok() {
                    let _ = std::fs::rename(&ck, cd.join(format!("{tun}.json")));
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&tdir);
}

fn prune_empty(dir: &std::path::Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                prune_empty(&p);
            }
        }
    }
    let _ = std::fs::remove_dir(dir);
}

fn collect_arts(dir: &std::path::Path, out: &mut HashMap<String, std::path::PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect_arts(&p, out);
            } else {
                let name = e.file_name().to_string_lossy().to_string();
                if let Some(stem) = name.split('.').next() {
                    if !stem.is_empty() {
                        out.entry(stem.to_owned()).or_insert(p.clone());
                    }
                }
            }
        }
    }
}

pub fn run(stage: &std::path::Path) -> ClsOut {
    run_mode(stage, Mode::Main)
}

pub fn strict(stage: &std::path::Path) -> ClsOut {
    run_mode(stage, Mode::Strict)
}

fn run_mode(stage: &std::path::Path, mode: Mode) -> ClsOut {
    let mut out = ClsOut { af: 0, garbage: 0, neutral: 0, scripts: 0, kept: 0, dup: 0, art_rm: 0, bytes_rm: 0 };
    let sites_dir = stage.join("sites");
    let rd = match std::fs::read_dir(&sites_dir) {
        Ok(r) => r,
        Err(_) => {
            let _ = std::fs::write(stage.join("classification.json"), "{\"sites\":{}}\n");
            return out;
        }
    };
    let mut sites: Vec<std::path::PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    sites.sort();
    if sites.is_empty() {
        let _ = std::fs::write(stage.join("classification.json"), "{\"sites\":{}}\n");
        return out;
    }
    let mut arts: HashMap<String, std::path::PathBuf> = HashMap::new();
    let next = AtomicUsize::new(0);
    let keep_hashes: std::sync::Mutex<HashSet<String>> = std::sync::Mutex::new(HashSet::new());
    let results: std::sync::Mutex<Vec<Option<SiteOut>>> = std::sync::Mutex::new((0..sites.len()).map(|_| None).collect());
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(sites.len());
    let mut art_roots = vec![stage.join("artifacts")];
    if let Ok(rd) = std::fs::read_dir(stage.join("sites")) {
        for e in rd.flatten() {
            let af = e.path().join("antifraud");
            if af.is_dir() {
                art_roots.push(af);
            }
        }
    }
    for r in &art_roots {
        collect_arts(r, &mut arts);
    }
    let arts_ref = &arts;
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= sites.len() {
                    break;
                }
                let mut local: HashSet<String> = HashSet::new();
                let so = process_site(&sites[i], stage, arts_ref, mode, &mut local);
                if let Ok(mut g) = keep_hashes.lock() {
                    g.extend(local.drain());
                }
                if let Ok(mut r) = results.lock() {
                    r[i] = Some(so);
                }
            });
        }
    });
    let site_outs: Vec<SiteOut> = results
        .into_inner()
        .map(|r| r.into_iter().flatten().collect())
        .unwrap_or_default();
    for so in &site_outs {
        out.af += so.af;
        out.garbage += so.garbage;
        out.neutral += so.neutral;
        out.scripts += so.scripts;
        out.kept += so.kept;
        out.dup += so.dup;
    }
    let keep = keep_hashes.into_inner().unwrap_or_default();
    let mut hash_verdict: HashMap<String, (u8, bool, u8)> = HashMap::new();
    for so in &site_outs {
        for (h, vd, bl, fam) in &so.art_v {
            let e = hash_verdict.entry(h.clone()).or_insert((*vd, *bl, *fam));
            if e.0 == 2 && *vd != 2 {
                e.0 = *vd;
            }
            if !*bl && e.1 {
                e.1 = false;
            }
        }
    }
    let art_dir = stage.join("artifacts");
    if let Ok(rd) = std::fs::read_dir(&art_dir) {
        for e in rd.flatten() {
            let p = e.path();
            let name = p.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let stem = name.split('.').next().unwrap_or("").to_owned();
            if keep.contains(&stem) {
                continue;
            }
            let verdict = hash_verdict.get(&stem);
            // Main prunes garbage/masked artifacts, Strict prunes everything
            // that is not proven antifraud. The engine layer (collect/raw,
            // bctrace, sinkfilter output) is never touched by this file - it
            // only READS collect/filtered/report.json - so the full-fidelity
            // telemetry stays intact either way.
            let remove = match verdict {
                None => mode == Mode::Strict,
                Some((2, true, _)) => true,
                Some((2, false, fam)) => {
                    if mode == Mode::Strict {
                        true
                    } else {
                        let head = read_head(&p, 4096);
                        res_sniff_ok(&head, *fam)
                    }
                }
                Some((1, _, _)) => false,
                Some(_) => mode == Mode::Strict,
            };
            if remove {
                if let Ok(m) = std::fs::metadata(&p) {
                    out.bytes_rm += m.len();
                }
                if std::fs::remove_file(&p).is_ok() {
                    out.art_rm += 1;
                }
            }
        }
    }
    let mut claimed: HashSet<String> = HashSet::new();
    let mut art_files: HashMap<String, std::path::PathBuf> = arts.clone();
    if let Ok(rd) = std::fs::read_dir(&art_dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(stem) = name.split('.').next() {
                if !stem.is_empty() {
                    art_files.insert(stem.to_owned(), e.path());
                }
            }
        }
    }
    let mut site_arts: Vec<String> = Vec::with_capacity(site_outs.len());
    for (i, so) in site_outs.iter().enumerate() {
        let mut arts = String::new();
        let vd_map: HashMap<&String, u8> = so.art_v.iter().map(|(h, v, _, _)| (h, *v)).collect();
        for (h, v) in &so.art {
            if !claimed.insert(h.clone()) {
                continue;
            }
            let vd = vd_map.get(h).copied().unwrap_or(0);
            let keep_it = if mode == Mode::Strict { vd == 1 } else { vd != 2 };
            if !keep_it {
                if let Some(src) = art_files.get(h) {
                    if !src.starts_with(&art_dir) {
                        let _ = std::fs::remove_file(src);
                    }
                }
                continue;
            }
            if let Some(src) = art_files.get(h) {
                let dir = sites[i].join("antifraud").join(safe_seg(v));
                if std::fs::create_dir_all(&dir).is_ok() {
                    if let Some(fname) = src.file_name() {
                        if std::fs::rename(src, dir.join(fname)).is_ok() {
                            if !arts.is_empty() {
                                arts.push(',');
                            }
                            arts.push_str(&format!("{}:{}", esc(h), esc(v)));
                        }
                    }
                }
            }
        }
        site_arts.push(arts);
    }
    prune_empty(&art_dir);
    prune_empty(&sites_dir);
    let docs: Vec<String> = site_outs
        .iter()
        .enumerate()
        .map(|(i, so)| {
            let arts = &site_arts[i];
            let inner = if arts.is_empty() {
                so.inner.clone()
            } else {
                format!("{},\"artifacts\":{{{}}}", so.inner, arts)
            };
            format!("{}:{{{}}}", esc(&so.name), inner)
        })
        .collect();
    let doc = format!("{{\"sites\":{{{}}}}}\n", docs.join(","));
    let _ = std::fs::write(stage.join("classification.json"), doc);
    out
}

fn collect_ttls(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect_ttls(&p, out);
            } else if p.file_name().map(|x| x == "timeline.jsonl").unwrap_or(false) {
                out.push(p);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_known_vectors() {
        assert_eq!(fnv32(b""), 0x811c9dc5);
        assert_eq!(fnv32(b"a"), 0xe40c292c);
        assert_eq!(fnv32(b"foobar"), 0xbf9cf968);
    }

    #[test]
    fn fnv_ascii_units_parity() {
        for s in ["Mozilla/5.0 (X11; Linux x86_64)", "0.5", "screen1920x1080", "abc123"] {
            assert!(ascii_units_parity(s), "parity broken for {s}");
        }
        assert!(!ascii_units_parity("від correspondance"));
    }

    #[test]
    fn entropy_levels() {
        assert_eq!(entropy(b"aaaa"), 0.0);
        let json = b"{\"event\":\"page_view\",\"page\":\"/home\",\"id\":12345}";
        assert!(entropy(json) < 5.0);
        let mut hi = Vec::new();
        for i in 0u32..4096 {
            hi.push((i.wrapping_mul(2654435761u32) >> 13) as u8);
        }
        assert!(entropy(&hi) > 6.5);
    }

    #[test]
    fn taint_hits_tokens() {
        let mut t = HashSet::new();
        t.insert(fnv32(b"Mozilla"));
        t.insert(fnv32(b"0.5"));
        let body = b"{\"ua\":\"Mozilla (X11)\",\"r\":0.5,\"x\":\"Zepra/6.0\"}";
        assert_eq!(body_taint_hits(body, &t), 2);
        assert_eq!(body_taint_hits(b"plain business payload: cart-add", &t), 0);
    }

    #[test]
    fn stack_urls() {
        let st = "Error\n    at collectFp (https://cdn.t.example/af.min.js:1:8842)\n    at https://site.example/app.js:4:2\n    at fn (eval at <anonymous> (https://cdn.t.example/af.min.js:1:1), <anonymous>:1:9)";
        assert_eq!(first_stack_url(st), Some("https://cdn.t.example/af.min.js"));
        let st2 = "Error\n    at https://site.example/app.js:4:2\n    at collectFp (https://cdn.t.example/af.min.js:1:8842)";
        assert_eq!(first_stack_url(st2), Some("https://site.example/app.js"));
        assert_eq!(first_stack_url("Error\n    at f (https://a.example/x.js:1:1)"), Some("https://a.example/x.js"));
        assert_eq!(first_stack_url("Error\n    at f (native)"), None);
        assert!(first_stack_url("no urls here").is_none());
    }

    #[test]
    fn cdp_stack_parse() {
        let s = "collectFp@https://cdn.t.example/af.min.js:1;run@https://site.example/app.js:4";
        assert_eq!(
            parse_cdp_stack(s),
            vec![
                "https://cdn.t.example/af.min.js".to_owned(),
                "https://site.example/app.js".to_owned()
            ]
        );
        // line:col both stripped; frames without '@' are not urls
        assert_eq!(
            parse_cdp_stack("f@https://a.example/x.js:3:17;native"),
            vec!["https://a.example/x.js".to_owned()]
        );
        // short residue after stripping is rejected (>10 rule)
        assert!(parse_cdp_stack("f@http://a.b:1:1").is_empty());
        assert!(parse_cdp_stack("").is_empty());
    }

    #[test]
    fn blacklist_hosts() {
        assert!(blacklisted("www.google-analytics.com"));
        assert!(blacklisted("google-analytics.com"));
        assert!(blacklisted("fonts.gstatic.com"));
        assert!(blacklisted("analytics.google.com"));
        assert!(blacklisted("www.youtube.com"));
        assert!(!blacklisted("challenges.cloudflare.com"));
        assert!(!blacklisted("accounts.x.ai"));
        assert!(!blacklisted("ingest.humanbehavior.co"));
    }

    #[test]
    fn sniff_families() {
        assert_eq!(binary_magic(&[0x89, b'P', b'N', b'G', 13, 10, 26, 10]), 1);
        assert_eq!(binary_magic(&[0xFF, 0xD8, 0xFF, 0xE0]), 1);
        assert_eq!(binary_magic(b"GIF89a"), 1);
        assert_eq!(binary_magic(b"wOFF2"), 3);
        assert_eq!(binary_magic(b"OTTO"), 3);
        assert_eq!(binary_magic(b"OggS"), 2);
        assert_eq!(binary_magic(&[0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]), 0);
        assert_eq!(binary_magic(b"var x=1;"), 0);
        assert!(textish(b"plain text payload"));
        assert!(!textish(&vec![0u8; 512]));
        assert!(js_like(b"function fingerprint(){return 1}"));
        assert!(!js_like(b".btn{color:red}"));
        assert!(res_sniff_ok(&[0x89, b'P', b'N', b'G'], 1));
        assert!(!res_sniff_ok(b"function x(){eval(1)}", 1));
        assert!(!res_sniff_ok(b"function x(){eval(1)}", 4));
        assert!(res_sniff_ok(b".a{b:c}", 4));
    }

    #[test]
    fn end_to_end_classify_dedup_and_clean() {
        let d = std::env::temp_dir().join("afeye-cls-test2");
        let _ = std::fs::remove_dir_all(&d);
        let tl_dir = d.join("sites/example.net/tunnels/1.2.3.4_51820/09.16.2026_04.00-04.30");
        std::fs::create_dir_all(&tl_dir).unwrap();
        std::fs::create_dir_all(d.join("artifacts")).unwrap();
        std::fs::write(d.join("artifacts").join("aa11.post"), b"{\"ua\":\"Mozilla/5.0 (X11; Linux x86_64)\",\"r\":0.5}").unwrap();
        std::fs::write(d.join("artifacts").join("bb22.post"), b"{\"v\":2,\"tid\":\"G-1\",\"events\":\"page_view\"}").unwrap();
        std::fs::write(d.join("artifacts").join("cc33.js"), b"var af=1;").unwrap();
        std::fs::write(d.join("artifacts").join("dd44.json"), b"{\"pong\":true}").unwrap();
        std::fs::write(d.join("artifacts").join("ee55.png"), b"function hidden(){eval('fp()')};").unwrap();
        std::fs::write(d.join("artifacts").join("ff66.png"), [0x89u8, b'P', b'N', b'G', 13, 10, 26, 10]).unwrap();
        let vd = d.join("sites/example.net/antifraud/datadome");
        std::fs::create_dir_all(&vd).unwrap();
        std::fs::write(vd.join("timeline.jsonl"), "{\"k\":1,\"d\":{\"rid\":\"R1\"}}\n").unwrap();
        let lines = [
            r#"{"t":1,"u":1,"s":1,"b":0,"k":1,"d":{"rid":"R1","m":"POST","u":"https://api.example.net/collect","ty":"Fetch","ini":"script","stk":"collectFp@https://cdn.example.net/af.js:1"}}"#,
            r#"{"t":2,"u":1,"s":1,"b":0,"k":2,"d":{"rid":"R1","u":"https://api.example.net/collect","st":200,"h":{"set-cookie":"datadome=abc; Path=/"}}}"#,
            r#"{"t":3,"u":1,"s":1,"b":0,"k":3,"d":{"rid":"R1","a":"aa11","x":"post","n":50}}"#,
            r#"{"t":4,"u":1,"s":1,"b":0,"k":1,"d":{"rid":"R2","m":"POST","u":"https://www.google-analytics.com/g/collect?v=2","ty":"Image","ini":"other"}}"#,
            r#"{"t":5,"u":1,"s":1,"b":0,"k":3,"d":{"rid":"R2","a":"bb22","x":"post","n":30}}"#,
            r#"{"t":6,"u":1,"s":1,"b":0,"k":7,"d":{"sid":"S1","u":"https://cdn.example.net/af.js","hl":1000,"ch":"x"}}"#,
            r#"{"t":6,"u":1,"s":1,"b":0,"k":8,"d":{"sid":"S1","u":"https://cdn.example.net/af.js","a":"cc33","x":"js","n":8}}"#,
            r#"{"t":20,"u":1,"s":1,"b":0,"k":1,"d":{"rid":"R3","m":"GET","u":"https://api.other.net/ping","ty":"Fetch","ini":"script"}}"#,
            r#"{"t":21,"u":1,"s":1,"b":0,"k":2,"d":{"rid":"R3","u":"https://api.other.net/ping","st":200,"h":{"content-type":"application/json"}}}"#,
            r#"{"t":22,"u":1,"s":1,"b":0,"k":3,"d":{"rid":"R3","a":"dd44","x":"json","n":13}}"#,
            r#"{"t":30,"u":1,"s":1,"b":0,"k":1,"d":{"rid":"R4","m":"GET","u":"https://cdn.example.net/pixel.png","ty":"Image","ini":"other"}}"#,
            r#"{"t":31,"u":1,"s":1,"b":0,"k":3,"d":{"rid":"R4","a":"ee55","x":"png","n":32}}"#,
            r#"{"t":32,"u":1,"s":1,"b":0,"k":1,"d":{"rid":"R5","m":"GET","u":"https://cdn.example.net/logo.png","ty":"Image","ini":"other"}}"#,
            r#"{"t":33,"u":1,"s":1,"b":0,"k":3,"d":{"rid":"R5","a":"ff66","x":"png","n":8}}"#,
            r#"{"t":7,"b":0,"j":10.5,"kk":"stk:toDataURL","v":["Error\n    at f (https://cdn.example.net/af.js:1:2)\n    at g (https://cdn.example.net/af.js:3:4)",11.2]}"#,
            r#"{"t":8,"b":0,"j":10.6,"kk":"stk:getParameter","v":["Error\n    at f (https://cdn.example.net/af.js:1:2)",11.3]}"#,
            r#"{"t":9,"b":0,"j":10.7,"kk":"stk:g:userAgent","v":["Error\n    at h (https://cdn.example.net/af.js:5:6)",11.4]}"#,
            r#"{"t":10,"b":0,"j":10.8,"kk":"_th","v":[3826005026]}"#,
            r#"{"t":11,"b":0,"j":11.0,"kk":"net:send","v":["https://api.example.net/collect","POST","{\"ua\":\"Mozilla",11.0,1,0]}"#,
            r#"{"t":12,"b":0,"j":11.2,"kk":"net:send","v":["https://api.example.net/collect","POST","{\"ua\":\"Mozilla",11.2,1,0]}"#,
            r#"{"t":13,"b":0,"j":11.4,"kk":"net:send","v":["https://api.example.net/collect","POST","other-payload",11.4,1,0]}"#,
            r#"{"t":14,"b":0,"j":11.6,"kk":"_c","v":["Math.random",5]}"#,
        ];
        let mut tl = String::new();
        for l in lines {
            tl.push_str(l);
            tl.push('\n');
        }
        std::fs::write(tl_dir.join("timeline.jsonl"), tl).unwrap();
        let out = run(&d);
        assert_eq!(out.scripts, 1);
        assert!(out.af >= 1);
        assert!(out.garbage >= 1);
        assert_eq!(out.dup, 1, "duplicate net:send must be dropped once");
        let merged = d.join("sites/example.net/timeline.jsonl");
        let filtered = std::fs::read_to_string(&merged).unwrap();
        assert!(!filtered.contains("google-analytics"));
        assert_eq!(filtered.matches("net:send").count(), 2);
        assert!(filtered.contains("stk:toDataURL"));
        assert!(filtered.contains("\"rid\":\"R1\""));
        assert!(filtered.contains("api.other.net/ping"), "neutral request must survive main filter");
        assert!(filtered.contains("\"rid\":\"R4\""), "masked image-script request must survive");
        assert!(!d.join("sites/example.net/tunnels").exists());
        assert!(d.join("sites/example.net/antifraud/first-party/aa11.post").exists());
        assert!(d.join("sites/example.net/antifraud/unknown/cc33.js").exists());
        assert!(d.join("sites/example.net/antifraud/first-party/dd44.json").exists(), "neutral artifact must survive main filter");
        assert!(d.join("sites/example.net/antifraud/first-party/ee55.png").exists(), "masked js-under-png must survive");
        assert!(!d.join("artifacts/bb22.post").exists());
        assert!(!d.join("artifacts/ff66.png").exists(), "real png must be swept");
        let cls = std::fs::read_to_string(d.join("classification.json")).unwrap();
        assert!(cls.contains("\"antifraud\""));
        assert!(cls.contains("api.example.net/collect"));
        assert!(cls.contains("cookie:datadome"));
        assert!(cls.contains("masked:Image"));
        assert!(cls.contains("\"dup\":1"));
        assert!(cls.contains("\"artifacts\""));
        assert!(cls.contains("aa11"));
        let strict_dir = std::env::temp_dir().join("afeye-cls-test2-strict");
        let _ = std::fs::remove_dir_all(&strict_dir);
        crate::arch::copy_tree(&d, &strict_dir).unwrap();
        strict(&strict_dir);
        let s_merged = std::fs::read_to_string(strict_dir.join("sites/example.net/timeline.jsonl")).unwrap();
        assert!(!s_merged.contains("api.other.net"), "strict filter drops neutral");
        assert!(s_merged.contains("api.example.net/collect"));
        assert!(s_merged.contains("\"rid\":\"R4\""), "masked survives strict");
        assert!(!strict_dir.join("artifacts/dd44.json").exists(), "strict drops neutral artifact");
        assert!(!strict_dir.join("sites/example.net/antifraud/first-party/dd44.json").exists(), "strict drops neutral artifact");
        assert!(strict_dir.join("sites/example.net/antifraud/first-party/ee55.png").exists());
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&strict_dir);
    }
}
