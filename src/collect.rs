use crate::events::{esc, J};
use bytes::BufMut;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_RAW_DIR: &str = "/tmp/afeye-raw";
// WIRE v3: [0..4] total | [4] kind | [5] flags | [6..10] sid u32 |
// [10..12] tid u16 | [12..16] reserved (not validated) | [16..24] ts u64 |
// payload at 24.
const HDR: usize = 24;
const MAX_RECORD: u32 = 24 + (1 << 20);
const PREVIEW: usize = 4096;

pub const LAYER_V8: u8 = 0;
pub const LAYER_BLINK: u8 = 1;
pub const LAYER_NET: u8 = 2;
pub const KIND_SINK_HELLO: u8 = 0;
pub const KIND_BYTECODE_TRACE: u8 = 40;

const KINDS: [&str; 41] = [
    "sink-hello",
    "script-source",
    "bytecode-entry",
    "wasm-module",
    "wasm-memory",
    "wasm-table",
    "microtask-enqueue",
    "microtask-run",
    "call-completed",
    "atomics",
    "sab-backing",
    "crypto-op",
    "timer",
    "perf-entry",
    "message",
    "structured-clone",
    "fingerprint",
    "net-request",
    "net-resp-body",
    "websocket",
    "client-hints",
    "sw-cache",
    "script-source",
    "input",
    "event-dispatch",
    "dom-metric",
    "audio",
    "webrtc",
    "fetch",
    "dom-api",
    "microtask",
    "wasm-instance",
    "fn-tostring",
    "clock",
    "isolate",
    "worker",
    "nav-start",
    "taint-edge",
    "error-stack",
    "sink-drop",
    "bytecode-trace",
];

const LAYERS: [&str; 3] = ["v8", "blink", "net"];

const BATCHED_KINDS: [&str; 8] = [
    "dom-api",
    "call-completed",
    "event-dispatch",
    "input",
    "clock",
    "microtask",
    "timer",
    "bytecode-trace",
];

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn batched_table() -> [bool; KINDS.len()] {
    let mut t = [false; KINDS.len()];
    let mut i = 0;
    while i < KINDS.len() {
        let mut j = 0;
        while j < BATCHED_KINDS.len() {
            if str_eq(KINDS[i], BATCHED_KINDS[j]) {
                t[i] = true;
            }
            j += 1;
        }
        i += 1;
    }
    t
}

static BATCHED: [bool; KINDS.len()] = batched_table();

const PART_ROLL_BYTES: u64 = 8 << 20;

const MAX_KIND: u8 = (KINDS.len() - 1) as u8;

fn kind_name(kind: u8) -> &'static str {
    KINDS.get(kind as usize).copied().unwrap_or("unknown")
}

fn layer_name(layer: u8) -> &'static str {
    LAYERS.get(layer as usize).copied().unwrap_or("?")
}

fn layer_of(file_stem: &str) -> Option<(&'static str, u8)> {
    let (name, _) = file_stem.split_once('-')?;
    match name {
        "v8" => Some(("v8", LAYER_V8)),
        "blink" => Some(("blink", LAYER_BLINK)),
        "net" => Some(("net", LAYER_NET)),
        _ => None,
    }
}

fn parse_per_key(key: &str) -> Option<(u8, u8)> {
    let (l, name) = key.split_once('/')?;
    let lid = LAYERS.iter().position(|x| *x == l)? as u8;
    let kind = KINDS.iter().position(|x| *x == name)? as u8;
    Some((lid, kind))
}

pub struct Stats {
    pub records: u64,
    pub bytes: u64,
    pub truncated: u64,
    pub corrupt: u64,
    pub files: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub per: BTreeMap<(u8, u8), u64>,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            records: 0,
            bytes: 0,
            truncated: 0,
            corrupt: 0,
            files: 0,
            first_ts: 0,
            last_ts: 0,
            per: BTreeMap::new(),
        }
    }
}

impl std::fmt::Debug for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Stats")
            .field("records", &self.records)
            .field("bytes", &self.bytes)
            .field("truncated", &self.truncated)
            .field("corrupt", &self.corrupt)
            .field("files", &self.files)
            .field("first_ts", &self.first_ts)
            .field("last_ts", &self.last_ts)
            .field("per", &self.per)
            .finish()
    }
}

impl Stats {
    pub fn per_count(&self, layer: u8, kind: u8) -> u64 {
        self.per.get(&(layer, kind)).copied().unwrap_or(0)
    }
}

impl serde::Serialize for Stats {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(8))?;
        m.serialize_entry("records", &self.records)?;
        m.serialize_entry("bytes", &self.bytes)?;
        m.serialize_entry("truncated", &self.truncated)?;
        m.serialize_entry("corrupt", &self.corrupt)?;
        m.serialize_entry("files", &self.files)?;
        m.serialize_entry("first_ts", &self.first_ts)?;
        m.serialize_entry("last_ts", &self.last_ts)?;
        let mut per: BTreeMap<String, u64> = BTreeMap::new();
        for (&(lid, kind), &v) in &self.per {
            let mut name = String::with_capacity(24);
            name.push_str(layer_name(lid));
            name.push('/');
            name.push_str(kind_name(kind));
            *per.entry(name).or_insert(0) += v;
        }
        m.serialize_entry("per", &per)?;
        m.end()
    }
}

#[derive(serde::Deserialize)]
struct StatsWire {
    #[serde(default)]
    records: u64,
    #[serde(default)]
    bytes: u64,
    #[serde(default)]
    truncated: u64,
    #[serde(default)]
    corrupt: u64,
    #[serde(default)]
    files: u64,
    #[serde(default)]
    first_ts: u64,
    #[serde(default)]
    last_ts: u64,
    #[serde(default)]
    per: BTreeMap<String, u64>,
}

impl<'de> serde::Deserialize<'de> for Stats {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = StatsWire::deserialize(d)?;
        let mut per: BTreeMap<(u8, u8), u64> = BTreeMap::new();
        for (k, v) in w.per {
            if let Some(key) = parse_per_key(&k) {
                *per.entry(key).or_insert(0) += v;
            }
        }
        Ok(Stats {
            records: w.records,
            bytes: w.bytes,
            truncated: w.truncated,
            corrupt: w.corrupt,
            files: w.files,
            first_ts: w.first_ts,
            last_ts: w.last_ts,
            per,
        })
    }
}

struct FileTail {
    off: u64,
    partial: Vec<u8>,
}

pub struct ScanState {
    tails: HashMap<PathBuf, FileTail>,
    seq: u64,
    parts: HashMap<(u8, u8), PartWriter>,
    hellos: [u64; 3],
    chunk: Vec<u8>,
    path_buf: PathBuf,
}

struct PartWriter {
    file: File,
    rel: String,
    seq: u32,
    written: u64,
}

impl ScanState {
    pub fn new() -> Self {
        ScanState {
            tails: HashMap::new(),
            seq: 0,
            parts: HashMap::new(),
            hellos: [0; 3],
            chunk: Vec::new(),
            path_buf: PathBuf::new(),
        }
    }
}

fn put_file_name<'a>(
    buf: &'a mut [u8; 96],
    layer: &str,
    kname: &str,
    tag: u8,
    num: u64,
    width: usize,
) -> &'a [u8] {
    let mut n = 0usize;
    buf[n..n + layer.len()].copy_from_slice(layer.as_bytes());
    n += layer.len();
    buf[n] = b'-';
    n += 1;
    buf[n..n + kname.len()].copy_from_slice(kname.as_bytes());
    n += kname.len();
    buf[n] = b'-';
    n += 1;
    if tag != 0 {
        buf[n] = tag;
        n += 1;
    }
    let mut ib = itoa::Buffer::new();
    let s = ib.format(num).as_bytes();
    if s.len() < width {
        for _ in 0..width - s.len() {
            buf[n] = b'0';
            n += 1;
        }
    }
    buf[n..n + s.len()].copy_from_slice(s);
    n += s.len();
    buf[n..n + 4].copy_from_slice(b".bin");
    n += 4;
    &buf[..n]
}

fn put_rel(j: &mut J, name: &[u8]) {
    j.key("p");
    j.b.put_u8(b'"');
    j.b.put_slice(b"raw/");
    j.b.put_slice(name);
    j.b.put_u8(b'"');
}

fn put_hex16(j: &mut J, h: &[u8; 32]) {
    static H: &[u8; 16] = b"0123456789abcdef";
    j.key("h");
    j.b.put_u8(b'"');
    for &c in &h[..8] {
        j.b.put_u8(H[(c >> 4) as usize]);
        j.b.put_u8(H[(c & 15) as usize]);
    }
    j.b.put_u8(b'"');
}

impl PartWriter {
    fn roll(&mut self, raw_out: &Path, layer: &str, kname: &str) {
        self.seq += 1;
        let mut nb = [0u8; 96];
        let name = put_file_name(&mut nb, layer, kname, b'p', self.seq as u64, 4);
        if let Ok(f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(raw_out.join(std::str::from_utf8(name).unwrap_or("part.bin")))
        {
            let mut rel = String::with_capacity(name.len() + 4);
            rel.push_str("raw/");
            rel.push_str(std::str::from_utf8(name).unwrap_or("part.bin"));
            self.file = f;
            self.rel = rel;
            self.written = 0;
        }
    }

    fn push(&mut self, raw_out: &Path, layer: &str, kname: &str, payload: &[u8]) -> Option<u64> {
        if self.written >= PART_ROLL_BYTES {
            self.roll(raw_out, layer, kname);
        }
        let off = self.written;
        if self.file.write_all(payload).is_err() {
            return None;
        }
        self.written += payload.len() as u64;
        Some(off)
    }
}

fn part_writer<'a>(
    raw_out: &Path,
    parts: &'a mut HashMap<(u8, u8), PartWriter>,
    layer_id: u8,
    kind: u8,
    layer: &str,
    kname: &str,
) -> Option<&'a mut PartWriter> {
    let key = (layer_id, kind);
    if !parts.contains_key(&key) {
        let mut nb = [0u8; 96];
        let name = put_file_name(&mut nb, layer, kname, b'p', 0, 4);
        let name = std::str::from_utf8(name).unwrap_or("part.bin");
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(raw_out.join(name))
            .ok()?;
        let mut rel = String::with_capacity(name.len() + 4);
        rel.push_str("raw/");
        rel.push_str(name);
        parts.insert(
            key,
            PartWriter {
                file: f,
                rel,
                seq: 0,
                written: 0,
            },
        );
    }
    parts.get_mut(&key)
}

pub struct HelloCounts {
    per_layer: [AtomicU64; 3],
}

impl HelloCounts {
    fn new() -> Self {
        HelloCounts {
            per_layer: [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
        }
    }

    pub fn total(&self) -> u64 {
        self.per_layer
            .iter()
            .map(|a| a.load(Ordering::Relaxed))
            .sum()
    }
}

pub struct Collector {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<Stats>>,
    hellos: Arc<HelloCounts>,
}

fn ensure_raw_dir(raw_dir: &Path) {
    let _ = fs::create_dir_all(raw_dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(raw_dir, fs::Permissions::from_mode(0o777));
    }
}

pub fn scan_once(raw_dir: &Path, out_dir: &Path, state: &mut ScanState, stats: &mut Stats) {
    ensure_raw_dir(raw_dir);
    let raw_dir = match raw_dir.canonicalize().unwrap_or_else(|_| raw_dir.to_path_buf()) {
        p if p.is_dir() => p,
        _ => return,
    };
    let entries = match fs::read_dir(&raw_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension().map(|x| x == "rec").unwrap_or(false)
                && p.file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(layer_of)
                    .is_some()
        })
        .collect();
    files.sort();
    stats.files = files.len() as u64;

    let raw_out = out_dir.join("raw");
    let _ = fs::create_dir_all(&raw_out);
    state.path_buf = raw_out.join("x");
    let mut index = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(out_dir.join("index.jsonl"))
    {
        Ok(f) => std::io::BufWriter::with_capacity(1 << 16, f),
        Err(_) => return,
    };

    for path in files {
        let (layer, layer_id) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(layer_of)
            .unwrap_or(("", 0));
        let pid: u64 = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.split_once('-'))
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(0);
        let off = {
            state
                .tails
                .entry(path.clone())
                .or_insert(FileTail {
                    off: 0,
                    partial: Vec::new(),
                })
                .off
        };
        let mut f = match File::open(&path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        if f.seek(SeekFrom::Start(off)).is_err() {
            continue;
        }
        state.chunk.clear();
        if f.read_to_end(&mut state.chunk).is_err() {
            continue;
        }
        let new_off = off + state.chunk.len() as u64;
        let partial = {
            let e = state.tails.get_mut(&path).unwrap();
            e.off = new_off;
            &mut e.partial
        };
        partial.extend_from_slice(&state.chunk);
        let len = partial.len();
        let total_at = |p: usize| -> u32 {
            u32::from_le_bytes([partial[p], partial[p + 1], partial[p + 2], partial[p + 3]])
        };
        let plausible_at = |p: usize| -> bool {
            if p + HDR > len {
                return false;
            }
            let t = total_at(p) as usize;
            t >= HDR
                && t <= MAX_RECORD as usize
                && p + t <= len
                && partial[p + 4] <= MAX_KIND
                && partial[p + 5] <= 1
        };
        let mut consumed = 0usize;
        loop {
            if len - consumed < HDR {
                break;
            }
            let total = total_at(consumed) as usize;
            let header_ok = total >= HDR
                && total <= MAX_RECORD as usize
                && partial[consumed + 4] <= MAX_KIND
                && partial[consumed + 5] <= 1;
            if !header_ok {
                stats.corrupt += 1;
                consumed += 1;
                continue;
            }
            if consumed + total > len {
                let mut next = false;
                let mut p = consumed + 1;
                while p + HDR <= len {
                    if plausible_at(p) {
                        next = true;
                        break;
                    }
                    p += 1;
                }
                if next {
                    stats.corrupt += 1;
                    consumed += 1;
                    continue;
                }
                break;
            }
            let rec = &partial[consumed..consumed + total];
            let kind = rec[4];
            let flags = rec[5];
            let sid = u32::from_le_bytes([rec[6], rec[7], rec[8], rec[9]]);
            let tid = u16::from_le_bytes([rec[10], rec[11]]);
            let ts = u64::from_le_bytes([
                rec[16], rec[17], rec[18], rec[19], rec[20], rec[21], rec[22], rec[23],
            ]);
            let payload = &rec[HDR..];
            state.seq += 1;
            let kname = kind_name(kind);
            *stats.per.entry((layer_id, kind)).or_insert(0) += 1;
            stats.records += 1;
            stats.bytes += payload.len() as u64;
            if flags & 1 != 0 {
                stats.truncated += 1;
            }
            if kind == KIND_SINK_HELLO && (layer_id as usize) < 3 {
                state.hellos[layer_id as usize] += 1;
            }
            if stats.first_ts == 0 || ts < stats.first_ts {
                stats.first_ts = ts;
            }
            if ts > stats.last_ts {
                stats.last_ts = ts;
            }
            let mut j = J::new(192 + PREVIEW);
            j.open();
            j.fkey("ts");
            j.u64v(ts);
            j.key("l");
            j.s(layer);
            j.key("pid");
            j.u64v(pid);
            j.key("k");
            j.s(kname);
            j.key("sid");
            j.u64v(sid as u64);
            j.key("tid");
            j.u64v(tid as u64);
            j.key("len");
            j.u64v(payload.len() as u64);
            if flags != 0 {
                j.key("f");
                j.u64v(flags as u64);
            }
            let hash = blake3::hash(payload);
            put_hex16(&mut j, hash.as_bytes());
            let mut single = false;
            if BATCHED[kind as usize] && !payload.is_empty() {
                match part_writer(&raw_out, &mut state.parts, layer_id, kind, layer, kname) {
                    Some(pw) => match pw.push(&raw_out, layer, kname, payload) {
                        Some(po) => {
                            j.key("p");
                            j.s(&pw.rel);
                            j.key("o");
                            j.u64v(po);
                        }
                        None => single = true,
                    },
                    None => single = true,
                }
            } else {
                single = true;
            }
            if single {
                let mut nb = [0u8; 96];
                let name = put_file_name(&mut nb, layer, kname, 0, state.seq, 6);
                let name = std::str::from_utf8(name).unwrap_or("rec.bin");
                state.path_buf.set_file_name(name);
                let _ = fs::write(&state.path_buf, payload);
                put_rel(&mut j, name.as_bytes());
            }
            let n = payload.len().min(PREVIEW);
            if let Ok(s) = simdutf8::basic::from_utf8(&payload[..n]) {
                let cut = if payload.len() > PREVIEW {
                    s.char_indices().map(|(i, _)| i).last().unwrap_or(0)
                } else {
                    s.len()
                };
                j.key("txt");
                esc(&mut j.b, &s[..cut]);
            }
            let line = j.fin();
            let _ = index.write_all(&line);
            let _ = index.write_all(b"\n");
            consumed += total;
        }
        if consumed > 0 {
            partial.drain(..consumed);
        }
    }
    let _ = index.flush();
    let _ = fs::write(
        out_dir.join("stats.json"),
        serde_json::to_vec(&*stats).unwrap_or_default(),
    );
}

impl Collector {
    pub fn spawn_dirs(raw_dir: PathBuf, out_dir: PathBuf) -> Collector {
        let _ = fs::create_dir_all(&out_dir);
        let stop = Arc::new(AtomicBool::new(false));
        let hellos = Arc::new(HelloCounts::new());
        let stop2 = stop.clone();
        let hellos2 = hellos.clone();
        let handle = std::thread::Builder::new()
            .name("afeye-collect".into())
            .spawn(move || {
                let mut state = ScanState::new();
                let mut stats = Stats::default();
                let mut tick: u32 = 0;
                loop {
                    scan_once(&raw_dir, &out_dir, &mut state, &mut stats);
                    for (i, a) in hellos2.per_layer.iter().enumerate() {
                        a.store(state.hellos[i], Ordering::Relaxed);
                    }
                    if stop2.load(Ordering::Acquire) {
                        break;
                    }
                    let pause = if tick < 10 { 200 } else { 2000 };
                    tick += 1;
                    for _ in 0..pause {
                        if stop2.load(Ordering::Acquire) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                stats
            })
            .ok();
        Collector {
            stop,
            handle,
            hellos,
        }
    }

    pub fn hellos(&self) -> u64 {
        self.hellos.total()
    }

    pub fn hellos_handle(&self) -> impl Fn() -> u64 + Send + 'static {
        let hellos = self.hellos.clone();
        move || hellos.total()
    }

    pub fn stop(mut self) -> Stats {
        self.stop.store(true, Ordering::Release);
        match self.handle.take() {
            Some(h) => h.join().unwrap_or_default(),
            None => Stats::default(),
        }
    }
}

pub fn run_standalone(raw_dir: &Path, out_dir: &Path) {
    let mut state = ScanState::new();
    let mut stats = Stats::default();
    eprintln!(
        "[collect] watching {} -> {}",
        raw_dir.display(),
        out_dir.display()
    );
    loop {
        scan_once(raw_dir, out_dir, &mut state, &mut stats);
        eprintln!(
            "[collect] records={} bytes={} truncated={} corrupt={} files={}",
            stats.records, stats.bytes, stats.truncated, stats.corrupt, stats.files
        );
        std::thread::sleep(Duration::from_millis(1000));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec_full(kind: u8, flags: u8, sid: u32, tid: u16, ts: u64, payload: &[u8]) -> Vec<u8> {
        let total = (HDR + payload.len()) as u32;
        let mut v = Vec::with_capacity(total as usize);
        v.extend_from_slice(&total.to_le_bytes());
        v.push(kind);
        v.push(flags);
        v.extend_from_slice(&sid.to_le_bytes());
        v.extend_from_slice(&tid.to_le_bytes());
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&ts.to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn rec(kind: u8, flags: u8, ts: u64, payload: &[u8]) -> Vec<u8> {
        rec_full(kind, flags, 0, 0, ts, payload)
    }

    #[test]
    fn parses_framing_and_materializes_raw() {
        let tmp = tempfile::tempdir().unwrap();
        let raw = tmp.path().join("raw");
        let out = tmp.path().join("collect");
        fs::create_dir_all(&raw).unwrap();
        let mut f = File::create(raw.join("v8-4242.rec")).unwrap();
        f.write_all(&rec(1, 0, 111, b"var a=1;")).unwrap();
        f.write_all(&rec(3, 1, 222, &[9u8; 32])).unwrap();
        f.write_all(&rec_full(0, 0, 0x1122_3344, 0x5566, 55, b"afeye-sink/v8 v3 pid=1"))
            .unwrap();
        let full = rec(9, 0, 333, b"abcd");
        f.write_all(&full[..12]).unwrap();
        drop(f);

        let mut state = ScanState::new();
        let mut stats = Stats::default();
        scan_once(&raw, &out, &mut state, &mut stats);
        assert_eq!(stats.records, 3);
        assert_eq!(stats.corrupt, 0);
        assert_eq!(stats.truncated, 1);
        assert_eq!(stats.first_ts, 55);
        assert_eq!(stats.last_ts, 222);
        assert_eq!(stats.per_count(LAYER_V8, 1), 1);
        assert_eq!(stats.per_count(LAYER_V8, 3), 1);
        assert_eq!(stats.per_count(LAYER_V8, KIND_SINK_HELLO), 1);
        let idx = fs::read_to_string(out.join("index.jsonl")).unwrap();
        assert_eq!(idx.lines().count(), 3);
        assert!(idx.contains("\"k\":\"script-source\""));
        assert!(idx.contains("\"f\":1"));
        assert!(idx.contains("\"txt\":\"var a=1;\""));
        assert!(idx.contains("\"sid\":287454020"), "sid missing: {idx}");
        assert!(idx.contains("\"tid\":21862"), "tid missing: {idx}");
        assert!(idx.contains("\"sid\":0"), "zero sid must still be present");
        let bin = fs::read(out.join("raw/v8-wasm-module-000002.bin")).unwrap();
        assert_eq!(bin, vec![9u8; 32]);
        assert_eq!(
            fs::read(out.join("raw/v8-script-source-000001.bin")).unwrap(),
            b"var a=1;"
        );

        let mut f = OpenOptions::new()
            .append(true)
            .open(raw.join("v8-4242.rec"))
            .unwrap();
        f.write_all(&full[12..]).unwrap();
        drop(f);
        scan_once(&raw, &out, &mut state, &mut stats);
        assert_eq!(stats.records, 4);
        assert_eq!(stats.per_count(LAYER_V8, 9), 1);
    }

    #[test]
    fn corrupt_record_resyncs() {
        let tmp = tempfile::tempdir().unwrap();
        let raw = tmp.path().join("raw");
        let out = tmp.path().join("collect");
        fs::create_dir_all(&raw).unwrap();
        let mut f = File::create(raw.join("net-1.rec")).unwrap();
        f.write_all(&[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
        f.write_all(&rec(17, 0, 10, b"GET /x")).unwrap();
        drop(f);
        let mut state = ScanState::new();
        let mut stats = Stats::default();
        scan_once(&raw, &out, &mut state, &mut stats);
        assert_eq!(stats.records, 1);
        assert!(stats.corrupt >= 1);
        assert_eq!(stats.per_count(LAYER_NET, 17), 1);
    }

    #[test]
    fn reserved_bytes_are_not_validated() {
        let tmp = tempfile::tempdir().unwrap();
        let raw = tmp.path().join("raw");
        let out = tmp.path().join("collect");
        fs::create_dir_all(&raw).unwrap();
        let mut r = rec(1, 0, 7, b"zz");
        r[12] = 0xAB;
        r[13] = 0xCD;
        r[14] = 0xEF;
        r[15] = 0x01;
        fs::write(raw.join("blink-5.rec"), &r).unwrap();
        let mut state = ScanState::new();
        let mut stats = Stats::default();
        scan_once(&raw, &out, &mut state, &mut stats);
        assert_eq!(stats.records, 1);
        assert_eq!(stats.corrupt, 0);
        assert_eq!(stats.per_count(LAYER_BLINK, 1), 1);
    }

    #[test]
    fn stats_json_roundtrip_keeps_string_keys() {
        let mut stats = Stats::default();
        *stats.per.entry((LAYER_V8, KIND_SINK_HELLO)).or_insert(0) += 2;
        *stats.per.entry((LAYER_NET, 17)).or_insert(0) += 5;
        let s = serde_json::to_string(&stats).unwrap();
        assert!(s.contains("\"v8/sink-hello\":2"), "{s}");
        assert!(s.contains("\"net/net-request\":5"), "{s}");
        let back: Stats = serde_json::from_str(&s).unwrap();
        assert_eq!(back.per_count(LAYER_V8, KIND_SINK_HELLO), 2);
        assert_eq!(back.per_count(LAYER_NET, 17), 5);
        assert_eq!(back.records, stats.records);
    }

    #[test]
    fn layer_filter_rejects_unknown() {
        assert_eq!(layer_of("v8-123"), Some(("v8", LAYER_V8)));
        assert_eq!(layer_of("blink-45"), Some(("blink", LAYER_BLINK)));
        assert_eq!(layer_of("net-9"), Some(("net", LAYER_NET)));
        assert_eq!(layer_of("garbage-1"), None);
        assert_eq!(layer_of("nope"), None);
    }
}
