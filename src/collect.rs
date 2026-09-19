//! afeye collector v2.
//!
//! The C++ sinks (V8 / Blink / network-service) append length-prefixed records
//! to per-process files under /tmp/afeye-raw: `<layer>-<pid>.rec`.
//! Record framing (little endian):
//!   u32 total | u8 kind | u8 flags | u16 rsvd | u64 ts_ns | payload[total-16]
//! `total` counts the whole record including the 16-byte header.
//! ts_ns is CLOCK_MONOTONIC on the host: identical across every sink process,
//! so the three streams can be merged into one exact diff-able timeline.
//!
//! This module tails those files and materializes, under `<stage>/collect/`:
//!   raw/<layer>-<kind>-<seq>.bin   full payload bytes, nothing dropped
//!   index.jsonl                    one line per record (ts/layer/kind/flags/
//!                                  len/blake3/path/text preview)
//!   stats.json                     running counters, rewritten every scan

use crate::events::J;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_RAW_DIR: &str = "/tmp/afeye-raw";
const MAX_RECORD: u32 = 16 + (1 << 20);
const PREVIEW: usize = 4096;

const KINDS: [&str; 29] = [
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
    // kind 22: reserved. v4 emitted blink-hand-off script sources here (the
    // 0007 duplicate); v5 captures every script exactly once at the three
    // v8 compile funnels (eval / streamed / buffered - patches/0002), so this
    // slot stays wire-compatible but silent.
    "script-source",
    // kinds 23-28 (v4): input / event dispatch / dom+canvas metrics /
    // offline audio render / webrtc sdp-ice / renderer-side fetch origin.
    // v5 note: kind 23 (pre-dispatch input) is silent too - the single
    // EventDispatcher funnel already carries coords/keys/isTrusted.
    "input",
    "event-dispatch",
    "dom-metric",
    "audio",
    "webrtc",
    "fetch",
];

/// Highest valid kind byte the collector will accept in a record header.
const MAX_KIND: u8 = (KINDS.len() - 1) as u8;

fn kind_name(kind: u8) -> &'static str {
    KINDS.get(kind as usize).copied().unwrap_or("unknown")
}

fn layer_of(file_stem: &str) -> Option<&'static str> {
    let (name, _) = file_stem.split_once('-')?;
    match name {
        "v8" => Some("v8"),
        "blink" => Some("blink"),
        "net" => Some("net"),
        _ => None,
    }
}

#[derive(Default, Debug, serde::Serialize, serde::Deserialize)]
pub struct Stats {
    pub records: u64,
    pub bytes: u64,
    pub truncated: u64,
    pub corrupt: u64,
    pub files: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub per: BTreeMap<String, u64>,
}

struct FileTail {
    off: u64,
    partial: Vec<u8>,
}

pub struct ScanState {
    tails: HashMap<PathBuf, FileTail>,
    seq: u64,
}

impl ScanState {
    pub fn new() -> Self {
        ScanState {
            tails: HashMap::new(),
            seq: 0,
        }
    }
}

pub struct Collector {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    stats: Arc<Mutex<Stats>>,
    raw_dir: PathBuf,
    out_dir: PathBuf,
    state: Arc<Mutex<ScanState>>,
}

fn ensure_raw_dir(raw_dir: &Path) {
    let _ = fs::create_dir_all(raw_dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(raw_dir, fs::Permissions::from_mode(0o777));
    }
}

/// One full scan of the raw dir. Newly appended bytes of every `<layer>-*.rec`
/// file are parsed record-by-record and materialized under `out_dir`.
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
    let mut index = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(out_dir.join("index.jsonl"))
    {
        Ok(f) => std::io::BufWriter::with_capacity(1 << 16, f),
        Err(_) => return,
    };

    for path in files {
        let layer = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(layer_of)
            .unwrap_or("");
        // pid from the `<layer>-<pid>.rec` stem - the sink filter groups
        // script chains per process ("one isolate/session = one stream").
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
        let mut chunk = Vec::new();
        if f.read_to_end(&mut chunk).is_err() {
            continue;
        }
        let new_off = off + chunk.len() as u64;
        let partial = {
            let e = state.tails.get_mut(&path).unwrap();
            e.off = new_off;
            &mut e.partial
        };
        partial.extend_from_slice(&chunk);
        let len = partial.len();
        let total_at = |p: usize| -> u32 {
            u32::from_le_bytes([partial[p], partial[p + 1], partial[p + 2], partial[p + 3]])
        };
        // A position is a plausible record start when the full header is
        // present, the length is sane, the kind fits the table, the flags
        // byte only uses bit0 and the reserved halfword is zero.
        let plausible_at = |p: usize| -> bool {
            if p + 16 > len {
                return false;
            }
            let t = total_at(p) as usize;
            t >= 16
                && t <= MAX_RECORD as usize
                && p + t <= len
                && partial[p + 4] <= MAX_KIND
                && partial[p + 5] <= 1
                && partial[p + 6] == 0
                && partial[p + 7] == 0
        };
        let mut consumed = 0usize;
        loop {
            if len - consumed < 16 {
                break;
            }
            let total = total_at(consumed) as usize;
            let header_ok = total >= 16
                && total <= MAX_RECORD as usize
                && partial[consumed + 4] <= MAX_KIND
                && partial[consumed + 5] <= 1
                && partial[consumed + 6] == 0
                && partial[consumed + 7] == 0;
            if !header_ok {
                stats.corrupt += 1;
                consumed += 1;
                continue;
            }
            if consumed + total > len {
                // Starved: either a record mid-write (wait) or corruption
                // with an in-range length (resync only when a complete
                // plausible record exists further ahead).
                let mut next = false;
                let mut p = consumed + 1;
                while p + 16 <= len {
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
            let rec = &partial[consumed..consumed + total as usize];
            let kind = rec[4];
            let flags = rec[5];
            let ts = u64::from_le_bytes([
                rec[8], rec[9], rec[10], rec[11], rec[12], rec[13], rec[14], rec[15],
            ]);
            let payload = &rec[16..];
            state.seq += 1;
            let kname = kind_name(kind);
            let fname = format!("{}-{}-{:06}.bin", layer, kname, state.seq);
            let fpath = raw_out.join(&fname);
            let _ = fs::write(&fpath, payload);
            let hash = blake3::hash(payload);
            let h16: String = hash.to_hex()[..16].to_string();
            let key = format!("{}/{}", layer, kname);
            *stats.per.entry(key).or_insert(0) += 1;
            stats.records += 1;
            stats.bytes += payload.len() as u64;
            if flags & 1 != 0 {
                stats.truncated += 1;
            }
            if stats.first_ts == 0 || ts < stats.first_ts {
                stats.first_ts = ts;
            }
            if ts > stats.last_ts {
                stats.last_ts = ts;
            }
            let mut j = J::new(128 + PREVIEW + fname.len());
            j.open();
            j.fkey("ts");
            j.u64v(ts);
            j.key("l");
            j.s(layer);
            j.key("pid");
            j.u64v(pid);
            j.key("k");
            j.s(kname);
            j.key("len");
            j.u64v(payload.len() as u64);
            if flags != 0 {
                j.key("f");
                j.u64v(flags as u64);
            }
            j.key("h");
            j.s(&h16);
            j.key("p");
            j.s(&format!("raw/{}", fname));
            if let Some(txt) = text_preview(payload) {
                j.key("txt");
                j.s(&txt);
            }
            let line = j.fin();
            let _ = index.write_all(&line);
            let _ = index.write_all(b"\n");
            consumed += total as usize;
        }
        let rest = partial[consumed..].to_vec();
        state.tails.get_mut(&path).unwrap().partial = rest;
    }
    let _ = index.flush();
    let _ = fs::write(
        out_dir.join("stats.json"),
        serde_json::to_vec(&*stats).unwrap_or_default(),
    );
}

fn text_preview(payload: &[u8]) -> Option<String> {
    let n = payload.len().min(PREVIEW);
    let head = &payload[..n];
    let s = simdutf8::basic::from_utf8(head).ok()?;
    let mut cut = s.len();
    if payload.len() > PREVIEW {
        cut = s.char_indices().map(|(i, _)| i).last().unwrap_or(0);
    }
    Some(s[..cut].to_string())
}

impl Collector {
    pub fn spawn(stage_root: &Path) -> Collector {
        Collector::spawn_dirs(
            PathBuf::from(std::env::var("AF_RAW_DIR").unwrap_or_else(|_| DEFAULT_RAW_DIR.into())),
            stage_root.join("collect"),
        )
    }

    pub fn spawn_dirs(raw_dir: PathBuf, out_dir: PathBuf) -> Collector {
        let _ = fs::create_dir_all(&out_dir);
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Mutex::new(Stats::default()));
        let state = Arc::new(Mutex::new(ScanState::new()));
        let stop2 = stop.clone();
        let stats2 = stats.clone();
        let state2 = state.clone();
        let raw2 = raw_dir.clone();
        let out2 = out_dir.clone();
        let handle = std::thread::Builder::new()
            .name("afeye-collect".into())
            .spawn(move || {
                let mut tick: u32 = 0;
                while !stop2.load(Ordering::Acquire) {
                    if let (Ok(mut st), Ok(mut sc)) = (state2.lock(), stats2.lock()) {
                        scan_once(&raw2, &out2, &mut st, &mut sc);
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
            })
            .ok();
        Collector {
            stop,
            handle,
            stats,
            raw_dir,
            out_dir,
            state,
        }
    }

    /// sink-hello records seen so far, summed over the three layers.
    /// Proof whether the running chrome actually contains afeye sinks:
    /// a stock build writes nothing to the raw dir, ever.
    pub fn hellos(&self) -> u64 {
        self.stats
            .lock()
            .map(|s| {
                ["v8/sink-hello", "blink/sink-hello", "net/sink-hello"]
                    .iter()
                    .filter_map(|k| s.per.get(*k).copied())
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Shared read-only probe usable from another thread before `stop()`.
    /// Returns a closure reading the live sink-hello count.
    pub fn hellos_handle(&self) -> impl Fn() -> u64 + Send + 'static {
        let stats = self.stats.clone();
        move || {
            stats
                .lock()
                .map(|s| {
                    ["v8/sink-hello", "blink/sink-hello", "net/sink-hello"]
                        .iter()
                        .filter_map(|k| s.per.get(*k).copied())
                        .sum()
                })
                .unwrap_or(0)
        }
    }

    /// Stop the scan thread, run one final drain scan, return final stats.
    pub fn stop(mut self) -> Stats {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if let (Ok(mut st), Ok(mut sc)) = (self.state.lock(), self.stats.lock()) {
            scan_once(&self.raw_dir, &self.out_dir, &mut st, &mut sc);
            let _ = fs::write(
                self.out_dir.join("stats.json"),
                serde_json::to_vec(&*sc).unwrap_or_default(),
            );
            return std::mem::take(&mut *sc);
        }
        Stats::default()
    }
}

/// Standalone entry: tail the raw dir until killed (used by the afeye-collect
/// bin for local probing next to a patched browser).
pub fn run_standalone(raw_dir: &Path, out_dir: &Path) {
    let mut state = ScanState::new();
    let mut stats = Stats::default();
    eprintln!("[collect] watching {} -> {}", raw_dir.display(), out_dir.display());
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

    fn rec(kind: u8, flags: u8, ts: u64, payload: &[u8]) -> Vec<u8> {
        let total = (16 + payload.len()) as u32;
        let mut v = Vec::with_capacity(16 + payload.len());
        v.extend_from_slice(&total.to_le_bytes());
        v.push(kind);
        v.push(flags);
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(&ts.to_le_bytes());
        v.extend_from_slice(payload);
        v
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
        f.write_all(&rec(0, 0, 55, b"afeye-sink/v8 v2 pid=1")).unwrap();
        // torn tail: full record is 20 bytes, only the first 12 written
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
        assert_eq!(stats.per.get("v8/script-source"), Some(&1));
        assert_eq!(stats.per.get("v8/wasm-module"), Some(&1));
        assert_eq!(stats.per.get("v8/sink-hello"), Some(&1));
        let idx = fs::read_to_string(out.join("index.jsonl")).unwrap();
        assert_eq!(idx.lines().count(), 3);
        assert!(idx.contains("\"k\":\"script-source\""));
        assert!(idx.contains("\"f\":1"));
        assert!(idx.contains("\"txt\":\"var a=1;\""));
        let bin = fs::read(out.join("raw/v8-wasm-module-000002.bin")).unwrap();
        assert_eq!(bin, vec![9u8; 32]);
        assert_eq!(fs::read(out.join("raw/v8-script-source-000001.bin")).unwrap(), b"var a=1;");

        // append the missing 8 bytes -> torn record completes on next scan
        let mut f = OpenOptions::new().append(true).open(raw.join("v8-4242.rec")).unwrap();
        f.write_all(&full[12..]).unwrap();
        drop(f);
        scan_once(&raw, &out, &mut state, &mut stats);
        assert_eq!(stats.records, 4);
        assert_eq!(stats.per.get("v8/atomics"), Some(&1));
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
        assert_eq!(stats.per.get("net/net-request"), Some(&1));
    }

    #[test]
    fn layer_filter_rejects_unknown() {
        assert_eq!(layer_of("v8-123"), Some("v8"));
        assert_eq!(layer_of("blink-45"), Some("blink"));
        assert_eq!(layer_of("net-9"), Some("net"));
        assert_eq!(layer_of("garbage-1"), None);
        assert_eq!(layer_of("nope"), None);
    }
}
