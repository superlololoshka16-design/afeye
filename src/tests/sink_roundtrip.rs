//! Honest round-trip: the sink C++ that ships inside the .patch files is
//! extracted, compiled with g++, run with the sink active, and its records
//! are read back through the production collector (afeye::collect) and
//! verified byte-exact. If this test is green, the bytes in the patch are
//! provably the bytes that produced the timeline.

use afeye::collect::{scan_once, ScanState, Stats};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn extract_new_files(patch: &Path, out_root: &Path) {
    let text = std::fs::read_to_string(patch).expect("patch read");
    let mut current: Option<String> = None;
    let mut body: Vec<u8> = Vec::new();
    let mut in_hunk = false;
    // only new-file hunks are extracted: `@@ -0,0` bodies are pure '+'
    // lines, and the destination is the b/ path (4th token of the header).
    let flush = |current: &mut Option<String>, body: &mut Vec<u8>, in_hunk: &mut bool| {
        if let (Some(path), true) = (current.take(), *in_hunk) {
            if !body.is_empty() {
                let dest = out_root.join(path.trim_start_matches("b/"));
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).unwrap();
                }
                std::fs::write(dest, &body).unwrap();
            }
        }
        body.clear();
        *in_hunk = false;
    };
    for line in text.split_inclusive('\n') {
        if line.starts_with("diff --git ") {
            flush(&mut current, &mut body, &mut in_hunk);
            let mut it = line.split_whitespace();
            let _ = it.next();
            let _ = it.next();
            let _ = it.next();
            current = it.next().map(|s| s.to_string());
        } else if line.starts_with("@@ -0,0") {
            if current.is_some() {
                in_hunk = true;
            }
        } else if in_hunk {
            if let Some(rest) = line.strip_prefix('+') {
                body.extend_from_slice(rest.as_bytes());
            } else if line.starts_with(' ') || line.starts_with('-') {
                flush(&mut current, &mut body, &mut in_hunk);
            }
        }
    }
    flush(&mut current, &mut body, &mut in_hunk);
}

fn have_gxx() -> bool {
    Command::new("g++")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn sink_patch_roundtrip_is_byte_exact() {
    if !have_gxx() {
        eprintln!("skipping sink round-trip: no g++ on PATH");
        return;
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    for p in [
        "0001-v8-sink.patch",
        "0006-blink-sink.patch",
        "0011-network-wire.patch",
    ] {
        extract_new_files(&manifest.join("src/patches").join(p), &src);
    }
    let v8_sink = src.join("src/afeye/sink.cc");
    let blink_sink = src.join("third_party/blink/renderer/platform/afeye/sink.cc");
    let net_sink = src.join("services/network/public/cpp/afeye_sink.cc");
    assert!(v8_sink.exists(), "v8 sink not extracted");
    assert!(blink_sink.exists(), "blink sink not extracted");
    assert!(net_sink.exists(), "net sink not extracted");

    let inc = format!("-I{}", src.display());
    let compile = |args: &[&str], bin: &str| {
        let out = Command::new("g++")
            .args(args)
            .arg("-o")
            .arg(dir.path().join(bin))
            .output()
            .expect("g++ spawn");
        assert!(
            out.status.success(),
            "g++ failed for {bin}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    compile(
        &[
            "-std=c++17",
            "-O2",
            "-DV8_AFEYE",
            &inc,
            v8_sink.to_str().unwrap(),
            manifest.join("tools/sink_test_main.cc").to_str().unwrap(),
        ],
        "v8_test",
    );
    compile(
        &[
            "-std=c++17",
            "-O2",
            "-DBLINK_AFEYE",
            &inc,
            blink_sink.to_str().unwrap(),
            manifest.join("tools/blink_smoke_main.cc").to_str().unwrap(),
        ],
        "blink_test",
    );
    compile(
        &[
            "-std=c++17",
            "-O2",
            "-DNET_AFEYE",
            &inc,
            net_sink.to_str().unwrap(),
            manifest.join("tools/net_smoke_main.cc").to_str().unwrap(),
        ],
        "net_test",
    );

    // 1. env-off: the patched sink must stay silent without AFEYE_SINK.
    let out = Command::new(dir.path().join("v8_test"))
        .arg("off")
        .env_remove("AFEYE_SINK")
        .output()
        .expect("run off");
    assert!(out.status.success(), "off-run must exit 0");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "enabled=0");

    // 2. env-on battery for all three layers.
    let raw = dir.path().join("afeye-raw");
    let collect_out = dir.path().join("collect");
    std::fs::create_dir_all(&raw).unwrap();
    for bin in ["v8_test", "blink_test", "net_test"] {
        let out = Command::new(dir.path().join(bin))
            .env("AFEYE_SINK", "1")
            .env("AFEYE_RAW_DIR", &raw)
            .output()
            .unwrap_or_else(|e| panic!("run {bin}: {e}"));
        assert!(
            out.status.success(),
            "{bin} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // 3. drain: poll until BATTERY-END shows up through the collector.
    let mut state = ScanState::new();
    let mut stats = Stats::default();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        scan_once(&raw, &collect_out, &mut state, &mut stats);
        let idx =
            std::fs::read_to_string(collect_out.join("index.jsonl")).unwrap_or_default();
        if idx.contains("BATTERY-END") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "BATTERY-END never arrived; stats so far: {stats:?}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }

    // 4. exact assertions on the materialized timeline.
    let idx = std::fs::read_to_string(collect_out.join("index.jsonl")).unwrap();
    let mut lines: Vec<&str> = idx.lines().collect();
    lines.sort();
    let count = |k: &str| {
        lines
            .iter()
            .filter(|l| l.contains(&format!("\"k\":\"{k}\"")))
            .count()
    };

    assert_eq!(count("sink-hello"), 3, "one hello per layer");
    assert_eq!(count("script-source"), 3, "str + twostr + truncated");
    assert_eq!(count("wasm-module"), 1);
    assert_eq!(count("microtask-enqueue"), 1);
    assert_eq!(count("atomics"), 2, "probe + BATTERY-END, zero-len dropped");
    assert_eq!(count("sab-backing"), 1);
    assert_eq!(count("bytecode-entry"), 4000, "8 threads x 500");
    assert_eq!(count("timer"), 1, "blink smoke");
    assert_eq!(count("crypto-op"), 1, "blink smoke");
    assert_eq!(count("message"), 1, "blink smoke");
    assert_eq!(count("net-request"), 2, "method/url + req-body span");

    let read_bin = |needle: &str| -> Vec<u8> {
        for l in &lines {
            if l.contains(needle) {
                let p = l.split("\"p\":\"").nth(1).unwrap().split('"').next().unwrap();
                return std::fs::read(collect_out.join(p)).unwrap();
            }
        }
        panic!("no index line with {needle}");
    };

    assert_eq!(read_bin("console.log(1);"), b"console.log(1);");
    assert_eq!(read_bin("http://x/dd.js"), b"http://x/dd.js\0var a=1;");
    let mut expected_span = b"span-tag\0".to_vec();
    expected_span.extend(
        (0..100u32).map(|i| (i.wrapping_mul(7).wrapping_add(3)) as u8),
    );
    assert_eq!(read_bin("\"k\":\"sab-backing\""), expected_span);
    let expected_wasm: Vec<u8> = (0..4096u32).map(|i| (i * 7 + 3) as u8).collect();
    assert_eq!(read_bin("\"k\":\"wasm-module\""), expected_wasm);
    assert_eq!(read_bin("BATTERY-END"), b"BATTERY-END");

    // truncated record: 2 MiB input capped to kMaxRecord-16 with flag 1.
    let trunc_line = lines
        .iter()
        .find(|l| l.contains("\"k\":\"script-source\"") && l.contains("\"f\":1"))
        .expect("truncated script-source record");
    let p = trunc_line.split("\"p\":\"").nth(1).unwrap().split('"').next().unwrap();
    let trunc_bin = std::fs::read(collect_out.join(p)).unwrap();
    assert_eq!(trunc_bin.len(), (1 << 20) - 16);
    assert!(trunc_bin.iter().all(|&b| b == b'B'));

    // storm integrity: every (tid,i) tuple survived the ring + file drain.
    let mut per_tid: BTreeMap<u32, u32> = BTreeMap::new();
    for l in &lines {
        if !l.contains("\"k\":\"bytecode-entry\"") {
            continue;
        }
        let p = l.split("\"p\":\"").nth(1).unwrap().split('"').next().unwrap();
        let b = std::fs::read(collect_out.join(p)).unwrap();
        assert_eq!(b.len(), 12);
        let tid = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let i = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let tag = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        assert_eq!(tag, 2);
        assert!(i < 500);
        *per_tid.entry(tid).or_insert(0) += 1;
    }
    assert_eq!(per_tid.len(), 8);
    assert!(per_tid.values().all(|&c| c == 500));

    let final_stats: Stats = serde_json::from_str(
        &std::fs::read_to_string(collect_out.join("stats.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(final_stats.corrupt, 0, "no torn records on the file path");
    assert_eq!(final_stats.truncated, 1);
    eprintln!(
        "sink round-trip OK: {} records, {} bytes, files={}",
        final_stats.records, final_stats.bytes, final_stats.files
    );
}
