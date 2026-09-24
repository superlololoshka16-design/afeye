//! Honest round-trip of the 0033 bytecode-trace wire format.
//!
//! bcrec.h and sink.cc are extracted FROM the patch files, compiled with
//! g++, run to emit a synthetic trace (meta + func-def + instruction
//! stream built with the SAME C++ builders the v8 runtime hook uses),
//! then the records are scanned through the production collector
//! (afeye::collect) and decoded by the production bctrace::run.
//!
//! Green here proves the C++ encoder and the Rust decoder agree
//! byte-for-byte - without building chromium.

use afeye::bctrace;
use afeye::collect::{scan_once, ScanState, Stats};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn extract_new_files(patch: &Path, out_root: &Path) {
    let text = std::fs::read_to_string(patch).expect("patch read");
    let mut current: Option<String> = None;
    let mut body: Vec<u8> = Vec::new();
    let mut in_hunk = false;
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
fn bcrec_wire_roundtrip_is_byte_exact() {
    if !have_gxx() {
        eprintln!("skipping bcrec round-trip: no g++ on PATH");
        return;
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    // 0001 provides the sink; 0033 provides bcrec.h
    for p in ["0001-v8-sink.patch", "0033-v8-ignition-bytecode-trace.patch"] {
        extract_new_files(&manifest.join("patches").join(p), &src);
    }
    let sink_h = src.join("v8/src/afeye/sink.h");
    let bcrec_h = src.join("v8/src/afeye/bcrec.h");
    assert!(sink_h.exists(), "sink.h not extracted from 0001");
    assert!(bcrec_h.exists(), "bcrec.h not extracted from 0033");

    let inc_v8 = format!("-I{}", src.join("v8").display());
    let bin = dir.path().join("bcrec_test");
    let out = Command::new("g++")
        .args([
            "-std=c++17",
            "-O2",
            "-DV8_AFEYE",
            &inc_v8,
            src.join("v8/src/afeye/sink.cc").to_str().unwrap(),
            manifest.join("tools/bcrec_main.cc").to_str().unwrap(),
            "-o",
            bin.to_str().unwrap(),
            "-lpthread",
        ])
        .output()
        .expect("g++ spawn");
    assert!(
        out.status.success(),
        "g++ failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // run the emitter against a fresh raw dir
    let raw = dir.path().join("raw");
    std::fs::create_dir_all(&raw).unwrap();
    let run = Command::new(&bin)
        .env("AFEYE_SINK", "1")
        .env("AFEYE_RAW_DIR", &raw)
        .output()
        .expect("run emitter");
    assert!(run.status.success(), "emitter failed");

    // let the drain thread flush
    std::thread::sleep(Duration::from_millis(300));
    let rec_files: Vec<_> = std::fs::read_dir(&raw)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "rec").unwrap_or(false))
        .collect();
    assert!(!rec_files.is_empty(), "no .rec emitted");

    // production collector
    let collect_dir = dir.path().join("collect");
    let mut state = ScanState::new();
    let mut stats = Stats::default();
    scan_once(&raw, &collect_dir, &mut state, &mut stats);
    assert!(stats.corrupt == 0, "collector saw corrupt records");
    let bc_count = stats
        .per
        .get("v8/bytecode-trace")
        .copied()
        .unwrap_or(0);
    assert_eq!(bc_count, 5, "expected meta+def+3 instr records, got {bc_count}");

    // production decoder
    let st = bctrace::run(&collect_dir).expect("bctrace run");
    assert_eq!(st.funcs, 1, "func-def not decoded");
    assert_eq!(st.instructions, 3, "instruction stream not decoded");
    // dead block: the func-def carries a never-executed tail LdaConstant
    // at offsets 4..6 -> exactly one dead block, 2 dead bytes
    assert_eq!(st.dead_blocks, 1, "dead block not detected by fact");
    assert_eq!(st.dead_bytes, 2);

    // semantic stream: engine-decoded operands + cp resolution + result
    let fid_hex = {
        let rep: serde_json::Value = serde_json::from_slice(
            &std::fs::read(collect_dir.join("filtered/bctrace.json")).unwrap(),
        )
        .unwrap();
        rep["functions"][0]["func_id"].as_u64().unwrap()
    };
    let sem = std::fs::read_to_string(
        collect_dir
            .join("filtered/bctrace/sem")
            .join(format!("{:08x}.jsonl", fid_hex)),
    )
    .unwrap();
    let lines: Vec<serde_json::Value> =
        sem.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 3);
    // LdaConstant: cp operand 0 resolves to "secret-key", acc-in Smi 7,
    // result = acc of next record = "Mozilla/5.0"
    assert_eq!(lines[0]["op"], "LdaConstant");
    assert_eq!(lines[0]["args"][0], "secret-key");
    assert_eq!(lines[0]["acc"], 7);
    assert_eq!(lines[0]["res"], "Mozilla/5.0");
    // Star0: register value rode along in full
    assert_eq!(lines[1]["op"], "Star0");
    let regs = lines[1]["regs"].as_array().unwrap();
    assert!(regs.iter().any(|r| r["v"] == "Mozilla/5.0"), "reg value missing");
    // Return: terminator, reads acc, writes nothing -> no res
    assert_eq!(lines[2]["op"], "Return");
    assert!(lines[2].get("res").is_none());
}
