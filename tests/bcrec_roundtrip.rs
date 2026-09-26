//! Honest round-trip of the 0033 bytecode-trace wire format on WIRE v3.
//!
//! bcrec.h and sink.cc are extracted FROM the patch files, compiled with
//! g++, run to emit a synthetic trace (meta + func-def + instruction
//! stream built with the SAME C++ builders the v8 runtime hook uses),
//! then the records are scanned through the production collector
//! (afeye::collect) and decoded by the production bctrace::run.
//!
//! WIRE v3: every record carries the 24-byte header
//!   [u32 total][u8 kind][u8 flags][u32 sid][u16 tid][u32 rsv][u64 ts_ns]
//! payload at offset 24; kind 40 (bytecode-trace) carries sid=tid=rsv=0.
//! The bcrec Hdr (72 bytes) rides INSIDE that payload, unchanged.
//!
//! Green here proves the C++ encoder and the Rust decoder agree
//! byte-for-byte - without building chromium.

use afeye::bctrace;
use afeye::collect::{
    scan_once, ScanState, Stats, KIND_BYTECODE_TRACE, KIND_SINK_HELLO, LAYER_V8,
};
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

fn rd_u16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
fn rd_u32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
fn rd_u64(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes([
        b[i], b[i + 1], b[i + 2], b[i + 3], b[i + 4], b[i + 5], b[i + 6], b[i + 7],
    ])
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
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "rec").unwrap_or(false))
        .collect();
    assert_eq!(rec_files.len(), 1, "exactly one v8-<pid>.rec");

    // WIRE v3 raw framing: 24-byte header per record, kind 40 stream with
    // sid=tid=reserved zero (the bcrec emitter runs outside any isolate),
    // ts at [16..24], payload at 24, records tile the file exactly.
    let buf = std::fs::read(&rec_files[0]).unwrap();
    let mut off = 0usize;
    let mut n40 = 0usize;
    let mut hello = false;
    while off + 24 <= buf.len() {
        let total = rd_u32(&buf, off) as usize;
        let kind = buf[off + 4];
        let flags = buf[off + 5];
        let sid = rd_u32(&buf, off + 6);
        let tid = rd_u16(&buf, off + 10);
        let rsv = rd_u32(&buf, off + 12);
        let ts = rd_u64(&buf, off + 16);
        assert!(total >= 24, "record total {total} < 24 at {off}");
        assert!(off + total <= buf.len(), "record overruns file at {off}");
        assert!(matches!(kind, 0 | 40), "unexpected kind {kind} at {off}");
        assert_eq!(flags, 0, "bcrec stream must not truncate");
        assert_eq!(sid, 0, "kind {kind} must carry sid=0");
        assert_eq!(tid, 0, "kind {kind} must carry tid=0");
        assert_eq!(rsv, 0, "reserved nonzero at {off}");
        assert!(ts > 0, "zero ts at {off}");
        if kind == 0 {
            hello = true;
            assert!(buf[off + 24..off + total].starts_with(b"afeye-sink/v8 v2 pid="));
        } else {
            n40 += 1;
        }
        off += total;
    }
    assert_eq!(off, buf.len(), "records must tile the file exactly");
    assert!(hello, "no sink-hello");
    assert_eq!(n40, 5, "expected meta+def+3 instr kind-40 records");

    // production collector
    let collect_dir = dir.path().join("collect");
    let mut state = ScanState::new();
    let mut stats = Stats::default();
    scan_once(&raw, &collect_dir, &mut state, &mut stats);
    assert_eq!(stats.corrupt, 0, "collector saw corrupt records");
    assert_eq!(stats.per_count(LAYER_V8, KIND_SINK_HELLO), 1);
    assert_eq!(
        stats.per_count(LAYER_V8, KIND_BYTECODE_TRACE),
        5,
        "expected meta+def+3 instr records"
    );

    // production decoder
    let st = bctrace::run(&collect_dir).expect("bctrace run");
    assert_eq!(st.records, 5, "bcrec records not indexed");
    assert_eq!(st.funcs, 1, "func-def not decoded");
    assert_eq!(st.instructions, 3, "instruction stream not decoded");
    // dead block: the func-def carries a never-executed tail LdaConstant
    // at offsets 4..6 -> exactly one dead block, 2 dead bytes
    assert_eq!(st.dead_blocks, 1, "dead block not detected by fact");
    assert_eq!(st.dead_bytes, 2);
    assert_eq!(st.live_blocks, 1);
    assert_eq!(st.offset_mismatch, 0, "static walk disagrees with stream");

    // deterministic identity: MakeFuncId(script_id=7, literal=0, pos=0,
    // isolate_tag=0x1234) - the same FNV-1a the C++ builder ran
    let fid = 0x1456b592u32;
    assert_eq!(st.func_scripts.get(&fid).map(String::as_str), Some("translit.js"));
    assert_eq!(st.script_ids.get(&7).map(String::as_str), Some("translit.js"));

    // valuebook.bin: 15-byte entry header [u32 len][u32 func_id][u32 off]
    // [u16 op_id][u8 src] + value bytes. The executed reg string rides
    // first (src=1, op Star0 @2); acc duplicates dedup away; the cp
    // literal "secret-key" is an existence fact (src=2, op_id=0xffff).
    let filt = collect_dir.join("filtered");
    let vb = std::fs::read(filt.join("valuebook.bin")).expect("valuebook.bin");
    let mut entries: Vec<(u32, u32, u16, u8, Vec<u8>)> = Vec::new();
    let mut p = 0usize;
    while p + 15 <= vb.len() {
        let len = rd_u32(&vb, p) as usize;
        assert!(p + 15 + len <= vb.len(), "valuebook entry overruns");
        entries.push((
            rd_u32(&vb, p + 4),
            rd_u32(&vb, p + 8),
            rd_u16(&vb, p + 12),
            vb[p + 14],
            vb[p + 15..p + 15 + len].to_vec(),
        ));
        p += 15 + len;
    }
    assert_eq!(p, vb.len(), "valuebook.bin parses cleanly to EOF");
    assert_eq!(st.valuebook_entries, 2);
    assert_eq!(st.valuebook_bytes, 21, "11 + 10 value bytes");
    assert_eq!(
        entries,
        vec![
            (fid, 2, 1, 1, b"Mozilla/5.0".to_vec()),
            (fid, 0, 0xffff, 2, b"secret-key".to_vec()),
        ]
    );

    // ops.txt: line n = opcode n's name (op_id = meta index)
    assert_eq!(
        std::fs::read_to_string(filt.join("ops.txt")).unwrap(),
        "LdaConstant\nStar0\nReturn\n"
    );

    // exec_funcs.bin: sorted LE u32 func_ids with exec_count > 0
    let ef = std::fs::read(filt.join("exec_funcs.bin")).unwrap();
    assert_eq!(ef.len(), 4);
    assert_eq!(rd_u32(&ef, 0), fid);

    // semantic stream: engine-decoded operands + cp resolution + result
    let rep: serde_json::Value =
        serde_json::from_slice(&std::fs::read(filt.join("bctrace.json")).unwrap()).unwrap();
    assert_eq!(rep["valuebook_entries"], 2);
    assert_eq!(rep["offset_mismatch"], 0);
    let f0 = &rep["functions"][0];
    assert_eq!(f0["func_id"].as_u64().unwrap(), fid as u64);
    assert_eq!(f0["dead_ranges"][0], serde_json::json!([4, 6]));
    let sem = std::fs::read_to_string(
        collect_dir
            .join("filtered/bctrace/sem")
            .join(format!("{:08x}.jsonl", fid)),
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
    assert!(regs.iter().any(|r| r["word"] == 0xbeef), "reg word missing");
    // Return: terminator, reads acc, writes nothing -> no res
    assert_eq!(lines[2]["op"], "Return");
    assert!(lines[2].get("res").is_none());

    // timestamp_virtual: vclock block rode on record 1 (emitter set
    // ib.Vclock(1000)) -> sem line carries vts
    assert_eq!(lines[0]["vts"], 1000);
    assert!(lines[1].get("vts").is_none());

    // function identity: fn_name and script_id are REAL fields now, not
    // the script name masquerading as function name
    assert_eq!(f0["script"], "translit.js");
    assert_eq!(f0["fn"], "translitFn");
    assert_eq!(f0["script_id"], 7);
}
