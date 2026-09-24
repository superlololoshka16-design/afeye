use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;

// Decoder for the 0033 wire format (v8/src/afeye/bcrec.h - single source
// of truth; tests/bcrec_roundtrip.rs proves this parser agrees with the
// C++ builders byte-for-byte without building chromium).
//
// No limits, no caps, no length-guessing:
//   - payload blocks are [u8 tag][u32 len][bytes]; the tag says what the
//     bytes are. A type is never inferred from length.
//   - operand VALUES are engine-decoded (BytecodeDecoder in C++) and ride
//     in kTagOperand blocks. This decoder never re-derives operand layout
//     from the bytecode array - the static walk uses only per-opcode
//     sizes from the meta record for instruction boundaries and the CFG.
//   - func-def and meta blobs larger than one sink record arrive as
//     kFlagCont parts and are glued by (opcode, func_id) in offset order.

const HDR_LEN: usize = 72;
const OP_META: u8 = 0xfe;
const OP_FUNC_DEF: u8 = 0xff;
const FLAG_CONT: u8 = 2;
const FLAG_ACC_PAYLOAD: u8 = 4;

const TAG_ACC_STR: u8 = 0;
const TAG_ACC_F64: u8 = 1;
const TAG_ACC_SMI: u8 = 2;
const TAG_REG: u8 = 3;
const TAG_REG_STR: u8 = 4;
const TAG_REG_F64: u8 = 5;
const TAG_REG_SMI: u8 = 6;
const TAG_OPERAND: u8 = 7;
const TAG_ACC_STR16: u8 = 11;
const TAG_REG_STR16: u8 = 12;
const TAG_VCLOCK: u8 = 14;

#[derive(Clone)]
pub struct OpScaleMeta {
    pub size: u8,
    pub ops: Vec<(u8, u8)>, // (operand_type, offset)
}

pub struct OpMeta {
    pub name: String,
    pub n_ops: u8,
    pub flags: u8,   // bit0 jump, bit1 returns, bit2 calls, 3-4 subtype, 5 cond
    pub acc_use: u8, // 1 reads acc, 2 writes acc, 4 clobbers, 8 short-star
    pub scales: [OpScaleMeta; 3],
}

#[derive(Clone, Debug)]
pub enum CpEntry {
    Raw(u64),
    Str(Vec<u8>),   // 8-bit bytes
    Str16(Vec<u8>), // UTF-16LE bytes
    F64(f64),
}

pub struct FuncDef {
    pub func_id: u32,
    pub line: u32,
    pub frame_size: i32,
    pub param_count: u32,
    pub script_id: i32,
    pub script_name: String,
    pub fn_name: String,
    pub bytecode: Vec<u8>,
    pub cp: Vec<CpEntry>,
}

// typed payload values - tag-driven decode
#[derive(Clone, Debug)]
pub enum Pv {
    Str(Vec<u8>),
    Str16(Vec<u8>),
    F64(f64),
    Smi(i32),
    RegWord(u16, u64),
    RegStr(u16, Vec<u8>),
    RegStr16(u16, Vec<u8>),
    RegF64(u16, f64),
    RegSmi(u16, i32),
    Operand(u8, i64),
    Vclock(u64),
}

pub struct InstrRec {
    pub ts: u64,
    pub pid: u64,
    pub func_id: u32,
    pub offset: u32,
    pub opcode: u8,
    pub scale: u8,
    pub flags: u8,
    pub iso: u32,
    pub acc: u64,
    pub vclock: u64, // 0 = not emitted (AFEYE_VIRTUAL_CLOCK off)
    pub payloads: Vec<Pv>,
}

#[derive(Default)]
pub struct Stats {
    pub records: u64,
    pub instructions: u64,
    pub funcs: u64,
    pub dead_blocks: u64,
    pub live_blocks: u64,
    pub dead_bytes: u64,
    pub live_bytes: u64,
}

fn rd_u16(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
fn rd_u32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
fn rd_i32(b: &[u8], i: usize) -> i32 {
    i32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
fn rd_u64(b: &[u8], i: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[i..i + 8]);
    u64::from_le_bytes(x)
}

fn utf16le_to_string(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

// parse payload blocks: [u8 tag][u32 len][len bytes] until part end.
fn parse_blocks(rec: &[u8]) -> Vec<Pv> {
    let mut out = Vec::new();
    let mut i = HDR_LEN;
    while i + 5 <= rec.len() {
        let tag = rec[i];
        let len = rd_u32(rec, i + 1) as usize;
        i += 5;
        if i + len > rec.len() {
            break;
        }
        let b = &rec[i..i + len];
        i += len;
        let pv = match tag {
            TAG_ACC_STR => Pv::Str(b.to_vec()),
            TAG_ACC_STR16 => Pv::Str16(b.to_vec()),
            TAG_ACC_F64 if len == 8 => Pv::F64(f64::from_bits(rd_u64(b, 0))),
            TAG_ACC_SMI if len == 4 => Pv::Smi(rd_i32(b, 0)),
            TAG_REG if len == 10 => Pv::RegWord(rd_u16(b, 0), rd_u64(b, 2)),
            TAG_REG_STR if len >= 2 => Pv::RegStr(rd_u16(b, 0), b[2..].to_vec()),
            TAG_REG_STR16 if len >= 2 => {
                Pv::RegStr16(rd_u16(b, 0), b[2..].to_vec())
            }
            TAG_REG_F64 if len == 10 => {
                Pv::RegF64(rd_u16(b, 0), f64::from_bits(rd_u64(b, 2)))
            }
            TAG_REG_SMI if len == 6 => Pv::RegSmi(rd_u16(b, 0), rd_i32(b, 2)),
            TAG_OPERAND if len == 9 => {
                Pv::Operand(b[0], rd_u64(b, 1) as i64)
            }
            TAG_VCLOCK if len == 8 => Pv::Vclock(rd_u64(b, 0)),
            _ => continue,
        };
        out.push(pv);
    }
    out
}

// ---- meta ----
// [u16 n_bc][i32 reg_start] per-bc: name\0 n_ops flags acc_use
//   3x(u8 size, n_ops x (type, offset))  [u16 n_rt] names\0
fn parse_meta(p: &[u8]) -> Option<(Vec<OpMeta>, Vec<String>, i32)> {
    // blob starts AFTER the 72-byte Hdr (opcode 0xfe, acc = blob len)
    if p.len() < HDR_LEN + 6 || p[0] != OP_META {
        return None;
    }
    let mut i = HDR_LEN;
    let n_bc = rd_u16(p, i) as usize;
    i += 2;
    let reg_start = rd_i32(p, i);
    i += 4;
    let mut out = Vec::with_capacity(n_bc);
    for _ in 0..n_bc {
        let start = i;
        while i < p.len() && p[i] != 0 {
            i += 1;
        }
        if i >= p.len() {
            return None;
        }
        let name = String::from_utf8_lossy(&p[start..i]).into_owned();
        i += 1;
        if i + 3 > p.len() {
            return None;
        }
        let n_ops = p[i];
        let flags = p[i + 1];
        let acc_use = p[i + 2];
        i += 3;
        let mut scales = Vec::new();
        for _s in 0..3 {
            if i >= p.len() {
                return None;
            }
            let size = p[i];
            i += 1;
            let mut ops = Vec::new();
            for _o in 0..n_ops {
                if i + 2 > p.len() {
                    return None;
                }
                ops.push((p[i], p[i + 1]));
                i += 2;
            }
            scales.push(OpScaleMeta { size, ops });
        }
        out.push(OpMeta {
            name,
            n_ops,
            flags,
            acc_use,
            scales: [scales.remove(0), scales.remove(0), scales.remove(0)],
        });
    }
    let mut rt = Vec::new();
    if i + 2 <= p.len() {
        let n_rt = rd_u16(p, i) as usize;
        i += 2;
        for _ in 0..n_rt {
            let st = i;
            while i < p.len() && p[i] != 0 {
                i += 1;
            }
            rt.push(String::from_utf8_lossy(&p[st..i]).into_owned());
            i += 1;
        }
    }
    Some((out, rt, reg_start))
}

// ---- func-def blob ----
// [u32 bc_len][u32 name_len][u32 cp_bytes][i32 frame_size][u32 param_count]
// | bc | name | cp blocks (framed like payloads)
fn parse_func_def_blob(
    func_id: u32,
    line: u32,
    blob: &[u8],
) -> Option<FuncDef> {
    // head (32 bytes): [u32 bc_len][u32 script_name_len][u32 fn_name_len]
    // [u32 cp_bytes][i32 frame_size][u32 param_count][i32 script_id]
    // [u32 _reserved]
    if blob.len() < 32 {
        return None;
    }
    let bc_len = rd_u32(blob, 0) as usize;
    let script_name_len = rd_u32(blob, 4) as usize;
    let fn_name_len = rd_u32(blob, 8) as usize;
    let cp_bytes = rd_u32(blob, 12) as usize;
    let frame_size = rd_i32(blob, 16);
    let param_count = rd_u32(blob, 20);
    let script_id = rd_i32(blob, 24);
    let mut i = 32;
    if i + bc_len + script_name_len + fn_name_len + cp_bytes > blob.len() {
        return None;
    }
    let bytecode = blob[i..i + bc_len].to_vec();
    i += bc_len;
    let script_name =
        String::from_utf8_lossy(&blob[i..i + script_name_len]).into_owned();
    i += script_name_len;
    let fn_name = String::from_utf8_lossy(&blob[i..i + fn_name_len]).into_owned();
    i += fn_name_len;
    let cp_end = i + cp_bytes;
    let mut cp = Vec::new();
    while i + 5 <= cp_end {
        let tag = blob[i];
        let len = rd_u32(blob, i + 1) as usize;
        i += 5;
        if i + len > cp_end {
            break;
        }
        let b = &blob[i..i + len];
        i += len;
        cp.push(match tag {
            8 => CpEntry::Str(b.to_vec()),
            13 => CpEntry::Str16(b.to_vec()),
            9 if len == 8 => CpEntry::F64(f64::from_bits(rd_u64(b, 0))),
            _ if len == 8 => CpEntry::Raw(rd_u64(b, 0)),
            _ => CpEntry::Raw(0),
        });
    }
    Some(FuncDef {
        func_id,
        line,
        frame_size,
        param_count,
        script_id,
        script_name,
        fn_name,
        bytecode,
        cp,
    })
}

fn parse_instr(rec: &[u8], ts: u64, pid: u64) -> Option<InstrRec> {
    if rec.len() < HDR_LEN || rec[0] == OP_FUNC_DEF || rec[0] == OP_META {
        return None;
    }
    let payloads = parse_blocks(rec);
    let vclock = payloads
        .iter()
        .find_map(|pv| match pv {
            Pv::Vclock(v) => Some(*v),
            _ => None,
        })
        .unwrap_or(0);
    Some(InstrRec {
        ts,
        pid,
        func_id: rd_u32(rec, 8),
        offset: rd_u32(rec, 4),
        opcode: rec[0],
        scale: rec[1],
        flags: rec[3],
        iso: rd_u32(rec, 12),
        acc: rd_u64(rec, 16),
        vclock,
        payloads,
    })
}

struct DecodedInstr {
    offset: usize,
    opcode: u8,
}

// static walk for instruction boundaries + CFG. Uses ONLY per-opcode
// total sizes from the engine meta. Operand values come from records.
fn decode_func(bc: &[u8], meta: &[OpMeta]) -> Option<Vec<DecodedInstr>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < bc.len() {
        let op = bc[off] as usize;
        if op >= meta.len() {
            return None;
        }
        let m = &meta[op];
        let (rop, scale_i, base) = if m.name == "Wide" || m.name == "DebugBreakWide"
        {
            if off + 1 >= bc.len() {
                return None;
            }
            (bc[off + 1] as usize, 1usize, off + 1)
        } else if m.name == "ExtraWide" || m.name == "DebugBreakExtraWide" {
            if off + 1 >= bc.len() {
                return None;
            }
            (bc[off + 1] as usize, 2usize, off + 1)
        } else {
            (op, 0usize, off)
        };
        if rop >= meta.len() {
            return None;
        }
        let rm = &meta[rop];
        let sm = &rm.scales[scale_i];
        let total = sm.size as usize + (base - off);
        out.push(DecodedInstr {
            offset: base,
            opcode: rop as u8,
        });
        off += total;
    }
    Some(out)
}

fn cp_json(cp: &[CpEntry], idx: usize) -> Option<serde_json::Value> {
    match cp.get(idx)? {
        CpEntry::Str(b) => Some(json!(String::from_utf8_lossy(b))),
        CpEntry::Str16(b) => Some(json!(utf16le_to_string(b))),
        CpEntry::F64(f) => Some(json!(f)),
        CpEntry::Raw(w) => Some(json!(w)),
    }
}

// CFG block starts + edges, v8 jump semantics from meta flags:
//   subtype 1: target = offset + imm   (imm = operand 0, unsigned)
//   subtype 2: target = offset - imm   (JumpLoop)
//   subtype 3: target = offset + cp[imm] as Smi
//   subtype 4: switch - unresolved (executed offsets are ground truth)
// imm values come from the EXECUTED records (engine-decoded operands);
// static edges use the decoded instruction stream where available.
fn block_starts_of(instrs: &[DecodedInstr], meta: &[OpMeta]) -> Vec<usize> {
    let mut starts: HashSet<usize> = HashSet::new();
    starts.insert(instrs.first().map(|d| d.offset).unwrap_or(0));
    for (i, d) in instrs.iter().enumerate() {
        let m = &meta[d.opcode as usize];
        if m.flags & 3 != 0 {
            if let Some(nx) = instrs.get(i + 1) {
                starts.insert(nx.offset);
            }
        }
    }
    let mut sv: Vec<usize> = starts.into_iter().collect();
    sv.sort_unstable();
    sv
}

pub fn run(collect_dir: &Path) -> Result<Stats, String> {
    let mut stats = Stats::default();
    let index_p = collect_dir.join("index.jsonl");
    let index = match fs::read_to_string(&index_p) {
        Ok(s) => s,
        Err(_) => return Ok(stats),
    };
    let raw_dir = collect_dir.to_path_buf();

    let mut recs: Vec<(u64, u64, String, u64, u64)> = Vec::new();
    for line in index.lines() {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if v.get("k").and_then(|x| x.as_str()) != Some("bytecode-trace") {
            continue;
        }
        let path = v.get("p").and_then(|x| x.as_str()).unwrap_or("");
        if path.is_empty() {
            continue;
        }
        recs.push((
            v.get("ts").and_then(|x| x.as_u64()).unwrap_or(0),
            v.get("pid").and_then(|x| x.as_u64()).unwrap_or(0),
            path.to_string(),
            v.get("o").and_then(|x| x.as_u64()).unwrap_or(0),
            v.get("len").and_then(|x| x.as_u64()).unwrap_or(0),
        ));
    }
    stats.records = recs.len() as u64;
    if recs.is_empty() {
        return Ok(stats);
    }

    let mut meta: Vec<OpMeta> = Vec::new();
    let mut rt_names: Vec<String> = Vec::new();
    let mut funcs: HashMap<u32, FuncDef> = HashMap::new();
    let mut stream: Vec<InstrRec> = Vec::new();
    let mut executed: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut exec_count: HashMap<u32, u64> = HashMap::new();
    let mut first_ts: HashMap<u32, u64> = HashMap::new();

    // cont-part assembly: (opcode, func_id) -> ordered payload parts
    let mut parts: BTreeMap<(u8, u32), BTreeMap<u32, Vec<u8>>> = BTreeMap::new();

    let mut by_file: BTreeMap<&str, Vec<&(u64, u64, String, u64, u64)>> =
        BTreeMap::new();
    for r in &recs {
        by_file.entry(r.2.as_str()).or_default().push(r);
    }

    for (fname, group) in by_file {
        let blob = match fs::read(raw_dir.join(fname)) {
            Ok(b) => b,
            Err(_) => continue,
        };
        for (ts, pid, _p, off, len) in group {
            let start = *off as usize;
            let end = start + *len as usize;
            if end > blob.len() {
                continue;
            }
            let rec = &blob[start..end];
            if rec.len() < HDR_LEN {
                continue;
            }
            let opcode = rec[0];
            let flags = rec[3];
            let func_id = rd_u32(rec, 8);

            if opcode == OP_META || opcode == OP_FUNC_DEF {
                // blob record: single or cont-split. glue by position.
                let payload = &rec[HDR_LEN..];
                let m = parts.entry((opcode, func_id)).or_default();
                m.entry(rd_u32(rec, 4)).or_default().extend_from_slice(payload);
                if flags & FLAG_CONT == 0 {
                    // final part arrived: assemble
                    if let Some(map) = parts.remove(&(opcode, func_id)) {
                        let mut full: Vec<u8> = Vec::new();
                        for (_pos, b) in map {
                            full.extend_from_slice(&b);
                        }
                        // re-frame as a single-part record for the parsers
                        let mut one = rec[0..HDR_LEN].to_vec();
                        one.extend_from_slice(&full);
                        if opcode == OP_META {
                            if let Some((mm, rt, _rs)) = parse_meta(&one) {
                                meta = mm;
                                rt_names = rt;
                            }
                        } else if let Some(d) =
                            parse_func_def_blob(func_id, rd_u32(rec, 12), &full)
                        {
                            funcs.insert(func_id, d);
                            stats.funcs = funcs.len() as u64;
                        }
                    }
                }
                continue;
            }

            // instruction record (cont parts glue into one stream entry)
            if flags & FLAG_CONT != 0 {
                let m = parts.entry((opcode, func_id)).or_default();
                let e = m.entry(rd_u32(rec, 4)).or_default();
                if e.is_empty() {
                    // first part carries the header semantics; store whole rec
                    e.extend_from_slice(&rec[0..HDR_LEN]);
                }
                e.extend_from_slice(&rec[HDR_LEN..]);
                continue;
            }
            let ir = if let Some(map) = parts.remove(&(opcode, func_id)) {
                // glued: first stored entry begins with a saved header
                let mut full: Vec<u8> = Vec::new();
                for (_pos, b) in map {
                    full.extend_from_slice(&b);
                }
                parse_instr(&full, *ts, *pid)
            } else {
                parse_instr(rec, *ts, *pid)
            };
            if let Some(ir) = ir {
                stats.instructions += 1;
                executed.entry(ir.func_id).or_default().insert(ir.offset);
                *exec_count.entry(ir.func_id).or_insert(0) += 1;
                first_ts.entry(ir.func_id).or_insert(*ts);
                stream.push(ir);
            }
        }
    }
    if meta.is_empty() {
        return Err("bctrace: no meta record (0033 patch not active?)".into());
    }

    let out_dir = collect_dir.join("filtered").join("bctrace");
    let _ = fs::create_dir_all(&out_dir);
    let sem_dir = out_dir.join("sem");
    let _ = fs::create_dir_all(&sem_dir);

    // per-function reports: static walk, dead/live by executed offsets
    let mut func_reports = Vec::new();
    for (fid, def) in &funcs {
        let instrs = match decode_func(&def.bytecode, &meta) {
            Some(v) => v,
            None => continue,
        };
        let block_starts = block_starts_of(&instrs, &meta);
        let ex = executed.get(fid);
        let mut live_blocks = 0usize;
        let mut dead_blocks = 0usize;
        let mut dead_ranges: Vec<(usize, usize)> = Vec::new();
        let n_blocks = block_starts.len();
        for (bi, &bs) in block_starts.iter().enumerate() {
            let be = if bi + 1 < n_blocks {
                block_starts[bi + 1]
            } else {
                def.bytecode.len()
            };
            let hit = match ex {
                Some(s) => instrs
                    .iter()
                    .any(|d| d.offset >= bs && d.offset < be && s.contains(&(d.offset as u32))),
                None => false,
            };
            if hit {
                live_blocks += 1;
                stats.live_bytes += (be - bs) as u64;
            } else {
                dead_blocks += 1;
                dead_ranges.push((bs, be));
                stats.dead_bytes += (be - bs) as u64;
            }
        }
        stats.dead_blocks += dead_blocks as u64;
        stats.live_blocks += live_blocks as u64;

        let report = json!({
            "func_id": fid,
            "script_id": def.script_id,
            "script": def.script_name,
            "fn": def.fn_name,
            "line": def.line,
            "frame_size": def.frame_size,
            "param_count": def.param_count,
            "bc_len": def.bytecode.len(),
            "instructions": instrs.len(),
            "blocks": n_blocks,
            "executions": exec_count.get(fid).copied().unwrap_or(0),
            "live_blocks": live_blocks,
            "dead_blocks": dead_blocks,
            "dead_ranges": dead_ranges,
            "first_ts": first_ts.get(fid).copied().unwrap_or(0),
        });
        let fp = out_dir.join(format!("{:08x}.json", fid));
        if let Ok(mut f) = fs::File::create(&fp) {
            let bytes =
                serde_json::to_vec_pretty(&report).unwrap_or_default();
            let _ = f.write_all(&bytes);
        }
        func_reports.push(report);
    }

    // ---- semantic pass ----
    // stream sorted by ts; result of a write-acc opcode = acc of the NEXT
    // record with the same (pid, iso). Engine dataflow, no windowing.
    stream.sort_by_key(|r| r.ts);
    let mut next_same: HashMap<(u64, u32), Vec<usize>> = HashMap::new();
    for (n, r) in stream.iter().enumerate() {
        next_same.entry((r.pid, r.iso)).or_default().push(n);
    }
    let mut result_at: Vec<Option<usize>> = vec![None; stream.len()];
    for (_k, idxs) in &next_same {
        for w in idxs.windows(2) {
            result_at[w[0]] = Some(w[1]);
        }
    }

    let mut api_calls: BTreeMap<String, u64> = BTreeMap::new();
    let mut api_values: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    let mut sem_files: HashMap<u32, fs::File> = HashMap::new();

    let acc_of = |r: &InstrRec| -> Option<serde_json::Value> {
        if r.flags & FLAG_ACC_PAYLOAD == 0 {
            return None;
        }
        r.payloads.iter().find_map(|pv| match pv {
            Pv::Str(b) => Some(json!(String::from_utf8_lossy(b))),
            Pv::Str16(b) => Some(json!(utf16le_to_string(b))),
            Pv::F64(f) => Some(json!(f)),
            Pv::Smi(i) => Some(json!(i)),
            _ => None,
        })
    };

    for (n, r) in stream.iter().enumerate() {
        let m = match meta.get(r.opcode as usize) {
            Some(m) => m,
            None => continue,
        };
        let def = funcs.get(&r.func_id);

        // args from the record: engine-decoded operand values, cp-resolved
        let mut args: Vec<serde_json::Value> = Vec::new();
        for pv in &r.payloads {
            if let Pv::Operand(idx, v) = pv {
                // cp-index operands resolve through the function's constant
                // pool; runtime ids through the engine's name table.
                let resolved = match m.name.as_str() {
                    "LdaConstant" | "LdaGlobal" | "LdaGlobalInsideTypeof"
                    | "StaGlobal" | "LdaContextSlot" | "StaContextSlot"
                    | "GetNamedProperty" | "SetNamedProperty"
                    | "DefineNamedOwnProperty" | "AddNamedProperty"
                    | "CallProperty" | "CallProperty0" | "CallProperty1"
                    | "CallProperty2" | "CallUndefinedReceiver0"
                    | "CallUndefinedReceiver1" | "CallUndefinedReceiver2"
                    | "CallWithSpread" | "Construct" | "ConstructWithSpread"
                    | "TestReferenceEqual" | "JumpIfTrueConstant"
                    | "JumpIfFalseConstant" | "LdaLookupGlobalSlot" => {
                        if *idx == 0 {
                            def.and_then(|d| cp_json(&d.cp, *v as usize))
                        } else {
                            None
                        }
                    }
                    "CallRuntime" | "CallRuntimeForPair" => {
                        if *idx == 0 {
                            rt_names.get(*v as usize).map(|n| json!(n))
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                args.push(resolved.unwrap_or(json!(v)));
            }
        }

        let acc_in = acc_of(r);
        let result = if m.acc_use & 2 != 0 {
            result_at[n]
                .and_then(|j| stream.get(j))
                .and_then(|nx| acc_of(nx))
        } else {
            None
        };

        let key: Option<String> = match m.name.as_str() {
            "LdaGlobal" | "LdaGlobalInsideTypeof" | "LdaLookupGlobalSlot"
            | "StaGlobal" => args
                .first()
                .and_then(|a| a.as_str())
                .map(|n| format!("global {n}")),
            "GetNamedProperty" | "GetNamedPropertyFromSuper"
            | "SetNamedProperty" | "DefineNamedOwnProperty"
            | "AddNamedProperty" => args
                .first()
                .and_then(|a| a.as_str())
                .map(|n| format!("prop {n}")),
            "CallProperty" | "CallProperty0" | "CallProperty1"
            | "CallProperty2" | "CallUndefinedReceiver0"
            | "CallUndefinedReceiver1" | "CallUndefinedReceiver2"
            | "CallWithSpread" => args
                .first()
                .and_then(|a| a.as_str())
                .map(|n| format!("call {n}")),
            "CallRuntime" | "CallRuntimeForPair" => args
                .first()
                .and_then(|a| a.as_str())
                .map(|n| format!("runtime {n}")),
            _ => None,
        };
        if let Some(k) = &key {
            *api_calls.entry(k.clone()).or_insert(0) += 1;
            if let Some(v) = &result {
                let vals = api_values.entry(k.clone()).or_default();
                if vals.len() < 8 && !vals.iter().any(|x| x == v) {
                    vals.push(v.clone());
                }
            }
        }

        let f = sem_files.entry(r.func_id).or_insert_with(|| {
            fs::File::create(sem_dir.join(format!("{:08x}.jsonl", r.func_id)))
                .expect("sem file")
        });
        let mut line = json!({
            "ts": r.ts,
            "off": r.offset,
            "op": m.name,
        });
        if r.vclock != 0 {
            // timestamp_virtual: instruction-count-driven clock from 0034.
            // Physical ts stays for wall correlation; vts is deterministic
            // regardless of host speed.
            line["vts"] = json!(r.vclock);
        }
        if !args.is_empty() {
            line["args"] = json!(args);
        }
        if let Some(a) = acc_in {
            line["acc"] = a;
        }
        if let Some(res) = result {
            line["res"] = res;
        }
        // register values that rode along
        let regs: Vec<serde_json::Value> = r
            .payloads
            .iter()
            .filter_map(|pv| match pv {
                Pv::RegWord(i, w) => Some(json!({ "reg": *i, "word": w })),
                Pv::RegStr(i, b) => {
                    Some(json!({ "reg": *i, "v": String::from_utf8_lossy(b) }))
                }
                Pv::RegStr16(i, b) => {
                    Some(json!({ "reg": *i, "v": utf16le_to_string(b) }))
                }
                Pv::RegF64(i, f2) => Some(json!({ "reg": *i, "v": f2 })),
                Pv::RegSmi(i, v) => Some(json!({ "reg": *i, "v": v })),
                _ => None,
            })
            .collect();
        if !regs.is_empty() {
            line["regs"] = json!(regs);
        }
        let _ = writeln!(f, "{}", line);
    }

    let api_list: Vec<serde_json::Value> = api_calls
        .iter()
        .map(|(k, n)| {
            let mut e = json!({ "what": k, "times": n });
            if let Some(vals) = api_values.get(k) {
                e["values"] = json!(vals);
            }
            e
        })
        .collect();

    let summary = json!({
        "records": stats.records,
        "instructions": stats.instructions,
        "funcs": stats.funcs,
        "dead_blocks": stats.dead_blocks,
        "live_blocks": stats.live_blocks,
        "dead_bytes": stats.dead_bytes,
        "live_bytes": stats.live_bytes,
        "funcs_reported": func_reports.len(),
        "api_calls": api_list,
        "rule": "dead = basic block whose offsets NEVER appear in the executed stream. Operand values engine-decoded at emit time. Result of a write-acc instruction = acc of the next same-(pid,iso) record. Facts only.",
        "functions": func_reports,
    });
    let filt = collect_dir.join("filtered");
    let _ = fs::create_dir_all(&filt);
    let _ = fs::write(
        filt.join("bctrace.json"),
        serde_json::to_vec_pretty(&summary).unwrap_or_default(),
    );
    Ok(stats)
}
