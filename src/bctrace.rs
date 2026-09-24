use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::Path;


const HDR_LEN: usize = 72;
const OP_META: u8 = 0xfe;
const OP_FUNC_DEF: u8 = 0xff;

#[derive(Clone)]
pub struct OpScaleMeta {
    pub size: u8,
    pub ops: Vec<(u8, u8)>, // (operand_type, offset)
}

pub struct OpMeta {
    pub name: String,
    pub n_ops: u8,
    pub flags: u8, // bit0 jump, bit1 returns, bit2 calls
    pub scales: [OpScaleMeta; 3],
}

#[derive(Clone)]
pub enum CpEntry {
    Raw(u64),
    Str(Vec<u8>),
    F64(f64),
}

pub struct FuncDef {
    pub func_id: u32,
    pub line: u32,
    pub frame_size: u32,
    pub param_count: u64,
    pub name: String,
    pub bytecode: Vec<u8>,
    pub cp: Vec<CpEntry>,
}

#[derive(Clone)]
pub struct InstrRec {
    pub ts: u64,
    pub func_id: u32,
    pub offset: u32,
    pub opcode: u8,
    pub scale: u8,
    pub acc: u64,
    pub regs: Vec<u64>,
    pub payloads: Vec<Vec<u8>>,
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
fn rd_u64(b: &[u8], i: usize) -> u64 {
    let mut x = [0u8; 8];
    x.copy_from_slice(&b[i..i + 8]);
    u64::from_le_bytes(x)
}
fn rd_i32(b: &[u8], i: usize) -> i32 {
    i32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

// meta record: [4-byte tag 0xfe 00 00 00][u16 n_bc] then per bytecode:
//   name\0 u8 n_ops u8 flags, then 3 scales x (u8 total_size,
//   n_ops x (u8 type, u8 offset)). Operand width = next_offset - offset
//   (last: total_size - offset). Mirrors AfeyeEmitMeta in runtime-trace.cc.
fn parse_meta(p: &[u8]) -> Option<Vec<OpMeta>> {
    if p.len() < 6 || p[0] != OP_META {
        return None;
    }
    let mut i = 4usize;
    let n_bc = rd_u16(p, i) as usize;
    i += 2;
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
        if i + 2 > p.len() {
            return None;
        }
        let n_ops = p[i];
        let flags = p[i + 1];
        i += 2;
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
            scales: [
                scales.remove(0),
                scales.remove(0),
                scales.remove(0),
            ],
        });
    }
    Some(out)
}


fn parse_func_def(rec: &[u8], ts: u64) -> Option<FuncDef> {
    if rec.len() < HDR_LEN + 12 || rec[0] != OP_FUNC_DEF {
        return None;
    }
    let _ = ts;
    let func_id = rd_u32(rec, 8);
    let line = rd_u32(rec, 12);
    let frame_size = rd_u32(rec, 4);
    let param_count = rd_u64(rec, 16);
    let mut i = HDR_LEN;
    let bc_len = rd_u32(rec, i) as usize;
    let name_len = rd_u32(rec, i + 4) as usize;
    let cp_total = rd_u32(rec, i + 8) as usize;
    i += 12;
    if i + bc_len + name_len + cp_total > rec.len() {
        return None;
    }
    let bytecode = rec[i..i + bc_len].to_vec();
    i += bc_len;
    let name = String::from_utf8_lossy(&rec[i..i + name_len]).into_owned();
    i += name_len;
    let cp_end = i + cp_total;
    let mut cp = Vec::new();
    while i < cp_end {
        let tag = rec[i];
        i += 1;
        match tag {
            1 => {
                let l = rd_u16(rec, i) as usize;
                i += 2;
                cp.push(CpEntry::Str(rec[i..i + l].to_vec()));
                i += l;
            }
            2 => {
                let bits = rd_u64(rec, i);
                cp.push(CpEntry::F64(f64::from_bits(bits)));
                i += 8;
            }
            _ => {
                cp.push(CpEntry::Raw(rd_u64(rec, i)));
                i += 8;
            }
        }
    }
    Some(FuncDef {
        func_id,
        line,
        frame_size,
        param_count,
        name,
        bytecode,
        cp,
    })
}

fn parse_instr(rec: &[u8], ts: u64) -> Option<InstrRec> {
    if rec.len() < HDR_LEN || rec[0] == OP_FUNC_DEF || rec[0] == OP_META {
        return None;
    }
    let opcode = rec[0];
    let scale = rec[1];
    let n_payload = rec[2] as usize;
    let offset = rd_u32(rec, 4);
    let func_id = rd_u32(rec, 8);
    let acc = rd_u64(rec, 16);
    let mut regs = Vec::new();
    for r in 0..6 {
        let w = rd_u64(rec, 24 + r * 8);
        if w != 0 {
            regs.push(w);
        }
    }
    let mut i = HDR_LEN;
    let mut payloads = Vec::new();
    for _ in 0..n_payload {
        if i + 2 > rec.len() {
            break;
        }
        let l = rd_u16(rec, i) as usize;
        i += 2;
        if i + l > rec.len() {
            break;
        }
        payloads.push(rec[i..i + l].to_vec());
        i += l;
    }
    Some(InstrRec {
        ts,
        func_id,
        offset,
        opcode,
        scale,
        acc,
        regs,
        payloads,
    })
}

struct DecodedInstr {
    offset: usize,
    opcode: u8,
    size: usize,
    ops: Vec<i64>, // decoded operand values (signed where relevant)
}

// decode the whole function using the meta tables emitted by the engine.
// returns None on any inconsistency (unknown opcode, out-of-range jump).
fn decode_func(bc: &[u8], meta: &[OpMeta]) -> Option<Vec<DecodedInstr>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < bc.len() {
        let op = bc[off] as usize;
        if op >= meta.len() {
            return None;
        }
        let m = &meta[op];
        // prefixes: Wide(0) / ExtraWide(1) - real opcode follows, scale
        // from the prefix itself.
        let (rop, scale_i, base) = if m.name == "Wide" || m.name == "DebugBreakWide" {
            (bc[off + 1] as usize, 1usize, off + 1)
        } else if m.name == "ExtraWide" || m.name == "DebugBreakExtraWide" {
            (bc[off + 1] as usize, 2usize, off + 1)
        } else {
            (op, 0usize, off)
        };
        if rop >= meta.len() {
            return None;
        }
        let rm = &meta[rop];
        let sm = &rm.scales[scale_i];
        let mut ops = Vec::new();
        for k in 0..rm.n_ops as usize {
            let (otype, ooff) = sm.ops[k];
            let at = base + ooff as usize;
            // operand width = next operand offset - this offset, or
            // total_size - offset for the last operand.
            let next_off = if k + 1 < rm.n_ops as usize {
                sm.ops[k + 1].1 as usize
            } else {
                sm.size as usize
            };
            let w = next_off - ooff as usize;
            // Signed types: Imm(14), Reg(15)..RegOutTriple(21).
            // All others unsigned.
            let signed = otype >= 14;
            let v: i64 = if signed {
                match w {
                    1 => bc[at] as i8 as i64,
                    2 => i16::from_le_bytes([bc[at], bc[at + 1]]) as i64,
                    4 => rd_i32(bc, at) as i64,
                    _ => return None,
                }
            } else {
                match w {
                    1 => bc[at] as i64,
                    2 => rd_u16(bc, at) as i64,
                    4 => rd_u32(bc, at) as i64,
                    _ => return None,
                }
            };
            ops.push(v);
        }
        let total = sm.size as usize + (base - off);
        out.push(DecodedInstr {
            offset: base, // post-prefix: matches runtime BytecodeOffset()
            opcode: rop as u8,
            size: total,
            ops,
        });
        off += total;
    }
    Some(out)
}

// CFG: basic blocks split at jump targets and after jump/return
// instructions. Returns (block_starts, edges). Static structure - what
// COULD execute. The trace says what DID.
fn build_cfg(
    instrs: &[DecodedInstr],
    meta: &[OpMeta],
    cp: &[CpEntry],
) -> (Vec<usize>, Vec<(usize, usize)>) {
    // v8 semantics, straight from the engine tables (no guessing):
    //   target = instr_start + rel, where rel comes from operand 0:
    //     subtype 1 (immediate forward): rel = +imm
    //     subtype 2 (JumpLoop):          rel = -imm
    //     subtype 3 (jump constant):     rel = i32 from cp[imm] (Smi)
    //     subtype 4 (switch):            targets = Smis in cp[imm ..]
    //   conditional jumps also fall through to instr_start + size.
    let mut starts: HashSet<usize> = HashSet::new();
    starts.insert(0);
    let mut edges: Vec<(usize, usize)> = Vec::new();
    let off_set: HashSet<usize> = instrs.iter().map(|d| d.offset).collect();

    let cp_smi = |idx: i64| -> Option<i64> {
        match cp.get(idx as usize)? {
            CpEntry::Raw(w) => {
                // tagged Smi: value = word >> kSmiShift (32 on x64)
                Some((*w >> 32) as i32 as i64)
            }
            CpEntry::F64(_) | CpEntry::Str(_) => None,
        }
    };

    for d in instrs {
        let m = &meta[d.opcode as usize];
        let is_jump = m.flags & 1 != 0;
        let is_ret = m.flags & 2 != 0;
        let jtype = (m.flags >> 3) & 3;
        let cond = m.flags & (1 << 5) != 0;
        if is_jump && !d.ops.is_empty() {
            let imm = d.ops[0];
            let mut targets: Vec<i64> = Vec::new();
            match jtype {
                1 => targets.push(d.offset as i64 + imm),
                2 => targets.push(d.offset as i64 - imm),
                3 => {
                    if let Some(rel) = cp_smi(imm) {
                        targets.push(d.offset as i64 + rel);
                    }
                }
                _ => {
                    // switch tables: cp-index operand position differs
                    // per opcode (ops[0] vs ops[1]). Not resolved here -
                    // dead-block detection uses executed offsets, not
                    // edges. No guessing.
                }
            }
            for t in targets {
                if t >= 0 && off_set.contains(&(t as usize)) {
                    starts.insert(t as usize);
                    edges.push((d.offset, t as usize));
                }
            }
            if cond {
                let f = d.offset + d.size;
                if off_set.contains(&f) {
                    edges.push((d.offset, f));
                }
            }
        }
        if !is_jump && !is_ret {
            let n = d.offset + d.size;
            if off_set.contains(&n) {
                edges.push((d.offset, n));
            }
        }
    }
    // block boundary after every terminator: the next sequential
    // instruction begins a new block (reachable only by a jump).
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
    (sv, edges)
}

pub fn run(collect_dir: &Path) -> Result<Stats, String> {
    let mut stats = Stats::default();
    let index_p = collect_dir.join("index.jsonl");
    let index = match fs::read_to_string(&index_p) {
        Ok(s) => s,
        Err(_) => return Ok(stats),
    };
    let raw_dir = collect_dir.to_path_buf();

    // pass 1: index lines for kind bytecode-trace -> (ts, path, off, len)
    let mut recs: Vec<(u64, String, u64, u64)> = Vec::new();
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
            path.to_string(),
            v.get("o").and_then(|x| x.as_u64()).unwrap_or(0),
            v.get("len").and_then(|x| x.as_u64()).unwrap_or(0),
        ));
    }
    stats.records = recs.len() as u64;
    if recs.is_empty() {
        return Ok(stats);
    }

    // pass 2: decode. meta first (single record), then defs, then stream.
    let mut meta: Vec<OpMeta> = Vec::new();
    let mut funcs: HashMap<u32, FuncDef> = HashMap::new();
    let mut executed: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut exec_count: HashMap<u32, u64> = HashMap::new();
    let mut first_ts: HashMap<u32, u64> = HashMap::new();
    // per-func value streams: (offset, ts) -> acc payload summary
    let mut value_streams: HashMap<u32, Vec<ValuePoint>> = HashMap::new();

    // read payloads grouped by file to avoid re-reading part files
    let mut by_file: BTreeMap<&str, Vec<&(u64, String, u64, u64)>> = BTreeMap::new();
    for r in &recs {
        by_file.entry(r.1.as_str()).or_default().push(r);
    }

    for (fname, group) in by_file {
        let blob = match fs::read(raw_dir.join(fname)) {
            Ok(b) => b,
            Err(_) => continue,
        };
        for (ts, _p, off, len) in group {
            let start = *off as usize;
            let end = start + *len as usize;
            if end > blob.len() {
                continue;
            }
            let rec = &blob[start..end];
            if rec.is_empty() {
                continue;
            }
            if rec[0] == OP_META {
                if let Some(m) = parse_meta(rec) {
                    meta = m;
                }
                continue;
            }
            if rec[0] == OP_FUNC_DEF {
                if let Some(d) = parse_func_def(rec, *ts) {
                    funcs.entry(d.func_id).or_insert(d);
                    stats.funcs = funcs.len() as u64;
                }
                continue;
            }
            if let Some(ir) = parse_instr(rec, *ts) {
                stats.instructions += 1;
                executed.entry(ir.func_id).or_default().insert(ir.offset);
                *exec_count.entry(ir.func_id).or_insert(0) += 1;
                first_ts.entry(ir.func_id).or_insert(*ts);
                if !ir.payloads.is_empty() {
                    let vs = value_streams.entry(ir.func_id).or_default();
                    if vs.len() < 100_000 {
                        vs.push(ValuePoint {
                            ts: ir.ts,
                            offset: ir.offset,
                            opcode: ir.opcode,
                            acc: ir.acc,
                            payload: ir.payloads.last().cloned().unwrap_or_default(),
                        });
                    }
                }
            }
        }
    }
    if meta.is_empty() {
        return Err("bctrace: no meta record (0033 patch not active?)".into());
    }

    // pass 3: per-function CFG + dead/live by fact.
    let out_dir = collect_dir.join("filtered").join("bctrace");
    let _ = fs::create_dir_all(&out_dir);
    let mut func_reports = Vec::new();

    for (fid, def) in &funcs {
        let instrs = match decode_func(&def.bytecode, &meta) {
            Some(v) => v,
            None => continue,
        };
        let (block_starts, cfg_edges) = build_cfg(&instrs, &meta, &def.cp);
        let ex = executed.get(fid);
        let mut live_blocks = 0usize;
        let mut dead_blocks = 0usize;
        let mut dead_ranges: Vec<(usize, usize)> = Vec::new();
        let mut live_ranges: Vec<(usize, usize)> = Vec::new();
        let n_blocks = block_starts.len();
        for (bi, &bs) in block_starts.iter().enumerate() {
            let be = if bi + 1 < n_blocks {
                block_starts[bi + 1]
            } else {
                def.bytecode.len()
            };
            let hit = match ex {
                Some(s) => instrs.iter().any(|d| {
                    d.offset >= bs && d.offset < be && s.contains(&(d.offset as u32))
                }),
                None => false,
            };
            if hit {
                live_blocks += 1;
                live_ranges.push((bs, be));
            } else {
                dead_blocks += 1;
                dead_ranges.push((bs, be));
            }
        }
        stats.dead_blocks += dead_blocks as u64;
        stats.live_blocks += live_blocks as u64;
        for (a, b) in &dead_ranges {
            stats.dead_bytes += (b - a) as u64;
        }
        for (a, b) in &live_ranges {
            stats.live_bytes += (b - a) as u64;
        }

        // executed instruction disassembly with resolved operands
        let mut disasm: Vec<serde_json::Value> = Vec::new();
        if let Some(s) = ex {
            for d in &instrs {
                if !s.contains(&(d.offset as u32)) {
                    continue;
                }
                let m = &meta[d.opcode as usize];
                let mut entry = json!({
                    "off": d.offset,
                    "op": m.name,
                });
                let mut resolved: Vec<serde_json::Value> = Vec::new();
                for (k, &v) in d.ops.iter().enumerate() {
                    let otype = m.scales[0].ops.get(k).map(|o| o.0).unwrap_or(0);
                    // ConstantPoolIndex = 8
                    if otype == 8 && (v as usize) < def.cp.len() {
                        resolved.push(match &def.cp[v as usize] {
                            CpEntry::Str(b) => json!(String::from_utf8_lossy(b)),
                            CpEntry::F64(f) => json!(f),
                            CpEntry::Raw(w) => json!(w),
                        });
                    } else {
                        resolved.push(json!(v));
                    }
                }
                entry["args"] = json!(resolved);
                disasm.push(entry);
                if disasm.len() >= 4096 {
                    break;
                }
            }
        }

        let edge_list: Vec<(usize, usize)> = cfg_edges.iter().copied().take(4096).collect();
        let report = json!({
            "func_id": fid,
            "cfg_edges": edge_list,
            "name": def.name,
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
            "executed": disasm,
        });
        let rep_bytes = serde_json::to_vec_pretty(&report).unwrap_or_default();
        func_reports.push(report);

        let fp = out_dir.join(format!("{:08x}.json", fid));
        if let Ok(mut f) = fs::File::create(&fp) {
            let _ = f.write_all(&rep_bytes);
        }
    }

    // value streams: raw payloads at instructions that produced values.
    // This is the token assembly trail - strings/numbers as they were
    // built, in execution order.
    let mut vs_dir = out_dir.join("values");
    let _ = fs::create_dir_all(&vs_dir);
    vs_dir = out_dir.join("values");
    for (fid, pts) in &value_streams {
        let fp = vs_dir.join(format!("{:08x}.jsonl", fid));
        if let Ok(mut f) = fs::File::create(&fp) {
            for p in pts.iter().take(20_000) {
                let kind = if p.payload.len() == 8 && is_f64_plausible(&p.payload) {
                    "f64"
                } else if p.payload.len() == 4 {
                    "smi"
                } else {
                    "str"
                };
                let val = match kind {
                    "f64" => json!(f64::from_bits(rd_u64(&p.payload, 0))),
                    "smi" => json!(rd_i32(&p.payload, 0)),
                    _ => json!(String::from_utf8_lossy(&p.payload)),
                };
                let line = json!({
                    "ts": p.ts, "off": p.offset, "op": p.opcode,
                    "acc": p.acc, "kind": kind, "v": val,
                });
                let _ = writeln!(f, "{}", line);
            }
        }
    }

    let summary = json!({
        "records": stats.records,
        "instructions": stats.instructions,
        "funcs": stats.funcs,
        "dead_blocks": stats.dead_blocks,
        "live_blocks": stats.live_blocks,
        "dead_bytes": stats.dead_bytes,
        "live_bytes": stats.live_bytes,
        "funcs_reported": func_reports.len(),
        "rule": "dead = basic block present in the decoded bytecode whose offsets NEVER appear in the executed stream. Fact from raw execution, no heuristics, no time windows.",
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

struct ValuePoint {
    ts: u64,
    offset: u32,
    opcode: u8,
    acc: u64,
    payload: Vec<u8>,
}

fn is_f64_plausible(b: &[u8]) -> bool {
    if b.len() != 8 {
        return false;
    }
    let f = f64::from_bits(rd_u64(b, 0));
    f.is_finite() && f.abs() < 1e15
}

#[cfg(test)]
mod tests {
    use super::*;

    // synthetic meta for a mini instruction set matching real opcode
    // numbers from bytecodes.h at the pinned rev:
    //   LdaZero=12 (0 ops, size 1)
    //   LdaConstant=19 (1 op: ConstantPoolIndex, scalable unsigned byte)
    //   Star0=209 (0 ops, size 1)
    //   Jump=148 (1 op: Imm scalable signed)
    //   JumpIfTrue=163 (1 op: Imm, reads acc)
    //   Return=181 (0 ops)
    fn mini_meta() -> Vec<u8> {
        let mut v: Vec<u8> = vec![OP_META, 0, 0, 0];
        v.extend_from_slice(&211u16.to_le_bytes());
        let put = |v: &mut Vec<u8>, name: &str, nops: u8, flags: u8,
                       otype: u8, size_single: u8, size_double: u8, size_quad: u8| {
            v.extend_from_slice(name.as_bytes());
            v.push(0);
            v.push(nops);
            v.push(flags);
            for sz in [size_single, size_double, size_quad] {
                v.push(sz);
                for _ in 0..nops {
                    v.push(otype);
                    v.push(1); // operand offset = 1 (right after opcode)
                }
            }
        };
        // opcodes 0..210: fill dummies (size 1, no ops) except the ones we use
        for i in 0..211u16 {
            // flags mirror the real engine: bit0 jump, bit1 returns,
            // bits3-4 jump subtype (1=imm forward), bit5 conditional.
            match i {
                0 => put(&mut v, "Wide", 0, 0, 0, 1, 1, 1),
                12 => put(&mut v, "LdaZero", 0, 0, 0, 1, 1, 1),
                19 => put(&mut v, "LdaConstant", 1, 0, 8, 2, 3, 5),
                148 => put(&mut v, "Jump", 1, 1 | (1 << 3), 12, 2, 3, 5),
                163 => put(
                    &mut v,
                    "JumpIfTrue",
                    1,
                    1 | (1 << 3) | (1 << 5),
                    12,
                    2,
                    3,
                    5,
                ),
                181 => put(&mut v, "Return", 0, 2, 0, 1, 1, 1),
                209 => put(&mut v, "Star0", 0, 0, 0, 1, 1, 1),
                _ => put(&mut v, &format!("op{i}"), 0, 0, 0, 1, 1, 1),
            }
        }
        v
    }

    fn hdr(opcode: u8, offset: u32, func_id: u32, n_payload: u8) -> Vec<u8> {
        let mut h = vec![0u8; HDR_LEN];
        h[0] = opcode;
        h[1] = 1; // scale single
        h[2] = n_payload;
        h[4..8].copy_from_slice(&offset.to_le_bytes());
        h[8..12].copy_from_slice(&func_id.to_le_bytes());
        h
    }

    fn func_def(func_id: u32, bc: &[u8], cp_strings: &[&str]) -> Vec<u8> {
        let mut cpb: Vec<u8> = Vec::new();
        for s in cp_strings {
            cpb.push(1);
            cpb.extend_from_slice(&(s.len() as u16).to_le_bytes());
            cpb.extend_from_slice(s.as_bytes());
        }
        let mut v = vec![0u8; HDR_LEN];
        v[0] = OP_FUNC_DEF;
        v[3] = 1;
        v[4..8].copy_from_slice(&7u32.to_le_bytes()); // frame_size
        v[8..12].copy_from_slice(&func_id.to_le_bytes());
        v[12..16].copy_from_slice(&42u32.to_le_bytes()); // line
        v[16..24].copy_from_slice(&3u64.to_le_bytes()); // param_count
        v.extend_from_slice(&(bc.len() as u32).to_le_bytes());
        let name = b"test.js";
        v.extend_from_slice(&(name.len() as u32).to_le_bytes());
        v.extend_from_slice(&(cpb.len() as u32).to_le_bytes());
        v.extend_from_slice(bc);
        v.extend_from_slice(name);
        v.extend_from_slice(&cpb);
        v
    }

    fn write_run(dir: &Path, records: &[Vec<u8>]) {
        fs::create_dir_all(dir).unwrap();
        let part = dir.join("v8-bytecode-trace-000000.bin");
        let mut f = fs::File::create(&part).unwrap();
        let mut idx = String::new();
        let mut off = 0u64;
        for r in records {
            f.write_all(r).unwrap();
            idx.push_str(&format!(
                "{{\"ts\":{},\"l\":\"v8\",\"pid\":1,\"k\":\"bytecode-trace\",\"len\":{},\"h\":\"x\",\"p\":\"v8-bytecode-trace-000000.bin\",\"o\":{}}}\n",
                1_000_000u64 + off,
                r.len(),
                off
            ));
            off += r.len() as u64;
        }
        fs::write(dir.join("index.jsonl"), idx).unwrap();
    }

    #[test]
    fn dead_branch_detected_by_fact() {
        // bytecode: LdaZero; JumpIfTrue +2 (skip dead); LdaZero; Return;
        //           [dead] LdaConstant#0; Return
        // layout:
        //   0: LdaZero (1)
        //   1: JumpIfTrue imm=+3 -> target 1+2+3 = 6 (scale single: size 2)
        //   3: LdaZero (1)          <- live fallthrough
        //   4: Return (1)
        //   5: LdaConstant kImm8 0 (size 2) <- DEAD, never executed
        //   7: Return (1)
        let bc = vec![
            12, // LdaZero
            163, 3, // JumpIfTrue imm=+3 (next=3, target=6)... fix below
            12, // LdaZero
            181, // Return
            19, 0, // LdaConstant cp0
            181, // Return
        ];
        // JumpIfTrue at off 1, size 2, next = 3, imm +3 -> target 6? but 6 is
        // out of range (bc len 6). use imm +2 -> target 5 = LdaConstant.
        // We want the dead block to be the LdaConstant path, so the trace
        // must NOT execute offsets 5..6. imm=+2 target=5.
        let bc = {
            let mut b = bc.clone();
            b[2] = 2;
            b
        };
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("collect");
        let mut recs: Vec<Vec<u8>> = vec![mini_meta(), func_def(7, &bc, &["secret"])];
        // executed: 0, 1, 3, 4 only (branch not taken)
        for off in [0u32, 1, 3, 4] {
            let op = bc[off as usize];
            recs.push(hdr(op, off, 7, 0));
        }
        write_run(&cd, &recs);
        let st = run(&cd).unwrap();
        assert_eq!(st.instructions, 4);
        assert_eq!(st.funcs, 1);
        // blocks: starts {0, 3, 5} -> live {0..3: contains 0,1}, {3..5: 3,4}, dead {5..6}
        assert_eq!(st.dead_blocks, 1, "dead={}", st.dead_blocks);
        assert_eq!(st.live_blocks, 2);
        assert_eq!(st.dead_bytes, 3);
        let rep: serde_json::Value = serde_json::from_slice(
            &fs::read(cd.join("filtered/bctrace.json")).unwrap(),
        )
        .unwrap();
        let f0 = &rep["functions"][0];
        assert_eq!(f0["dead_ranges"].as_array().unwrap()[0][0], 5);
        assert_eq!(f0["name"], "test.js");
        assert_eq!(f0["line"], 42);
    }

    #[test]
    fn operand_resolution_uses_constant_pool() {
        // 0: LdaConstant cp1 ("tok3n") ; 2: Return
        let bc = vec![19, 1, 181];
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("collect");
        let mut recs = vec![mini_meta(), func_def(9, &bc, &["a", "tok3n"])];
        // LdaConstant with acc payload "tok3n" (string value)
        let mut h = hdr(19, 0, 9, 1);
        h.extend_from_slice(&5u16.to_le_bytes());
        h.extend_from_slice(b"tok3n");
        recs.push(h);
        recs.push(hdr(181, 2, 9, 0));
        write_run(&cd, &recs);
        let st = run(&cd).unwrap();
        assert_eq!(st.instructions, 2);
        assert_eq!(st.dead_blocks, 0);
        let rep: serde_json::Value = serde_json::from_slice(
            &fs::read(cd.join("filtered/bctrace.json")).unwrap(),
        )
        .unwrap();
        let ex = &rep["functions"][0]["executed"][0];
        assert_eq!(ex["op"], "LdaConstant");
        assert_eq!(ex["args"][0], "tok3n");
        // value stream captured the string payload
        let vs = fs::read_to_string(
            cd.join("filtered/bctrace/values/00000009.jsonl"),
        )
        .unwrap();
        assert!(vs.contains("tok3n"), "vs={vs}");
    }

    #[test]
    fn wide_prefix_decodes_with_true_scale() {
        // Wide(0) LdaConstant with 2-byte cp index at double scale.
        // meta mini: LdaConstant double size 3 (op + 2-byte operand).
        // 0: Wide, 1: LdaConstant, 2..4: cp index u16 = 1
        let bc = vec![0, 19, 1, 0, 181];
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("collect");
        let mut recs = vec![mini_meta(), func_def(11, &bc, &["x", "wide!"])];
        // executed stream: offsets 0 (the wide instr as a unit) and 4
        let mut h = hdr(19, 1, 11, 1);
        h.extend_from_slice(&5u16.to_le_bytes());
        h.extend_from_slice(b"wide!");
        recs.push(h);
        recs.push(hdr(181, 4, 11, 0));
        write_run(&cd, &recs);
        let st = run(&cd).unwrap();
        assert_eq!(st.instructions, 2);
        let rep: serde_json::Value = serde_json::from_slice(
            &fs::read(cd.join("filtered/bctrace.json")).unwrap(),
        )
        .unwrap();
        let ex = &rep["functions"][0]["executed"][0];
        assert_eq!(ex["op"], "LdaConstant");
        assert_eq!(ex["args"][0], "wide!");
        assert_eq!(st.dead_blocks, 0);
    }
}
