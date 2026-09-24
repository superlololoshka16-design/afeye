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
    pub flags: u8,   // bit0 jump, bit1 returns, bit2 calls
    pub acc_use: u8, // ImplicitRegisterUse bits: 1 read, 2 write, 4 clobber
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
    pub pid: u64,
    pub func_id: u32,
    pub offset: u32,
    pub opcode: u8,
    pub scale: u8,
    pub flags: u8, // bit1 truncated, bit2 acc-payload present (last block)
    pub iso: u32,  // isolate tag (hdr.line on instruction records)
    pub acc: u64,
    pub regs: Vec<u64>,
    // tagged payload blocks: (tag, bytes). Tags: 0=acc string,
    // 1=acc f64 bits, 2=acc smi, 3..=250 = string of regs[tag-3].
    pub payloads: Vec<(u8, Vec<u8>)>,
}

// typed value from a payload block. Tag-driven, zero length-guessing.
pub enum Pv {
    Str(Vec<u8>),
    F64(f64),
    Smi(i32),
}

fn pv_json(pv: &Pv) -> serde_json::Value {
    match pv {
        Pv::Str(b) => json!(String::from_utf8_lossy(b)),
        Pv::F64(f) => json!(f),
        Pv::Smi(i) => json!(i),
    }
}

fn decode_tagged(tag: u8, b: &[u8]) -> Option<Pv> {
    match tag {
        0 => Some(Pv::Str(b.to_vec())),
        1 if b.len() == 8 => Some(Pv::F64(f64::from_bits(rd_u64(b, 0)))),
        2 if b.len() == 4 => Some(Pv::Smi(rd_i32(b, 0))),
        _ => Some(Pv::Str(b.to_vec())), // register string blocks (tag >= 3)
    }
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
fn parse_meta(p: &[u8]) -> Option<(Vec<OpMeta>, Vec<String>, i32)> {
    if p.len() < 10 || p[0] != OP_META {
        return None;
    }
    let mut i = 4usize;
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
        if i + 2 > p.len() {
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
            scales: [
                scales.remove(0),
                scales.remove(0),
                scales.remove(0),
            ],
        });
    }
    // runtime function name table: u16 count then NUL-terminated names.
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
    let flags = rec[3];
    let offset = rd_u32(rec, 4);
    let func_id = rd_u32(rec, 8);
    let iso = rd_u32(rec, 12);
    let acc = rd_u64(rec, 16);
    // flags bits 5-7 = register count; keep ALL slots including zero
    // words (Smi 0 tags to word 0 - skipping would shift tag 3+k
    // attribution).
    let n_regs = ((flags >> 5) & 7) as usize;
    let mut regs = Vec::new();
    for r in 0..n_regs.min(6) {
        regs.push(rd_u64(rec, 24 + r * 8));
    }
    let mut i = HDR_LEN;
    let mut payloads = Vec::new();
    for _ in 0..n_payload {
        if i + 3 > rec.len() {
            break;
        }
        let tag = rec[i];
        let l = rd_u16(rec, i + 1) as usize;
        i += 3;
        if i + l > rec.len() {
            break;
        }
        payloads.push((tag, rec[i..i + l].to_vec()));
        i += l;
    }
    Some(InstrRec {
        ts,
        pid: 0,
        func_id,
        offset,
        opcode,
        scale,
        flags,
        iso,
        acc,
        regs,
        payloads,
    })
}

struct DecodedInstr {
    offset: usize,
    opcode: u8,
    size: usize,
    ops: Vec<i64>,     // decoded operand values (signed where relevant)
    otypes: Vec<u8>,   // engine operand types (ConstantPoolIndex=8, Reg=15..)
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
        let mut otypes = Vec::new();
        for k in 0..rm.n_ops as usize {
            let (otype, ooff) = sm.ops[k];
            otypes.push(otype);
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
            otypes,
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

// accumulator value of a record: the payload block with tag 0/1/2,
// decoded BY TAG. Register string blocks (tag>=3) are separate.
fn acc_value(r: &InstrRec) -> Option<serde_json::Value> {
    if r.flags & 4 == 0 {
        return None;
    }
    r.payloads
        .iter()
        .find(|(t, _)| *t <= 2)
        .and_then(|(t, b)| decode_tagged(*t, b))
        .map(|pv| pv_json(&pv))
}

// register string values: tag 3+k -> regs[k] slot.
fn reg_values(r: &InstrRec) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (t, b) in &r.payloads {
        if *t >= 3 {
            let k = (*t - 3) as usize;
            out.push((k, String::from_utf8_lossy(b).into_owned()));
        }
    }
    out
}

// resolve one operand to a JSON value using engine tables:
//   type 8  ConstantPoolIndex -> pool entry (string literal, number)
//   type 4  RuntimeId         -> runtime function name
//   types 15..=21 registers   -> "r{idx}" / "a{idx}" names
//   everything else           -> raw number
fn resolve_operand(
    otype: u8,
    v: i64,
    cp: &[CpEntry],
    rt: &[String],
    reg_start: i32,
) -> serde_json::Value {
    match otype {
        8 => match cp.get(v as usize) {
            Some(CpEntry::Str(b)) => json!(String::from_utf8_lossy(b)),
            Some(CpEntry::F64(f)) => json!(f),
            Some(CpEntry::Raw(w)) => json!(w),
            None => json!(v),
        },
        4 => match rt.get(v as usize) {
            Some(n) if !n.is_empty() => json!(n),
            _ => json!(v),
        },
        15..=21 => {
            let idx = reg_start - v as i32;
            if idx >= 0 {
                json!(format!("r{idx}"))
            } else {
                json!(format!("a{}", -idx))
            }
        }
        _ => json!(v),
    }
}

pub fn run(collect_dir: &Path) -> Result<Stats, String> {
    let mut stats = Stats::default();
    let index_p = collect_dir.join("index.jsonl");
    let index = match fs::read_to_string(&index_p) {
        Ok(s) => s,
        Err(_) => return Ok(stats),
    };
    let raw_dir = collect_dir.to_path_buf();

    // pass 1: index lines for kind bytecode-trace -> (ts, pid, path, off, len)
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

    // pass 2: decode. meta first (single record), then defs, then stream.
    let mut meta: Vec<OpMeta> = Vec::new();
    let mut rt_names: Vec<String> = Vec::new();
    let mut reg_start: i32 = 0;
    let mut funcs: HashMap<u32, FuncDef> = HashMap::new();
    // executed instruction stream in ts order: (pid, func_id, offset, acc,
    // payloads). acc of record N+1 is the RESULT of record N when N's
    // opcode writes the accumulator (engine ImplicitRegisterUse fact).
    let mut stream: Vec<InstrRec> = Vec::new();
    let mut executed: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut exec_count: HashMap<u32, u64> = HashMap::new();
    let mut first_ts: HashMap<u32, u64> = HashMap::new();

    // read payloads grouped by file to avoid re-reading part files
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
            if rec.is_empty() {
                continue;
            }
            if rec[0] == OP_META {
                if let Some((m, rt, rs)) = parse_meta(rec) {
                    meta = m;
                    rt_names = rt;
                    reg_start = rs;
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
            if let Some(mut ir) = parse_instr(rec, *ts) {
                ir.pid = *pid;
                stats.instructions += 1;
                executed.entry(ir.func_id).or_default().insert(ir.offset);
                *exec_count.entry(ir.func_id).or_insert(0) += 1;
                first_ts.entry(ir.func_id).or_insert(*ts);
                stream.push(ir.clone());
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


    // ---- semantic pass: the literal execution story ----
    // stream is in ts order (index.jsonl order). Result propagation: when
    // an opcode WRITES the accumulator (engine acc_use bit1), its result is
    // the acc word/payload of the NEXT record with the same (pid, isolate)
    // - exact dataflow, no windowing, no guessing.
    stream.sort_by_key(|r| r.ts);
    let dec_by_func: HashMap<u32, Vec<DecodedInstr>> = funcs
        .iter()
        .filter_map(|(fid, def)| {
            decode_func(&def.bytecode, &meta).map(|d| (*fid, d))
        })
        .collect();
    // per (pid, iso) next-record index for result lookup
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

    let sem_dir = out_dir.join("sem");
    let _ = fs::create_dir_all(&sem_dir);
    let mut api_calls: BTreeMap<String, u64> = BTreeMap::new();
    let mut api_values: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
    let mut sem_files: HashMap<u32, fs::File> = HashMap::new();

    for (n, r) in stream.iter().enumerate() {
        let m = match meta.get(r.opcode as usize) {
            Some(m) => m,
            None => continue,
        };
        let def = match funcs.get(&r.func_id) {
            Some(d) => d,
            None => continue,
        };
        let decoded = dec_by_func
            .get(&r.func_id)
            .and_then(|v| v.iter().find(|d| d.offset as u32 == r.offset));

        // args: resolved operands from the decoded instruction
        let args: Vec<serde_json::Value> = match decoded {
            Some(d) => d
                .ops
                .iter()
                .zip(d.otypes.iter())
                .map(|(&v, &t)| resolve_operand(t, v, &def.cp, &rt_names, reg_start))
                .collect(),
            None => Vec::new(),
        };

        // accumulator entering this instruction (tag-decoded, no length
        // guessing).
        let acc_in = acc_value(r);
        // result = acc of the next same-(pid,iso) record when this opcode
        // writes the accumulator (engine acc_use fact).
        let result = if m.acc_use & 2 != 0 {
            result_at[n].and_then(|j| stream.get(j)).and_then(acc_value)
        } else {
            None
        };
        let rvals = reg_values(r);

        // what it pulls: globals, property names, methods, runtime fns,
        // constant strings - counted with resolved names, values sampled.
        let key: Option<String> = match m.name.as_str() {
            "LdaGlobal" | "LdaGlobalInsideTypeof" | "LdaLookupGlobalSlot"
            | "StaGlobal" | "LdaContextSlot" | "StaContextSlot" => {
                args.first().and_then(|a| a.as_str()).map(|n| format!("global {n}"))
            }
            "GetNamedProperty" | "GetNamedPropertyFromSuper" | "SetNamedProperty"
            | "DefineNamedOwnProperty" | "AddNamedProperty" => {
                args.first().and_then(|a| a.as_str()).map(|n| format!("prop {n}"))
            }
            "CallProperty" | "CallProperty0" | "CallProperty1" | "CallProperty2"
            | "CallUndefinedReceiver0" | "CallUndefinedReceiver1"
            | "CallUndefinedReceiver2" | "CallWithSpread" => {
                args.first().and_then(|a| a.as_str()).map(|n| format!("call {n}"))
            }
            "CallRuntime" | "CallRuntimeForPair" => {
                args.first().and_then(|a| a.as_str()).map(|n| format!("runtime {n}"))
            }
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
        if !args.is_empty() {
            line["args"] = json!(args);
        }
        if let Some(a) = acc_in {
            line["acc"] = a;
        }
        if let Some(res) = result {
            line["res"] = res;
        }
        if !rvals.is_empty() {
            line["regs"] = json!(rvals
                .iter()
                .map(|(k, v)| json!({ "reg": *k, "v": v }))
                .collect::<Vec<_>>());
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

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic meta mirroring the REAL wire format from AfeyeEmitMeta:
    //   [0xfe,0,0,0][u16 n_bc][i32 reg_start]
    //   per bytecode: name\0 u8 n_ops u8 flags u8 acc_use
    //                 3 scales x (u8 size, n_ops x (u8 type, u8 offset))
    //   [u16 n_rt][rt names NUL-terminated]
    // Real opcode numbers at the pinned rev: Wide=0, LdaZero=12,
    // LdaConstant=19, LdaGlobal=35, GetNamedProperty=168-ish (not needed),
    // Jump=148, JumpIfTrue=163, Return=181, Star0=209.
    // Real operand types: ConstantPoolIndex=8, UImm=12, Imm=14, Reg=15.
    // Real ImplicitRegisterUse bits: read=1, write=2, clobber=4.
    const RT_NAMES: &[&str] = &["", "CreateDataProperty"];

    fn mini_meta() -> Vec<u8> {
        let mut v: Vec<u8> = vec![OP_META, 0, 0, 0];
        v.extend_from_slice(&211u16.to_le_bytes());
        v.extend_from_slice(&(-1i32).to_le_bytes()); // reg_start: r0 = -1-op
        let put = |v: &mut Vec<u8>,
                   name: &str,
                   nops: u8,
                   flags: u8,
                   acc_use: u8,
                   otype: u8,
                   sizes: [u8; 3]| {
            v.extend_from_slice(name.as_bytes());
            v.push(0);
            v.push(nops);
            v.push(flags);
            v.push(acc_use);
            for sz in sizes {
                v.push(sz);
                for _ in 0..nops {
                    v.push(otype);
                    v.push(1); // operand offset = 1
                }
            }
        };
        for i in 0..211u16 {
            match i {
                0 => put(&mut v, "Wide", 0, 0, 0, 0, [1, 1, 1]),
                // LdaZero: writes acc (2), no operands
                12 => put(&mut v, "LdaZero", 0, 0, 2, 0, [1, 1, 1]),
                // LdaConstant: writes acc (2), cp-index operand (type 8)
                19 => put(&mut v, "LdaConstant", 1, 0, 2, 8, [2, 3, 5]),
                // LdaGlobal: writes acc (2), cp-index operand (type 8)
                35 => put(&mut v, "LdaGlobal", 1, 0, 2, 8, [3, 4, 6]),
                // Jump: unconditional (1), imm-forward subtype (1<<3), UImm
                148 => put(&mut v, "Jump", 1, 1 | (1 << 3), 0, 12, [2, 3, 5]),
                // JumpIfTrue: jump+cond (1|(1<<5)), imm-forward (1<<3), reads acc
                163 => put(
                    &mut v,
                    "JumpIfTrue",
                    1,
                    1 | (1 << 3) | (1 << 5),
                    1,
                    12,
                    [2, 3, 5],
                ),
                // Return: reads acc (1), terminator (2)
                181 => put(&mut v, "Return", 0, 2, 1, 0, [1, 1, 1]),
                // Star0: reads acc, writes short-star reg (1|8)
                209 => put(&mut v, "Star0", 0, 0, 1 | 8, 0, [1, 1, 1]),
                _ => put(&mut v, &format!("op{i}"), 0, 0, 0, 0, [1, 1, 1]),
            }
        }
        // runtime name table
        v.extend_from_slice(&(RT_NAMES.len() as u16).to_le_bytes());
        for n in RT_NAMES {
            v.extend_from_slice(n.as_bytes());
            v.push(0);
        }
        v
    }

    // instruction record: hdr(72) + payload blocks [u16 len][bytes]
    fn hdr(opcode: u8, offset: u32, func_id: u32, n_payload: u8, flags: u8) -> Vec<u8> {
        let mut h = vec![0u8; HDR_LEN];
        h[0] = opcode;
        h[1] = 1; // scale single
        h[2] = n_payload;
        h[3] = flags;
        h[4..8].copy_from_slice(&offset.to_le_bytes());
        h[8..12].copy_from_slice(&func_id.to_le_bytes());
        // h[12..16] = iso tag; tests keep it 0 - same isolate for all recs
        h
    }

    // append an acc-string payload block [tag=0][u16 len][bytes] and set
    // flags bit2 (acc payload present) - matches the C++ wire format.
    fn with_str_payload(mut rec: Vec<u8>, s: &str) -> Vec<u8> {
        rec.push(0); // tag 0 = acc string
        rec.extend_from_slice(&(s.len() as u16).to_le_bytes());
        rec.extend_from_slice(s.as_bytes());
        rec[2] += 1; // n_payload
        rec[3] |= 4; // acc payload present
        rec
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
        v[12..16].copy_from_slice(&42u32.to_le_bytes()); // start line
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
        let mut ts = 1_000_000u64;
        for r in records {
            f.write_all(r).unwrap();
            idx.push_str(&format!(
                "{{\"ts\":{},\"l\":\"v8\",\"pid\":1,\"k\":\"bytecode-trace\",\"len\":{},\"h\":\"x\",\"p\":\"v8-bytecode-trace-000000.bin\",\"o\":{}}}\n",
                ts, r.len(), off
            ));
            off += r.len() as u64;
            ts += 1000; // strictly increasing ts per record
        }
        fs::write(dir.join("index.jsonl"), idx).unwrap();
    }

    fn summary(cd: &Path) -> serde_json::Value {
        serde_json::from_slice(&fs::read(cd.join("filtered/bctrace.json")).unwrap()).unwrap()
    }

    #[test]
    fn dead_branch_detected_by_fact() {
        //   0: LdaZero            (1)
        //   1: JumpIfTrue imm=+4  (2) -> target 1+4 = 5  [conditional: falls to 3]
        //   3: LdaZero            (1)
        //   4: Return             (1)
        //   5: LdaConstant cp0    (2) <- DEAD when branch not taken
        //   7: Return             (1)
        let bc = vec![12, 163, 4, 12, 181, 19, 0, 181];
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("collect");
        let mut recs = vec![mini_meta(), func_def(7, &bc, &["secret"])];
        // executed: 0, 1, 3, 4 - branch NOT taken, offsets 5..7 never run
        for off in [0u32, 1, 3, 4] {
            recs.push(hdr(bc[off as usize], off, 7, 0, 0));
        }
        write_run(&cd, &recs);
        let st = run(&cd).unwrap();
        assert_eq!(st.instructions, 4);
        assert_eq!(st.funcs, 1);
        assert_eq!(st.dead_blocks, 1, "dead={}", st.dead_blocks);
        assert_eq!(st.live_blocks, 2);
        assert_eq!(st.dead_bytes, 3); // offsets 5,6,7 -> [5,8)
        let rep = summary(&cd);
        let f0 = &rep["functions"][0];
        assert_eq!(f0["dead_ranges"].as_array().unwrap()[0][0], 5);
        assert_eq!(f0["name"], "test.js");
    }

    #[test]
    fn semantic_stream_shows_what_is_pulled_and_values() {
        //   0: LdaGlobal cp0 ("navigator")      -> result "Mozilla/5.0"
        //   3: LdaConstant cp1 ("userAgent")    -> result "Mozilla/5.0 (X11)"
        //   5: Return
        // LdaGlobal: opcode 35, 1 cp operand, size 3 single scale.
        let bc = vec![35, 0, 0, 19, 1, 181];
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("collect");
        let mut recs = vec![mini_meta(), func_def(9, &bc, &["navigator", "userAgent"])];
        // record 0: LdaGlobal, acc-in empty, result arrives on NEXT record
        recs.push(hdr(35, 0, 9, 0, 0));
        // record 1: LdaConstant with acc payload "Mozilla/5.0" - this is the
        // RESULT of record 0 (LdaGlobal writes acc), and its own result
        // arrives on record 2.
        recs.push(with_str_payload(hdr(19, 3, 9, 0, 0), "Mozilla/5.0"));
        // record 2: Return with acc payload "Mozilla/5.0 (X11)" = result of
        // the LdaConstant.
        recs.push(with_str_payload(hdr(181, 5, 9, 0, 0), "Mozilla/5.0 (X11)"));
        write_run(&cd, &recs);
        let st = run(&cd).unwrap();
        assert_eq!(st.instructions, 3);

        // per-function semantic stream
        let sem = fs::read_to_string(cd.join("filtered/bctrace/sem/00000009.jsonl")).unwrap();
        let lines: Vec<serde_json::Value> = sem
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        // LdaGlobal: arg resolved from cp to "navigator", result = next acc
        assert_eq!(lines[0]["op"], "LdaGlobal");
        assert_eq!(lines[0]["args"][0], "navigator");
        assert_eq!(lines[0]["res"], "Mozilla/5.0");
        // LdaConstant: arg "userAgent", result the longer UA string
        assert_eq!(lines[1]["op"], "LdaConstant");
        assert_eq!(lines[1]["args"][0], "userAgent");
        assert_eq!(lines[1]["res"], "Mozilla/5.0 (X11)");
        // Return reads acc, doesn't write -> no "res"
        assert_eq!(lines[2]["op"], "Return");
        assert!(lines[2].get("res").is_none());

        // run-level api_calls summary: what it pulled, with values
        let rep = summary(&cd);
        let api = rep["api_calls"].as_array().unwrap();
        let g = api.iter().find(|e| e["what"] == "global navigator").unwrap();
        assert_eq!(g["times"], 1);
        assert_eq!(g["values"][0], "Mozilla/5.0");
    }

    #[test]
    fn reg_payload_attribution_survives_zero_words() {
        // Star-like instruction with two input registers: r0 = Smi 0
        // (tagged word 0 - the slot MUST be kept), r1 = string "tok".
        // Payload blocks: tag 4 (= regs[1]) string, tag 0 acc smi 7.
        // Wire: hdr flags n_regs=2 (bits 5-7), regs[0]=0, regs[1]=word,
        // then blocks [4][len]["tok"], [0][4][7i32].
        let bc = vec![209, 181]; // Star0 ; Return
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("collect");
        let mut recs = vec![mini_meta(), func_def(13, &bc, &[])];
        let mut h = hdr(209, 0, 13, 2, 0);
        h[3] |= 4 | (2 << 5); // acc payload + n_regs=2
        h[24..32].copy_from_slice(&0u64.to_le_bytes()); // r0 = Smi 0 word
        h[32..40].copy_from_slice(&0x1234u64.to_le_bytes()); // r1 word
        // reg block: tag 4 -> regs[1]
        h.push(4);
        h.extend_from_slice(&3u16.to_le_bytes());
        h.extend_from_slice(b"tok");
        // acc block: tag 0 string
        h.push(0);
        h.extend_from_slice(&1u16.to_le_bytes());
        h.extend_from_slice(b"x");
        recs.push(h);
        recs.push(hdr(181, 1, 13, 0, 0));
        write_run(&cd, &recs);
        let st = run(&cd).unwrap();
        assert_eq!(st.instructions, 2);
        let sem = fs::read_to_string(cd.join("filtered/bctrace/sem/0000000d.jsonl")).unwrap();
        let l0: serde_json::Value = serde_json::from_str(sem.lines().next().unwrap()).unwrap();
        // the "tok" string must be attributed to register slot 1, not 0
        let regs = l0["regs"].as_array().unwrap();
        assert_eq!(regs.len(), 1);
        assert_eq!(regs[0]["reg"], 1);
        assert_eq!(regs[0]["v"], "tok");
        assert_eq!(l0["acc"], "x");
    }

    #[test]
    fn wide_prefix_decodes_with_true_scale() {
        // 0: Wide(0) 1: LdaConstant 2..4: cp index u16=1 (double scale,
        //    size 3 + prefix = 4)  4: Return
        let bc = vec![0, 19, 1, 0, 181];
        let dir = tempfile::tempdir().unwrap();
        let cd = dir.path().join("collect");
        let mut recs = vec![mini_meta(), func_def(11, &bc, &["x", "wide!"])];
        // executed offsets are post-prefix: 1 for the wide LdaConstant, 4 Return
        recs.push(with_str_payload(hdr(19, 1, 11, 0, 0), "wide!"));
        recs.push(hdr(181, 4, 11, 0, 0));
        write_run(&cd, &recs);
        let st = run(&cd).unwrap();
        assert_eq!(st.instructions, 2);
        assert_eq!(st.dead_blocks, 0);
        let sem = fs::read_to_string(cd.join("filtered/bctrace/sem/0000000b.jsonl")).unwrap();
        let l0: serde_json::Value = serde_json::from_str(sem.lines().next().unwrap()).unwrap();
        assert_eq!(l0["op"], "LdaConstant");
        assert_eq!(l0["args"][0], "wide!");
    }
}
