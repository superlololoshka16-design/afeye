use crate::events::{esc, J};
use bytes::BufMut;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

// Decoder for the 0033 wire format (v8/src/afeye/bcrec.h - single source
// of truth; tests/bcrec_roundtrip.rs proves this parser agrees with the
// C++ builders byte-for-byte without building chromium).
//
// Two streaming passes, no Vec<InstrRec> with all payloads in RAM:
//   PASS1 maps each part file once (mmap on unix, read fallback), keeps
//   metadata only (executed offsets per func, exec counts, func-defs,
//   meta) and streams every carried value straight into
//   filtered/valuebook.bin with in-RAM hash dedup. Memory: O(unique
//   offsets + funcs + dedup hashes).
//   PASS2 re-reads the same files in the same order and emits the
//   semantic stream: one deferred record per (pid,iso) so the result of
//   a write-acc opcode = acc of the NEXT record of the same partition -
//   engine dataflow, no windowing, no global sort (file order = emission
//   order).
//
// Payload values (Pv) are indices into the record slice - no per-record
// copies; scratch block vectors are reused across records.
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

// valuebook.bin src codes
const SRC_ACC: u8 = 0;
const SRC_REG: u8 = 1;
const SRC_CP: u8 = 2;
// op_id sentinel: not an instruction (cp literal or opcode out of meta range)
const OP_ID_NONE: u16 = 0xFFFF;
const MIN_VALUE_LEN: usize = 4;

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

// typed payload values - tag-driven decode. String variants carry
// (offset,len) INTO the record slice: zero copies, scratch-reusable.
#[derive(Clone, Copy, Debug)]
pub enum Pv {
    Str(u32, u32),
    Str16(u32, u32),
    F64(f64),
    Smi(i32),
    RegWord(u16, u64),
    RegStr(u16, u32, u32),
    RegStr16(u16, u32, u32),
    RegF64(u16, f64),
    RegSmi(u16, i32),
    Operand(u8, i64),
    Vclock(u64),
}

impl Pv {
    fn bytes<'r>(&self, rec: &'r [u8]) -> &'r [u8] {
        let (s, l) = match *self {
            Pv::Str(s, l) | Pv::Str16(s, l) => (s, l),
            Pv::RegStr(_, s, l) | Pv::RegStr16(_, s, l) => (s, l),
            _ => return &[],
        };
        &rec[s as usize..(s + l) as usize]
    }
}

// accumulator reference of one record (indices into the record slice)
#[derive(Clone, Copy, Debug)]
enum AccRef {
    Str(u32, u32),
    Str16(u32, u32),
    F64(f64),
    Smi(i32),
}

// materialized result value for the deferred-record flush (bytes owned by
// a per-partition reuse buffer)
enum ResVal<'r> {
    Str(&'r [u8]),
    Str16(&'r [u8]),
    F64(f64),
    Smi(i32),
}

#[derive(Clone, Debug, PartialEq)]
enum OwnedVal {
    Str(String),
    F64(f64),
    Smi(i32),
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
    /// distinct values written to filtered/valuebook.bin
    pub valuebook_entries: u64,
    /// total value bytes written to filtered/valuebook.bin
    pub valuebook_bytes: u64,
    /// executed records whose opcode disagrees with the static walk at
    /// the same offset (wide-prefix resync risk, made visible not fixed)
    pub offset_mismatch: u64,
    /// func_id -> script name (from func-def blobs)
    pub func_scripts: HashMap<u32, String>,
    /// v8 script_id -> script name (from func-def blobs)
    pub script_ids: HashMap<u32, String>,
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

// ---- part-file mapping ----

enum FileBuf {
    #[cfg(unix)]
    Mmap { ptr: *const u8, len: usize },
    Owned(Vec<u8>),
}

impl FileBuf {
    fn open(path: &Path) -> Option<FileBuf> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let f = File::open(path).ok()?;
            let len = f.metadata().ok()?.len() as usize;
            if len > 0 {
                let p = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        len,
                        libc::PROT_READ,
                        libc::MAP_PRIVATE,
                        f.as_raw_fd(),
                        0,
                    )
                };
                if p != libc::MAP_FAILED {
                    return Some(FileBuf::Mmap {
                        ptr: p as *const u8,
                        len,
                    });
                }
            }
            let mut f = f;
            let mut v = Vec::new();
            f.read_to_end(&mut v).ok()?;
            Some(FileBuf::Owned(v))
        }
        #[cfg(not(unix))]
        fs::read(path).ok().map(FileBuf::Owned)
    }

    fn bytes(&self) -> &[u8] {
        match self {
            #[cfg(unix)]
            FileBuf::Mmap { ptr, len } => unsafe { std::slice::from_raw_parts(*ptr, *len) },
            FileBuf::Owned(v) => v,
        }
    }
}

impl Drop for FileBuf {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let FileBuf::Mmap { ptr, len } = self {
            if *len > 0 {
                unsafe {
                    libc::munmap(*ptr as *mut libc::c_void, *len);
                }
            }
        }
    }
}

// ---- valuebook streaming writer ----

struct ValueBook {
    w: BufWriter<File>,
    r: File,
    pos: u64,
    flushed: u64,
    dedup: HashSet<u64>,
    offs: HashMap<u64, u64>, // hash64 -> file offset of a written entry
    scratch: Vec<u8>,
    entries: u64,
    bytes: u64,
}

fn value_hash(v: &[u8]) -> u64 {
    let head = &v[..v.len().min(64)];
    let h = blake3::hash(head);
    let x = u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap());
    x ^ (v.len() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

impl ValueBook {
    fn create(path: &Path) -> std::io::Result<ValueBook> {
        let w = BufWriter::with_capacity(1 << 20, File::create(path)?);
        let r = File::open(path)?;
        Ok(ValueBook {
            w,
            r,
            pos: 0,
            flushed: 0,
            dedup: HashSet::new(),
            offs: HashMap::new(),
            scratch: Vec::new(),
            entries: 0,
            bytes: 0,
        })
    }

    // Compare one stored entry with `v` byte-for-byte. The value starts at
    // off+15 (after the header), NOT at off+4 where the cursor lands after
    // reading the length - reading from there compares against the rest of
    // the header and the dedup never fires.
    fn entry_eq(&mut self, off: u64, v: &[u8]) -> bool {
        let val_off = off + 15;
        let val_end = val_off + v.len() as u64;
        if val_end > self.flushed {
            if self.w.flush().is_err() {
                return false;
            }
            self.flushed = self.pos;
            if val_end > self.flushed {
                return false;
            }
        }
        let mut hb = [0u8; 4];
        if self.r.seek(SeekFrom::Start(off)).is_err() || self.r.read_exact(&mut hb).is_err() {
            return false;
        }
        let len = u32::from_le_bytes(hb) as usize;
        if len != v.len() {
            return false;
        }
        self.scratch.resize(len, 0);
        if self.r.seek(SeekFrom::Start(val_off)).is_err() {
            return false;
        }
        if self.r.read_exact(&mut self.scratch).is_err() {
            return false;
        }
        self.scratch == v
    }

    // 15-byte header [u32 len][u32 func_id][u32 off][u16 op_id][u8 src]
    // + exactly len value bytes. Values > 4KiB are written whole.
    fn put(&mut self, v: &[u8], func_id: u32, off: u32, op_id: u16, src: u8) {
        if v.len() < MIN_VALUE_LEN {
            return;
        }
        let h = value_hash(v);
        if !self.dedup.insert(h) {
            // hash64 hit: verify bytes against the store - an exact
            // duplicate is skipped, a genuine 64-bit collision (different
            // value, same hash64) is still written.
            let fo = self.offs.get(&h).copied();
            if let Some(fo) = fo {
                if self.entry_eq(fo, v) {
                    return;
                }
            }
        }
        let len = v.len() as u32;
        let mut hdr = [0u8; 15];
        hdr[0..4].copy_from_slice(&len.to_le_bytes());
        hdr[4..8].copy_from_slice(&func_id.to_le_bytes());
        hdr[8..12].copy_from_slice(&off.to_le_bytes());
        hdr[12..14].copy_from_slice(&op_id.to_le_bytes());
        hdr[14] = src;
        if self.w.write_all(&hdr).is_err() || self.w.write_all(v).is_err() {
            return;
        }
        self.offs.insert(h, self.pos);
        self.pos += 15 + v.len() as u64;
        self.entries += 1;
        self.bytes += v.len() as u64;
    }

    fn finish(mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

// parse payload blocks: [u8 tag][u32 len][len bytes] until part end.
fn parse_blocks(rec: &[u8], out: &mut Vec<Pv>) {
    out.clear();
    let mut i = HDR_LEN;
    while i + 5 <= rec.len() {
        let tag = rec[i];
        let len = rd_u32(rec, i + 1) as usize;
        i += 5;
        if i + len > rec.len() {
            break;
        }
        let s = i as u32;
        let l = len as u32;
        i += len;
        let pv = match tag {
            TAG_ACC_STR => Pv::Str(s, l),
            TAG_ACC_STR16 => Pv::Str16(s, l),
            TAG_ACC_F64 if len == 8 => Pv::F64(f64::from_bits(rd_u64(rec, i - len))),
            TAG_ACC_SMI if len == 4 => Pv::Smi(rd_i32(rec, i - len)),
            TAG_REG if len == 10 => Pv::RegWord(rd_u16(rec, i - len), rd_u64(rec, i - len + 2)),
            TAG_REG_STR if len >= 2 => Pv::RegStr(rd_u16(rec, i - len), s + 2, l - 2),
            TAG_REG_STR16 if len >= 2 => Pv::RegStr16(rd_u16(rec, i - len), s + 2, l - 2),
            TAG_REG_F64 if len == 10 => {
                Pv::RegF64(rd_u16(rec, i - len), f64::from_bits(rd_u64(rec, i - len + 2)))
            }
            TAG_REG_SMI if len == 6 => Pv::RegSmi(rd_u16(rec, i - len), rd_i32(rec, i - len + 2)),
            TAG_OPERAND if len == 9 => Pv::Operand(rec[i - len], rd_u64(rec, i - len + 1) as i64),
            TAG_VCLOCK if len == 8 => Pv::Vclock(rd_u64(rec, i - len)),
            _ => continue,
        };
        out.push(pv);
    }
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
// head (32 bytes): [u32 bc_len][u32 script_name_len][u32 fn_name_len]
//   [u32 cp_bytes][i32 frame_size][u32 param_count][i32 script_id]
//   [u32 _reserved] | bc | script_name | fn_name | cp blocks
fn parse_func_def_blob(func_id: u32, line: u32, blob: &[u8]) -> Option<FuncDef> {
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
    let script_name = String::from_utf8_lossy(&blob[i..i + script_name_len]).into_owned();
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

fn acc_of(pvs: &[Pv], flags: u8) -> Option<AccRef> {
    if flags & FLAG_ACC_PAYLOAD == 0 {
        return None;
    }
    pvs.iter().find_map(|pv| match pv {
        Pv::Str(s, l) => Some(AccRef::Str(*s, *l)),
        Pv::Str16(s, l) => Some(AccRef::Str16(*s, *l)),
        Pv::F64(f) => Some(AccRef::F64(*f)),
        Pv::Smi(i) => Some(AccRef::Smi(*i)),
        _ => None,
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
        let (rop, scale_i, base) = if m.name == "Wide" || m.name == "DebugBreakWide" {
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

// CFG block starts, v8 jump semantics from meta flags:
//   bit0 jump / bit1 returns -> the next instruction starts a new block
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

// operand value cp-resolution class (LdaContextSlot/StaContextSlot are
// NOT here: their operand 0 is a context slot, not a cp index)
fn cp_resolve_op(name: &str) -> bool {
    matches!(
        name,
        "LdaConstant"
            | "LdaGlobal"
            | "LdaGlobalInsideTypeof"
            | "StaGlobal"
            | "GetNamedProperty"
            | "SetNamedProperty"
            | "DefineNamedOwnProperty"
            | "AddNamedProperty"
            | "CallProperty"
            | "CallProperty0"
            | "CallProperty1"
            | "CallProperty2"
            | "CallUndefinedReceiver0"
            | "CallUndefinedReceiver1"
            | "CallUndefinedReceiver2"
            | "CallWithSpread"
            | "Construct"
            | "ConstructWithSpread"
            | "TestReferenceEqual"
            | "JumpIfTrueConstant"
            | "JumpIfFalseConstant"
            | "LdaLookupGlobalSlot"
    )
}

fn rt_resolve_op(name: &str) -> bool {
    matches!(name, "CallRuntime" | "CallRuntimeForPair")
}

// JS-call opcodes: the NEXT same-(pid,iso) record is the callee's first
// instruction, so its acc-in is NOT this call's result. res stays absent.
fn js_call_op(name: &str) -> bool {
    matches!(
        name,
        "CallProperty"
            | "CallProperty0"
            | "CallProperty1"
            | "CallProperty2"
            | "CallUndefinedReceiver0"
            | "CallUndefinedReceiver1"
            | "CallUndefinedReceiver2"
            | "CallWithSpread"
            | "Construct"
            | "ConstructWithSpread"
    )
}

fn api_category(name: &str) -> Option<(u8, &'static str)> {
    match name {
        "LdaGlobal" | "LdaGlobalInsideTypeof" | "LdaLookupGlobalSlot" | "StaGlobal" => {
            Some((0, "global"))
        }
        "GetNamedProperty"
        | "GetNamedPropertyFromSuper"
        | "SetNamedProperty"
        | "DefineNamedOwnProperty"
        | "AddNamedProperty" => Some((1, "prop")),
        "CallProperty"
        | "CallProperty0"
        | "CallProperty1"
        | "CallProperty2"
        | "CallUndefinedReceiver0"
        | "CallUndefinedReceiver1"
        | "CallUndefinedReceiver2"
        | "CallWithSpread" => Some((2, "call")),
        "CallRuntime" | "CallRuntimeForPair" => Some((3, "runtime")),
        _ => None,
    }
}

fn put_str_bytes(j: &mut J, b: &[u8]) {
    match std::str::from_utf8(b) {
        Ok(s) => esc(&mut j.b, s),
        Err(_) => {
            let s = String::from_utf8_lossy(b);
            esc(&mut j.b, &s);
        }
    }
}

fn put_accref(j: &mut J, rec: &[u8], v: AccRef) {
    match v {
        AccRef::Str(s, l) => put_str_bytes(j, &rec[s as usize..(s + l) as usize]),
        AccRef::Str16(s, l) => {
            let st = utf16le_to_string(&rec[s as usize..(s + l) as usize]);
            esc(&mut j.b, &st);
        }
        AccRef::F64(f) => j.f64v(f),
        AccRef::Smi(i) => j.i64v(i as i64),
    }
}

fn put_resval(j: &mut J, v: &ResVal<'_>) {
    match v {
        ResVal::Str(b) => put_str_bytes(j, b),
        ResVal::Str16(b) => {
            let st = utf16le_to_string(b);
            esc(&mut j.b, &st);
        }
        ResVal::F64(f) => j.f64v(*f),
        ResVal::Smi(i) => j.i64v(*i as i64),
    }
}

fn owned_of_res(v: &ResVal<'_>) -> OwnedVal {
    match v {
        ResVal::Str(b) => OwnedVal::Str(String::from_utf8_lossy(b).into_owned()),
        ResVal::Str16(b) => OwnedVal::Str(utf16le_to_string(b)),
        ResVal::F64(f) => OwnedVal::F64(*f),
        ResVal::Smi(i) => OwnedVal::Smi(*i),
    }
}

fn put_cp(j: &mut J, e: &CpEntry) {
    match e {
        CpEntry::Str(b) => put_str_bytes(j, b),
        CpEntry::Str16(b) => {
            let s = utf16le_to_string(b);
            esc(&mut j.b, &s);
        }
        CpEntry::F64(f) => j.f64v(*f),
        CpEntry::Raw(w) => j.u64v(*w),
    }
}

fn hex_name<'a>(buf: &'a mut [u8; 24], fid: u32, ext: &[u8]) -> &'a str {
    static H: &[u8; 16] = b"0123456789abcdef";
    let mut n = 0usize;
    for k in (0..8).rev() {
        buf[n] = H[((fid >> (k * 4)) & 15) as usize];
        n += 1;
    }
    buf[n..n + ext.len()].copy_from_slice(ext);
    n += ext.len();
    std::str::from_utf8(&buf[..n]).unwrap_or("x")
}

// ---- PASS2 semantic emitter ----

struct Sem<'m> {
    meta: &'m [OpMeta],
    rt_names: &'m [String],
    funcs: &'m HashMap<u32, FuncDef>,
    files: HashMap<u32, BufWriter<File>>,
    sem_dir: PathBuf,
    j: J,
    // cat -> name -> (count, up to 8 distinct result samples)
    api: BTreeMap<u8, BTreeMap<Vec<u8>, (u64, Vec<OwnedVal>)>>,
}

impl<'m> Sem<'m> {
    fn new(
        meta: &'m [OpMeta],
        rt_names: &'m [String],
        funcs: &'m HashMap<u32, FuncDef>,
        sem_dir: PathBuf,
    ) -> Sem<'m> {
        Sem {
            meta,
            rt_names,
            funcs,
            files: HashMap::new(),
            sem_dir,
            j: J::new(512),
            api: BTreeMap::new(),
        }
    }

    /// Flush and release every per-function writer. Must run before the
    /// summary reads the sem files back, otherwise the tail of each 1MiB
    /// BufWriter is still in memory and the files look truncated.
    fn flush_writers(&mut self) {
        for w in self.files.values_mut() {
            let _ = w.flush();
        }
    }

    fn close(&mut self) {
        self.flush_writers();
        self.files.clear();
    }

    // JS-call opcodes (their successor is the callee, not the result).
    fn emit(&mut self, rec: &[u8], ts: u64, pvs: &[Pv], res: Option<&ResVal<'_>>) {
        let meta: &'m [OpMeta] = self.meta;
        let opcode = rec[0];
        let m = match meta.get(opcode as usize) {
            Some(m) => m,
            None => return,
        };
        let wants_res = m.acc_use & 2 != 0 && !js_call_op(&m.name);
        self.build(rec, ts, pvs, res, m, wants_res);
        let func_id = rd_u32(rec, 8);
        if !self.files.contains_key(&func_id) {
            let mut nb = [0u8; 24];
            let name = hex_name(&mut nb, func_id, b".jsonl");
            if let Ok(f) = File::create(self.sem_dir.join(name)) {
                self.files
                    .insert(func_id, BufWriter::with_capacity(1 << 20, f));
            }
        }
        if let Some(w) = self.files.get_mut(&func_id) {
            let _ = w.write_all(&self.j.b);
        }
    }

    // build one sem json line into self.j and account api_calls/api_values
    fn build(
        &mut self,
        rec: &[u8],
        ts: u64,
        pvs: &[Pv],
        res: Option<&ResVal<'_>>,
        m: &'m OpMeta,
        wants_res: bool,
    ) {
        let funcs: &'m HashMap<u32, FuncDef> = self.funcs;
        let rt_names: &'m [String] = self.rt_names;
        let func_id = rd_u32(rec, 8);
        let offset = rd_u32(rec, 4);
        let flags = rec[3];
        let def = funcs.get(&func_id);
        let mut vclock = 0u64;
        for pv in pvs {
            if let Pv::Vclock(v) = pv {
                vclock = *v;
            }
        }

        let j = &mut self.j;
        j.b.clear();
        j.open();
        j.fkey("ts");
        j.u64v(ts);
        j.key("off");
        j.u64v(offset as u64);
        j.key("op");
        j.s(&m.name);
        if vclock != 0 {
            // timestamp_virtual: instruction-count-driven clock from 0034.
            // Physical ts stays for wall correlation; vts is deterministic
            // regardless of host speed.
            j.key("vts");
            j.u64v(vclock);
        }

        // args: engine-decoded operand values; cp-index operand 0 resolves
        // through the function constant pool, CallRuntime through the name
        // table; anything else stays raw. LdaContextSlot/StaContextSlot
        // operand 0 is a context slot, NOT a cp index - it stays raw.
        let mut n_args = 0usize;
        for pv in pvs {
            if let Pv::Operand(idx, v) = pv {
                if n_args == 0 {
                    j.key("args");
                    j.b.put_u8(b'[');
                } else {
                    j.b.put_u8(b',');
                }
                n_args += 1;
                if *idx == 0 && cp_resolve_op(&m.name) {
                    match def.and_then(|d| d.cp.get(*v as usize)) {
                        Some(e) => put_cp(j, e),
                        None => j.i64v(*v),
                    }
                } else if *idx == 0 && rt_resolve_op(&m.name) {
                    match rt_names.get(*v as usize) {
                        Some(n) => j.s(n),
                        None => j.i64v(*v),
                    }
                } else {
                    j.i64v(*v);
                }
            }
        }
        if n_args > 0 {
            j.b.put_u8(b']');
        }

        if let Some(a) = acc_of(pvs, flags) {
            j.key("acc");
            put_accref(j, rec, a);
        }
        if wants_res {
            if let Some(r) = res {
                j.key("res");
                put_resval(j, r);
            }
        }

        // register values that rode along
        let mut n_regs = 0usize;
        for pv in pvs {
            match pv {
                Pv::RegWord(i, w) => {
                    if n_regs == 0 {
                        j.key("regs");
                        j.b.put_u8(b'[');
                    } else {
                        j.b.put_u8(b',');
                    }
                    n_regs += 1;
                    j.b.put_slice(b"{\"reg\":");
                    j.u64v(*i as u64);
                    j.b.put_slice(b",\"word\":");
                    j.u64v(*w);
                    j.b.put_u8(b'}');
                }
                Pv::RegStr(i, s, l) | Pv::RegStr16(i, s, l) => {
                    if n_regs == 0 {
                        j.key("regs");
                        j.b.put_u8(b'[');
                    } else {
                        j.b.put_u8(b',');
                    }
                    n_regs += 1;
                    j.b.put_slice(b"{\"reg\":");
                    j.u64v(*i as u64);
                    j.b.put_slice(b",\"v\":");
                    let b = &rec[*s as usize..(*s + *l) as usize];
                    if matches!(pv, Pv::RegStr16(..)) {
                        let st = utf16le_to_string(b);
                        esc(&mut j.b, &st);
                    } else {
                        put_str_bytes(j, b);
                    }
                    j.b.put_u8(b'}');
                }
                Pv::RegF64(i, f2) => {
                    if n_regs == 0 {
                        j.key("regs");
                        j.b.put_u8(b'[');
                    } else {
                        j.b.put_u8(b',');
                    }
                    n_regs += 1;
                    j.b.put_slice(b"{\"reg\":");
                    j.u64v(*i as u64);
                    j.b.put_slice(b",\"v\":");
                    j.f64v(*f2);
                    j.b.put_u8(b'}');
                }
                Pv::RegSmi(i, v) => {
                    if n_regs == 0 {
                        j.key("regs");
                        j.b.put_u8(b'[');
                    } else {
                        j.b.put_u8(b',');
                    }
                    n_regs += 1;
                    j.b.put_slice(b"{\"reg\":");
                    j.u64v(*i as u64);
                    j.b.put_slice(b",\"v\":");
                    j.i64v(*v as i64);
                    j.b.put_u8(b'}');
                }
                _ => {}
            }
        }
        if n_regs > 0 {
            j.b.put_u8(b']');
        }
        j.b.put_u8(b'}');
        j.b.put_u8(b'\n');

        // api_calls / api_values: name = resolved operand-0 string, borrowed
        // from the constant pool / runtime-name table (no per-call alloc).
        if let Some((cat, _)) = api_category(&m.name) {
            let mut name_ref: Option<&'m [u8]> = None;
            let mut owned16: Option<String> = None;
            for pv in pvs {
                if let Pv::Operand(0, v) = pv {
                    if cp_resolve_op(&m.name) {
                        if let Some(e) = def.and_then(|d| d.cp.get(*v as usize)) {
                            match e {
                                CpEntry::Str(b) => name_ref = Some(b),
                                CpEntry::Str16(b) => {
                                    owned16 = Some(utf16le_to_string(b));
                                }
                                _ => {}
                            }
                        }
                    } else if rt_resolve_op(&m.name) {
                        name_ref =
                            rt_names.get(*v as usize).map(|n| n.as_bytes());
                    }
                    break;
                }
            }
            let key: Option<Vec<u8>> = match (&name_ref, &owned16) {
                (Some(b), _) => Some(b.to_vec()),
                (None, Some(s)) => Some(s.as_bytes().to_vec()),
                _ => None,
            };
            if let Some(key) = key {
                let by_cat = self.api.entry(cat).or_default();
                let e = by_cat.entry(key).or_insert((0, Vec::new()));
                e.0 += 1;
                if wants_res {
                    if let Some(r) = res {
                        let ov = owned_of_res(r);
                        if e.1.len() < 8 && !e.1.contains(&ov) {
                            e.1.push(ov);
                        }
                    }
                }
            }
        }
    }
}

struct Rec {
    ts: u64,
    pid: u64,
    off: u64,
    len: u64,
}

struct Deferred {
    buf: Vec<u8>, // full record bytes (header + payload), reused
    ts: u64,
}

pub fn run(collect_dir: &Path) -> Result<Stats, String> {
    let mut stats = Stats::default();
    let index_p = collect_dir.join("index.jsonl");
    let index = match fs::read_to_string(&index_p) {
        Ok(s) => s,
        Err(_) => return Ok(stats),
    };

    // group index entries by part file; within a group keep index order
    // (= emission order for that file)
    let mut order: Vec<PathBuf> = Vec::new();
    let mut ids: HashMap<PathBuf, u32> = HashMap::new();
    let mut groups: Vec<Vec<Rec>> = Vec::new();
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
        let pb = collect_dir.join(path);
        let id = match ids.get(&pb) {
            Some(&i) => i,
            None => {
                let i = order.len() as u32;
                ids.insert(pb.clone(), i);
                order.push(pb.clone());
                groups.push(Vec::new());
                i
            }
        };
        groups[id as usize].push(Rec {
            ts: v.get("ts").and_then(|x| x.as_u64()).unwrap_or(0),
            pid: v.get("pid").and_then(|x| x.as_u64()).unwrap_or(0),
            off: v.get("o").and_then(|x| x.as_u64()).unwrap_or(0),
            len: v.get("len").and_then(|x| x.as_u64()).unwrap_or(0),
        });
        stats.records += 1;
    }
    if stats.records == 0 {
        return Ok(stats);
    }

    let filt = collect_dir.join("filtered");
    let _ = fs::create_dir_all(&filt);
    let out_dir = filt.join("bctrace");
    let _ = fs::create_dir_all(&out_dir);
    let sem_dir = out_dir.join("sem");
    let _ = fs::create_dir_all(&sem_dir);

    let mut meta: Vec<OpMeta> = Vec::new();
    let mut rt_names: Vec<String> = Vec::new();
    let mut funcs: HashMap<u32, FuncDef> = HashMap::new();
    // func_id -> executed (offset, record opcode), sorted by offset
    let mut executed: HashMap<u32, Vec<(u32, u8)>> = HashMap::new();
    let mut exec_count: HashMap<u32, u64> = HashMap::new();
    let mut first_ts: HashMap<u32, u64> = HashMap::new();
    let mut mismatch_witness: Option<serde_json::Value> = None;

    let mut vb = ValueBook::create(&filt.join("valuebook.bin"))
        .map_err(|e| format!("bctrace: valuebook.bin: {e}"))?;

    // cont-part assembly: (opcode, func_id) -> offset-ordered payload parts
    let mut parts: BTreeMap<(u8, u32), BTreeMap<u32, Vec<u8>>> = BTreeMap::new();
    let mut glue: Vec<u8> = Vec::new();
    let mut pv: Vec<Pv> = Vec::new();

    // ---- PASS1: metadata + valuebook stream ----
    for gi in 0..order.len() {
        let buf = match FileBuf::open(&order[gi]) {
            Some(b) => b,
            None => continue,
        };
        let data = buf.bytes();
        for r in &groups[gi] {
            let start = r.off as usize;
            let end = start + r.len as usize;
            if end > data.len() {
                continue;
            }
            let rec = &data[start..end];
            if rec.len() < HDR_LEN {
                continue;
            }
            let opcode = rec[0];
            let flags = rec[3];
            let func_id = rd_u32(rec, 8);

            if opcode == OP_META || opcode == OP_FUNC_DEF {
                let payload = &rec[HDR_LEN..];
                let m = parts.entry((opcode, func_id)).or_default();
                m.entry(rd_u32(rec, 4))
                    .or_default()
                    .extend_from_slice(payload);
                if flags & FLAG_CONT == 0 {
                    if let Some(map) = parts.remove(&(opcode, func_id)) {
                        let mut full: Vec<u8> = Vec::new();
                        for (_pos, b) in map {
                            full.extend_from_slice(&b);
                        }
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
                        }
                    }
                }
                continue;
            }

            // instruction record (cont parts glue into one stream entry)
            let full_rec: &[u8];
            if flags & FLAG_CONT != 0 {
                let m = parts.entry((opcode, func_id)).or_default();
                let e = m.entry(rd_u32(rec, 4)).or_default();
                if e.is_empty() {
                    e.extend_from_slice(&rec[0..HDR_LEN]);
                }
                e.extend_from_slice(&rec[HDR_LEN..]);
                continue;
            } else if let Some(map) = parts.remove(&(opcode, func_id)) {
                glue.clear();
                for (_pos, b) in map {
                    glue.extend_from_slice(&b);
                }
                full_rec = &glue;
            } else {
                full_rec = rec;
            };

            stats.instructions += 1;
            let offset = rd_u32(full_rec, 4);
            *exec_count.entry(func_id).or_insert(0) += 1;
            first_ts.entry(func_id).or_insert(r.ts);
            let ex = executed.entry(func_id).or_default();
            let pos = ex.partition_point(|x| x.0 < offset);
            if pos == ex.len() || ex[pos].0 != offset {
                ex.insert(pos, (offset, opcode));
            }

            // valuebook: every string value this executed instruction
            // really carried (accumulator + registers), streamed to disk.
            parse_blocks(full_rec, &mut pv);
            let fl = full_rec[3];
            let op_id = if (opcode as usize) < meta.len() {
                opcode as u16
            } else {
                OP_ID_NONE
            };
            for p in &pv {
                match p {
                    Pv::Str(_, _) if fl & FLAG_ACC_PAYLOAD != 0 => {
                        vb.put(p.bytes(full_rec), func_id, offset, op_id, SRC_ACC)
                    }
                    Pv::Str16(_, _) if fl & FLAG_ACC_PAYLOAD != 0 => {
                        vb.put(p.bytes(full_rec), func_id, offset, op_id, SRC_ACC)
                    }
                    Pv::RegStr(..) => {
                        vb.put(p.bytes(full_rec), func_id, offset, op_id, SRC_REG)
                    }
                    Pv::RegStr16(..) => {
                        vb.put(p.bytes(full_rec), func_id, offset, op_id, SRC_REG)
                    }
                    _ => {}
                }
            }
            pv.clear();
        }
    }
    if meta.is_empty() {
        return Err("bctrace: no meta record (0033 patch not active?)".into());
    }
    stats.funcs = funcs.len() as u64;
    stats.func_scripts = funcs
        .iter()
        .map(|(fid, def)| (*fid, def.script_name.clone()))
        .collect();
    for def in funcs.values() {
        stats
            .script_ids
            .entry(def.script_id as u32)
            .or_insert_with(|| def.script_name.clone());
    }

    // ops.txt: line n = opcode n's name (op_id = meta index)
    {
        let mut ops = String::new();
        for m in &meta {
            ops.push_str(&m.name);
            ops.push('\n');
        }
        let _ = fs::write(filt.join("ops.txt"), ops.as_bytes());
    }

    // cp literals of EVERY function (executed or not): the fact is
    // "literal exists". src=2 + exec_funcs.bin separates existence from
    // execution - sinkfilter only counts a cp value as proven when its
    // func_id is in exec_funcs.bin.
    {
        let mut fids: Vec<u32> = funcs.keys().copied().collect();
        fids.sort_unstable();
        for fid in fids {
            let def = &funcs[&fid];
            for entry in &def.cp {
                let bytes = match entry {
                    CpEntry::Str(b) => b.as_slice(),
                    CpEntry::Str16(b) => b.as_slice(),
                    _ => continue,
                };
                vb.put(bytes, fid, 0, OP_ID_NONE, SRC_CP);
            }
        }
    }
    stats.valuebook_entries = vb.entries;
    stats.valuebook_bytes = vb.bytes;
    vb.finish()
        .map_err(|e| format!("bctrace: valuebook.bin flush: {e}"))?;

    // exec_funcs.bin: sorted func_ids with exec_count > 0
    {
        let mut ef: Vec<u32> = exec_count
            .iter()
            .filter(|(_, &c)| c > 0)
            .map(|(&f, _)| f)
            .collect();
        ef.sort_unstable();
        let mut buf = Vec::with_capacity(ef.len() * 4);
        for f in ef {
            buf.extend_from_slice(&f.to_le_bytes());
        }
        let _ = fs::write(filt.join("exec_funcs.bin"), buf);
    }

    // ---- per-function reports: static walk, dead/live by executed
    // offsets (binary search), honest offset-mismatch check ----
    let mut func_reports = Vec::new();
    let mut fids: Vec<u32> = funcs.keys().copied().collect();
    fids.sort_unstable();
    for fid in fids {
        let def = &funcs[&fid];
        let instrs = match decode_func(&def.bytecode, &meta) {
            Some(v) => v,
            None => continue,
        };
        let ex = executed.get(&fid);

        // wide-offset resync check: executed record offset/opcode vs the
        // static walk. Mismatches are counted and witnessed, never fixed
        // silently.
        if let Some(ex) = ex {
            for &(off, rec_op) in ex {
                let pos = instrs.partition_point(|d| (d.offset as u32) < off);
                match instrs.get(pos).filter(|d| d.offset as u32 == off) {
                    Some(d) if rec_op == d.opcode => {}
                    Some(d) => {
                        stats.offset_mismatch += 1;
                        if mismatch_witness.is_none() {
                            mismatch_witness = Some(serde_json::json!({
                                "func_id": fid,
                                "off": off,
                                "record_opcode": rec_op,
                                "static_opcode": d.opcode,
                                "kind": "record-vs-static",
                            }));
                        }
                    }
                    None => {
                        stats.offset_mismatch += 1;
                        if mismatch_witness.is_none() {
                            mismatch_witness = Some(serde_json::json!({
                                "func_id": fid,
                                "off": off,
                                "record_opcode": rec_op,
                                "static_opcode": null,
                                "kind": "offset-unknown",
                            }));
                        }
                    }
                }
            }
        }

        let block_starts = block_starts_of(&instrs, &meta);
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
                Some(ex) => {
                    let from = instrs.partition_point(|d| d.offset < bs);
                    instrs[from..]
                        .iter()
                        .take_while(|d| d.offset < be)
                        .any(|d| {
                            ex.binary_search_by_key(&(d.offset as u32), |x| x.0)
                                .is_ok()
                        })
                }
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

        let report = serde_json::json!({
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
            "executions": exec_count.get(&fid).copied().unwrap_or(0),
            "live_blocks": live_blocks,
            "dead_blocks": dead_blocks,
            "dead_ranges": dead_ranges,
            "first_ts": first_ts.get(&fid).copied().unwrap_or(0),
        });
        let mut nb = [0u8; 24];
        let name = hex_name(&mut nb, fid, b".json");
        let fp = out_dir.join(name);
        if let Ok(mut f) = File::create(&fp) {
            let bytes = serde_json::to_vec_pretty(&report).unwrap_or_default();
            let _ = f.write_all(&bytes);
        }
        func_reports.push(report);
    }

    // ---- PASS2: semantic stream, one deferred record per (pid,iso).
    // res of the deferred record = acc of the current one; file order =
    // emission order, no global sort. ----
    let mut sem = Sem::new(&meta, &rt_names, &funcs, sem_dir);
    let mut defer: HashMap<(u64, u32), Deferred> = HashMap::new();
    let mut pv_cur: Vec<Pv> = Vec::new();
    let mut pv_def: Vec<Pv> = Vec::new();
    parts.clear();
    for gi in 0..order.len() {
        let buf = match FileBuf::open(&order[gi]) {
            Some(b) => b,
            None => continue,
        };
        let data = buf.bytes();
        for r in &groups[gi] {
            let start = r.off as usize;
            let end = start + r.len as usize;
            if end > data.len() {
                continue;
            }
            let rec = &data[start..end];
            if rec.len() < HDR_LEN {
                continue;
            }
            let opcode = rec[0];
            if opcode == OP_META || opcode == OP_FUNC_DEF {
                continue;
            }
            let flags = rec[3];
            let func_id = rd_u32(rec, 8);

            let full_rec: &[u8];
            if flags & FLAG_CONT != 0 {
                let m = parts.entry((opcode, func_id)).or_default();
                let e = m.entry(rd_u32(rec, 4)).or_default();
                if e.is_empty() {
                    e.extend_from_slice(&rec[0..HDR_LEN]);
                }
                e.extend_from_slice(&rec[HDR_LEN..]);
                continue;
            } else if let Some(map) = parts.remove(&(opcode, func_id)) {
                glue.clear();
                for (_pos, b) in map {
                    glue.extend_from_slice(&b);
                }
                full_rec = &glue;
            } else {
                full_rec = rec;
            };

            let iso = rd_u32(full_rec, 12);
            parse_blocks(full_rec, &mut pv_cur);
            let key = (r.pid, iso);
            match defer.get_mut(&key) {
                Some(d) => {
                    // flush the deferred record; its result = THIS record's
                    // acc-in. full_rec lives through emit, so res borrows it
                    // directly - no copy.
                    let dts = d.ts;
                    let d_op = d.buf[0];
                    let wants_res = match meta.get(d_op as usize) {
                        Some(m) => m.acc_use & 2 != 0 && !js_call_op(&m.name),
                        None => false,
                    };
                    let res: Option<ResVal<'_>> = if wants_res {
                        acc_of(&pv_cur, full_rec[3]).map(|a| match a {
                            AccRef::Str(s, l) => {
                                ResVal::Str(&full_rec[s as usize..(s + l) as usize])
                            }
                            AccRef::Str16(s, l) => {
                                ResVal::Str16(&full_rec[s as usize..(s + l) as usize])
                            }
                            AccRef::F64(f) => ResVal::F64(f),
                            AccRef::Smi(i) => ResVal::Smi(i),
                        })
                    } else {
                        None
                    };
                    parse_blocks(&d.buf, &mut pv_def);
                    sem.emit(&d.buf, dts, &pv_def, res.as_ref());
                    d.buf.clear();
                    d.buf.extend_from_slice(full_rec);
                    d.ts = r.ts;
                }
                None => {
                    defer.insert(
                        key,
                        Deferred {
                            buf: full_rec.to_vec(),
                            ts: r.ts,
                        },
                    );
                }
            }
            pv_cur.clear();
        }
        sem.flush_writers();
    }
    // tail: flush every deferred record (no successor -> no res)
    let keys: Vec<(u64, u32)> = defer.keys().copied().collect();
    for k in keys {
        if let Some(d) = defer.remove(&k) {
            parse_blocks(&d.buf, &mut pv_def);
            sem.emit(&d.buf, d.ts, &pv_def, None);
        }
    }
    sem.close();

    // ---- summary ----
    let cat_names = ["global", "prop", "call", "runtime"];
    let mut api_list: Vec<serde_json::Value> = Vec::new();
    for (cat, by_name) in &sem.api {
        let cn = cat_names.get(*cat as usize).copied().unwrap_or("?");
        for (name, (n, vals)) in by_name {
            let mut prefix = cn.to_string();
            prefix.push(' ');
            let what = format!("{}{}", prefix, String::from_utf8_lossy(name));
            let mut e = serde_json::json!({ "what": what, "times": n });
            if !vals.is_empty() {
                let vs: Vec<serde_json::Value> = vals
                    .iter()
                    .map(|v| match v {
                        OwnedVal::Str(s) => serde_json::json!(s),
                        OwnedVal::F64(f) => serde_json::json!(f),
                        OwnedVal::Smi(i) => serde_json::json!(i),
                    })
                    .collect();
                e["values"] = serde_json::json!(vs);
            }
            api_list.push(e);
        }
    }
    api_list.sort_by(|a, b| {
        b["times"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["times"].as_u64().unwrap_or(0))
    });

    let mut summary = serde_json::json!({
        "records": stats.records,
        "instructions": stats.instructions,
        "funcs": stats.funcs,
        "dead_blocks": stats.dead_blocks,
        "live_blocks": stats.live_blocks,
        "dead_bytes": stats.dead_bytes,
        "live_bytes": stats.live_bytes,
        "funcs_reported": func_reports.len(),
        "valuebook_entries": stats.valuebook_entries,
        "valuebook_bytes": stats.valuebook_bytes,
        "offset_mismatch": stats.offset_mismatch,
        "api_calls": api_list,
        "rule": "dead = basic block whose offsets NEVER appear in the executed stream. Operand values engine-decoded at emit time. Result of a write-acc instruction = acc of the next same-(pid,iso) record in emission order; JS-call opcodes carry no res because their successor is the callee's first instruction, not the result. Facts only.",
        "functions": func_reports,
    });
    if let Some(w) = mismatch_witness {
        summary["offset_mismatch_witness"] = w;
    }
    let _ = fs::write(
        filt.join("bctrace.json"),
        serde_json::to_vec_pretty(&summary).unwrap_or_default(),
    );
    Ok(stats)
}
