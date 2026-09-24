// afeye bcrec battery - compiled against bcrec.h extracted FROM the
// 0033 patch, so the bytes it emits are byte-for-byte what the v8
// runtime-trace hook emits. tests/bcrec_roundtrip.rs scans these records
// through the production collector and decodes them with bctrace::run.
// Green here = wire format proven without building chromium.
//
// Wire semantics the stream demonstrates:
//   hdr.acc / acc payload = accumulator value ENTERING the instruction.
//   result of a write-acc opcode = acc of the NEXT record (same
//   pid+isolate) - engine dataflow, no windowing.
#include "src/afeye/bcrec.h"
#include "src/afeye/sink.h"

#include <cstdio>
#include <cstring>
#include <vector>

using namespace v8::afeye;
using namespace v8::afeye::bcrec;

static void emit(const Hdr& h, const uint8_t* pl, size_t n) {
  static thread_local std::vector<uint8_t> buf;
  buf.resize(sizeof(Hdr) + n);
  memcpy(buf.data(), &h, sizeof(h));
  if (n) memcpy(buf.data() + sizeof(Hdr), pl, n);
  Emit(kKind, NowNs(), buf.data(), static_cast<uint32_t>(buf.size()));
}

int main() {
  if (!Enabled()) {
    std::fprintf(stderr, "sink not enabled (set AFEYE_SINK=1)\n");
    return 2;
  }

  // ---- meta: 3-opcode mini engine + 1 runtime name. Tables mirror the
  // real AfeyeEmitMeta layout byte-for-byte.
  MetaBuilder mb;
  mb.Begin(3, -1);  // reg_file_start_offset: r0 operand = -1
  // opcode 0 "LdaConstant": 1 cp-index operand (type 8), writes acc (2)
  mb.Opcode("LdaConstant", 1, 0, 2);
  mb.Scale(2); mb.Operand(8, 1);
  mb.Scale(3); mb.Operand(8, 1);
  mb.Scale(5); mb.Operand(8, 1);
  // opcode 1 "Star0": 0 operands, reads acc (1)
  mb.Opcode("Star0", 0, 0, 1);
  mb.Scale(1); mb.Scale(1); mb.Scale(1);
  // opcode 2 "Return": terminator (flag bit1), reads acc (1)
  mb.Opcode("Return", 0, 2, 1);
  mb.Scale(1); mb.Scale(1); mb.Scale(1);
  mb.RuntimeNames(1);
  mb.RuntimeName("ArrayConcat");
  {
    Hdr h;
    memset(&h, 0, sizeof(h));
    h.opcode = kOpMeta;
    h.acc = mb.size();
    EmitSplit(h, mb.data(), mb.size(), true, emit);
  }

  // ---- func-def: bytecode with a DEAD tail instruction.
  //   0: LdaConstant cp0   (2 bytes)  executed
  //   2: Star0             (1)        executed
  //   3: Return            (1)        executed
  //   4: LdaConstant cp0   (2)        NEVER executed -> dead block [4,6)
  const uint8_t bc[] = {0x00, 0x00, 0x01, 0x02, 0x00, 0x00};
  FuncDefBuilder fb;
  const char* nm = "translit.js";
  const uint8_t* nameb = reinterpret_cast<const uint8_t*>(nm);
  const char* cpstr = "secret-key";
  CpSpan cp[1];
  cp[0].tag = kCpTagStr;
  cp[0].data = reinterpret_cast<const uint8_t*>(cpstr);
  cp[0].len = static_cast<uint32_t>(strlen(cpstr));
  fb.Build(bc, sizeof(bc), nameb, static_cast<uint32_t>(strlen(nm)), 4, 1,
           cp, 1);
  uint32_t fid = MakeFuncId(7, 0, 0, 0x1234);
  {
    Hdr h;
    memset(&h, 0, sizeof(h));
    h.opcode = kOpFuncDef;
    h.flags = kFlagFuncDef;
    h.func_id = fid;
    h.line = 10;
    h.acc = fb.size();
    EmitSplit(h, fb.data(), fb.size(), true, emit);
  }

  // ---- instruction stream ----
  // rec1: LdaConstant @0, acc-in = Smi 7, engine-decoded operand 0 = cp idx 0
  {
    InstrBuilder ib;
    ib.Begin(0x00, 1, 0, fid, 0x1234, 0x0e);  // 0x0e = tagged Smi 7
    ib.Operand(0, 0);
    ib.AccSmi(7);
    Hdr h = ib.FinishHdr();
    EmitSplit(h, ib.payload(), ib.payload_len(), false, emit);
  }
  // rec2: Star0 @2, acc-in = "Mozilla/5.0" (= RESULT of the LdaConstant),
  // stores it to r0: reg word + full string value.
  {
    InstrBuilder ib;
    ib.Begin(0x01, 1, 2, fid, 0x1234, 0xbeef);
    const char* v = "Mozilla/5.0";
    ib.RegStr(0, reinterpret_cast<const uint8_t*>(v),
              static_cast<uint32_t>(strlen(v)), false);
    ib.Reg(0, 0xbeef);
    ib.AccStr(reinterpret_cast<const uint8_t*>(v),
              static_cast<uint32_t>(strlen(v)), false);
    Hdr h = ib.FinishHdr();
    EmitSplit(h, ib.payload(), ib.payload_len(), false, emit);
  }
  // rec3: Return @3, acc-in = "Mozilla/5.0"
  {
    InstrBuilder ib;
    ib.Begin(0x02, 1, 3, fid, 0x1234, 0xbeef);
    const char* v = "Mozilla/5.0";
    ib.AccStr(reinterpret_cast<const uint8_t*>(v),
              static_cast<uint32_t>(strlen(v)), false);
    Hdr h = ib.FinishHdr();
    EmitSplit(h, ib.payload(), ib.payload_len(), false, emit);
  }

  Flush(1000);
  std::printf("bcrec battery emitted\n");
  return 0;
}
