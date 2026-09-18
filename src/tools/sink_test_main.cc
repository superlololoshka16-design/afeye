// afeye sink battery - compiled against the sink extracted FROM the patch
// file itself, so what is tested is exactly what ships in 0001-v8-sink.patch.
#include "src/afeye/sink.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace v8::afeye;

static void storm(int tid) {
  for (int i = 0; i < 500; i++) {
    uint32_t tuple[3] = {static_cast<uint32_t>(tid),
                         static_cast<uint32_t>(i), 2u};
    Emit(kBytecodeEntry, NowNs(), tuple, sizeof(tuple));
  }
}

int main(int argc, char** argv) {
  if (argc > 1 && std::strcmp(argv[1], "off") == 0) {
    bool on = Enabled();
    std::printf("enabled=%d\n", on ? 1 : 0);
    return on ? 1 : 0;
  }
  if (!Enabled()) {
    std::fprintf(stderr, "sink not enabled (set AFEYE_SINK=1)\n");
    return 2;
  }
  EmitStr(kScriptSource, NowNs(), "console.log(1);");
  EmitTwoStr(kScriptSource, NowNs(), "http://x/dd.js", "var a=1;");
  static uint8_t wasm[4096];
  for (size_t i = 0; i < sizeof(wasm); i++) wasm[i] = static_cast<uint8_t>(i * 7 + 3);
  Emit(kWasmModule, NowNs(), wasm, sizeof(wasm));
  uint64_t mt[2] = {5, 42};
  Emit(kMicrotaskEnqueue, NowNs(), mt, sizeof(mt));
  EmitStr(kAtomics, NowNs(), "atomics.wait probe");
  EmitSpan(kSabBacking, NowNs(), "span-tag", wasm, 100);
  Emit(kAtomics, NowNs(), "x", 0);
  std::string big(2 * 1024 * 1024, 'B');
  EmitStr(kScriptSource, NowNs(), big.c_str());
  std::vector<std::thread> th;
  for (int t = 0; t < 8; t++) th.emplace_back(storm, t);
  for (auto& x : th) x.join();
  EmitStr(kAtomics, NowNs(), "BATTERY-END");
  bool flushed = Flush(5000);
  std::printf("done dropped=%llu flushed=%d\n",
              static_cast<unsigned long long>(SinkDropped()), flushed ? 1 : 0);
  return 0;
}
