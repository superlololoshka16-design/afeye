// afeye blink-layer sink smoke - compiled from 0006-blink-sink.patch bytes.
#include <cstdio>

#include "third_party/blink/renderer/platform/afeye/sink.h"

int main() {
  if (!blink::afeye::Enabled()) {
    std::fprintf(stderr, "sink not enabled (set AFEYE_SINK=1)\n");
    return 2;
  }
  static const uint8_t kBytes[6] = {'a', 'b', 'c', 'd', 'e', 'f'};
  blink::afeye::EmitStr(blink::afeye::kTimer, blink::afeye::NowNs(),
                        "blink-smoke");
  blink::afeye::EmitSpan(blink::afeye::kCryptoOp, blink::afeye::NowNs(),
                         "smoke", kBytes, sizeof(kBytes));
  blink::afeye::EmitTwoStr(blink::afeye::kMessage, blink::afeye::NowNs(),
                           "bc-post", "{\"obj\":true}");
  std::printf("blink done dropped=%llu\n",
              static_cast<unsigned long long>(blink::afeye::SinkDropped()));
  return 0;
}
