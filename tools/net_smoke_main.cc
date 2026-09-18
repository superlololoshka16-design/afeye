// afeye net-layer sink smoke - compiled from 0011-network-wire.patch bytes.
#include <cstdio>

#include "services/network/afeye_sink.h"

int main() {
  if (!network::afeye::Enabled()) {
    std::fprintf(stderr, "sink not enabled (set AFEYE_SINK=1)\n");
    return 2;
  }
  static const char kBody[] = "device_id=abc&signals=%7Bx%7D";
  network::afeye::EmitTwoStr(network::afeye::kNetReq,
                             network::afeye::NowNs(), "POST",
                             "https://tlx.antifraud.example/collect");
  network::afeye::EmitSpan(network::afeye::kNetReq,
                           network::afeye::NowNs(), "req-body",
                           reinterpret_cast<const uint8_t*>(kBody),
                           sizeof(kBody) - 1);
  std::printf("net done dropped=%llu\n",
              static_cast<unsigned long long>(network::afeye::SinkDropped()));
  return 0;
}
