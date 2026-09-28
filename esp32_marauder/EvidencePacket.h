#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>
namespace passive_evidence {
inline const char* frameType(const uint8_t* frame) {
  switch (frame[0]) {
    case 0x40: return "probe_request";
    case 0x50: return "probe_response";
    case 0x80: return "beacon";
    default: return nullptr;
  }
}
// Promiscuous sig_len includes four FCS bytes on the pinned IDF. Only ordinary,
// unprotected, unfragmented management headers are supported (no +HTC).
inline size_t managementLength(const uint8_t* frame, size_t size) {
  if (!frame || size < 30 || !frameType(frame) || (frame[1] & 0xc7) || (frame[22] & 15)) return 0;
  size_t minimum = frame[0] == 0x40 ? 30 : 42;  // header, fixed AP fields, SSID IE, FCS
  return size >= minimum ? size - 4 : 0;
}
// Exclude TSF, sequence/retry bits, and the volatile TIM IE when comparing
// beacon content. Full bytes, including these fields, still reach the host.
inline uint32_t beaconFingerprint(const uint8_t* frame, size_t size) {
  uint32_t hash = 2166136261u;
  auto add = [&hash](uint8_t b) { hash = (hash ^ b) * 16777619u; };
  for (size_t i=16; i<22; ++i) add(frame[i]);  // BSSID
  for (size_t i=32; i<36; ++i) add(frame[i]);  // interval and capabilities
  for (size_t i=36; i<size;) {
    size_t end = i+2 <= size ? i+2+frame[i+1] : size;
    if (end > size) end=size;
    if (frame[i] != 5) for (size_t j=i; j<end; ++j) add(frame[j]);
    i=end;
  }
  return hash;
}
class BeaconSampler {
  struct Entry { bool used; uint8_t mac[6], channel; uint32_t hash; uint64_t time; };
  Entry entries[128]{};
  size_t next=0;
  Entry* find(const uint8_t* mac, uint8_t channel, uint32_t hash) {
    for (auto& e : entries) if (e.used && e.channel==channel && e.hash==hash && !memcmp(e.mac,mac,6)) return &e;
    return nullptr;
  }
public:
  static constexpr uint64_t INTERVAL_US=5000000;
  void reset() { memset(entries,0,sizeof(entries)); next=0; }
  bool suppress(const uint8_t* mac, uint8_t channel, uint32_t hash, uint64_t time) {
    auto e=find(mac,channel,hash);
    return e && time>=e->time && time-e->time<INTERVAL_US;
  }
  // Call only after successful queue admission: a dropped sample must be retried.
  void remember(const uint8_t* mac, uint8_t channel, uint32_t hash, uint64_t time) {
    auto e=find(mac,channel,hash);
    if (!e) { e=&entries[next]; next=(next+1)%128; }
    e->used=true; memcpy(e->mac,mac,6); e->channel=channel; e->hash=hash; e->time=time;
  }
};
}
